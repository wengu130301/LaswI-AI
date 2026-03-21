require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const QRCode = require('qrcode');
const axios = require('axios');

// 腾讯混元SDK
const tencentcloud = require('tencentcloud-sdk-nodejs-hunyuan');
const HunyuanClient = tencentcloud.hunyuan.v20230901.Client;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 数据库连接
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ---------- 自动建表 ----------
(async () => {
  try {
    // users 表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ 表 users 已就绪');

    // 添加字段（如果不存在）
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN current_session VARCHAR(255);`);
      console.log('✅ 字段 current_session 已添加到 users');
    } catch (err) { if (!err.message.includes('already exists')) console.error(err); }
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN api_token VARCHAR(64) UNIQUE;`);
      console.log('✅ 字段 api_token 已添加到 users');
    } catch (err) { if (!err.message.includes('already exists')) console.error(err); }

    // conversations
    await pool.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(10) NOT NULL,
        content TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ 表 conversations 已就绪');

    // scan_codes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS scan_codes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code VARCHAR(64) UNIQUE NOT NULL,
        session_id VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE
      );
    `);
    console.log('✅ 表 scan_codes 已就绪');
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scan_codes_code ON scan_codes(code);`);

    // 产品线配置表
    const productTables = ['digital_config', 'silent_config', 'pro_config', 'cyber_config'];
    for (const table of productTables) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ${table} (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          current_version VARCHAR(20) DEFAULT '1.0',
          features JSONB DEFAULT '{}',
          last_check TIMESTAMP DEFAULT NOW(),
          UNIQUE(user_id)
        );
      `);
      console.log(`✅ 表 ${table} 已就绪`);
    }

    // 地图导航历史
    await pool.query(`
      CREATE TABLE IF NOT EXISTS navigation_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        origin TEXT,
        destination TEXT NOT NULL,
        distance_km NUMERIC(10,2),
        duration_min INTEGER,
        route_data JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ 表 navigation_history 已就绪');

    // 浏览器搜索历史
    await pool.query(`
      CREATE TABLE IF NOT EXISTS browser_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        query TEXT NOT NULL,
        results JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ 表 browser_history 已就绪');

  } catch (err) {
    console.error('❌ 自动建表失败:', err);
  }
})();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// 腾讯混元客户端
const clientConfig = {
  credential: {
    secretId: process.env.TENCENT_SECRET_ID,
    secretKey: process.env.TENCENT_SECRET_KEY,
  },
  region: 'ap-guangzhou',
  profile: { httpProfile: { endpoint: 'hunyuan.tencentcloudapi.com' } },
};
const client = new HunyuanClient(clientConfig);

// ---------- 辅助函数 ----------
const getUserFromToken = async (req) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT current_session FROM users WHERE id = $1', [decoded.userId]);
    const currentSession = result.rows[0]?.current_session;
    if (currentSession && currentSession !== decoded.sessionId) return null;
    return decoded;
  } catch (err) { return null; }
};

const requireAuth = async (req, res, next) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: '未授权' });
  req.user = user;
  next();
};

const authenticateWebOrApi = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '缺少认证信息' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT current_session FROM users WHERE id = $1', [decoded.userId]);
    const currentSession = result.rows[0]?.current_session;
    if (currentSession && currentSession !== decoded.sessionId) return res.status(401).json({ error: '会话已过期' });
    req.userId = decoded.userId;
    return next();
  } catch (jwtErr) {
    try {
      const result = await pool.query('SELECT id FROM users WHERE api_token = $1', [token]);
      if (result.rows.length === 0) return res.status(401).json({ error: '认证无效' });
      req.userId = result.rows[0].id;
      return next();
    } catch (apiErr) { return res.status(401).json({ error: '认证失败' }); }
  }
};

// ---------- 用户认证 ----------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    const user = result.rows[0];
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '7d' });
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [sessionId, user.id]);
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: '用户名已存在' });
    console.error(err);
    res.status(500).json({ error: '注册失败' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: '用户名或密码错误' });
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '7d' });
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [sessionId, user.id]);
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '登录失败' });
  }
});

// ---------- 聊天 ----------
app.post('/api/chat', async (req, res) => {
  const { messages } = req.body;
  const user = await getUserFromToken(req);
  if (!messages || !Array.isArray(messages)) return res.status(400).json({ error: '消息格式错误' });
  try {
    const convertedMessages = messages.map(msg => ({ Role: msg.role, Content: msg.content }));
    const response = await client.ChatCompletions({
      Model: process.env.MODEL || 'hunyuan-pro',
      Messages: convertedMessages,
    });
    const reply = response.Choices?.[0]?.Message?.Content;
    if (!reply) throw new Error('API返回内容为空');
    if (user) {
      const userMsg = messages[messages.length - 1];
      await pool.query(
        'INSERT INTO conversations (user_id, role, content) VALUES ($1, $2, $3), ($1, $4, $5)',
        [user.userId, 'user', userMsg.content, 'assistant', reply]
      );
    }
    res.json({ reply });
  } catch (error) {
    console.error('混元API错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

app.get('/api/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT role, content, timestamp FROM conversations WHERE user_id = $1 ORDER BY timestamp ASC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取历史失败' });
  }
});

// ---------- 二维码 ----------
app.get('/api/qr/generate', requireAuth, async (req, res) => {
  try {
    const userId = req.user.userId;
    const sessionId = crypto.randomBytes(16).toString('hex');
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await pool.query(
      'INSERT INTO scan_codes (user_id, code, session_id, expires_at) VALUES ($1, $2, $3, $4)',
      [userId, code, sessionId, expiresAt]
    );
    const scanUrl = `${process.env.BASE_URL}/scan.html?code=${code}`;
    const qrImage = await QRCode.toDataURL(scanUrl);
    res.json({ qrImage, expiresIn: 5 * 60 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '生成二维码失败' });
  }
});

app.post('/api/qr/login', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: '缺少code' });
  try {
    const result = await pool.query(
      'SELECT * FROM scan_codes WHERE code = $1 AND used = FALSE AND expires_at > NOW()',
      [code]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: '二维码无效或已过期' });
    const scanCode = result.rows[0];
    await pool.query('UPDATE scan_codes SET used = TRUE WHERE id = $1', [scanCode.id]);
    const newSessionId = crypto.randomBytes(16).toString('hex');
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [newSessionId, scanCode.user_id]);
    const token = jwt.sign({ userId: scanCode.user_id, sessionId: newSessionId }, JWT_SECRET, { expiresIn: '7d' });
    const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [scanCode.user_id]);
    const username = userResult.rows[0]?.username || '';
    res.json({ token, user: { id: scanCode.user_id, username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '扫码登录失败' });
  }
});

app.get('/api/user/token', requireAuth, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query('SELECT api_token FROM users WHERE id = $1', [userId]);
    let token = result.rows[0]?.api_token;
    if (!token) {
      token = crypto.randomBytes(32).toString('hex');
      await pool.query('UPDATE users SET api_token = $1 WHERE id = $2', [token, userId]);
    }
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取令牌失败' });
  }
});

// ---------- 产品线 API（简化，仅列出 digital 和 silent 作为示例，其他类似）----------
app.get('/api/digital/config', authenticateWebOrApi, async (req, res) => {
  const userId = req.userId;
  try {
    let result = await pool.query('SELECT * FROM digital_config WHERE user_id = $1', [userId]);
    if (result.rows.length === 0) {
      await pool.query(
        'INSERT INTO digital_config (user_id, current_version, features) VALUES ($1, $2, $3)',
        [userId, '1.0', { voice_enabled: false, notification_enabled: true }]
      );
      result = await pool.query('SELECT * FROM digital_config WHERE user_id = $1', [userId]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取配置失败' });
  }
});
app.post('/api/digital/config', authenticateWebOrApi, async (req, res) => {
  const userId = req.userId;
  const { features } = req.body;
  try {
    await pool.query('UPDATE digital_config SET features = $1 WHERE user_id = $2', [features, userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '更新配置失败' });
  }
});
// silent, pro, cyber 类似，此处省略重复代码（实际可参考之前版本）

// ---------- 地图导航 ----------
const AMAP_KEY = process.env.AMAP_KEY;
function isCoordinate(str) {
  if (!str) return false;
  const parts = str.split(',');
  if (parts.length !== 2) return false;
  const lng = parseFloat(parts[0]), lat = parseFloat(parts[1]);
  return !isNaN(lng) && !isNaN(lat) && lng >= 73 && lng <= 135 && lat >= 18 && lat <= 54;
}
async function parseUserInput(userText) {
  const prompt = `请从以下用户输入中提取目的地和偏好，只返回JSON格式，如 {"destination":"火车站","preference":"最快路线"}。如果无法提取，destination 设为 null。输入：${userText}`;
  const response = await client.ChatCompletions({
    Model: 'hunyuan-lite',
    Messages: [{ Role: 'user', Content: prompt }],
  });
  const content = response.Choices[0].Message.Content;
  try {
    return JSON.parse(content);
  } catch (err) {
    return { destination: null, preference: '推荐路线' };
  }
}
async function planRoute(from, to, preference) {
  const geocodeUrl = 'https://restapi.amap.com/v3/geocode/geo';
  const geocodeRes = await axios.get(geocodeUrl, { params: { address: to, key: AMAP_KEY, output: 'JSON' } });
  if (geocodeRes.data.status !== '1') throw new Error('地理编码失败：' + geocodeRes.data.info);
  const destLocation = geocodeRes.data.geocodes[0].location;
  let originLocation = null;
  if (from && isCoordinate(from)) originLocation = from;
  else if (from && from !== 'auto') {
    const originGeocode = await axios.get(geocodeUrl, { params: { address: from, key: AMAP_KEY, output: 'JSON' } });
    if (originGeocode.data.status === '1' && originGeocode.data.geocodes.length > 0)
      originLocation = originGeocode.data.geocodes[0].location;
  }
  if (!originLocation) originLocation = '116.397428,39.90923';
  const directionUrl = 'https://restapi.amap.com/v3/direction/driving';
  const params = { origin: originLocation, destination: destLocation, key: AMAP_KEY, output: 'JSON', extensions: 'all' };
  if (preference === '最快路线') params.strategy = 0;
  else if (preference === '最短路线') params.strategy = 2;
  else if (preference === '避开高速') params.strategy = 3;
  const directionRes = await axios.get(directionUrl, { params });
  if (directionRes.data.status !== '1') throw new Error('路线规划失败：' + directionRes.data.info);
  const route = directionRes.data.route.paths[0];
  const distance = (route.distance / 1000).toFixed(1);
  const duration = Math.round(route.duration / 60);
  const steps = route.steps.map(step => step.instruction);
  const polyline = route.steps.map(step => step.polyline).join(';');
  return {
    destination: to,
    distance: `${distance} km`,
    duration: `${duration} 分钟`,
    steps,
    polyline,
    raw_distance: parseFloat(distance),
    raw_duration: duration
  };
}
app.post('/api/maps/navigate', async (req, res) => {
  const { query, origin } = req.body;
  if (!query) return res.status(400).json({ error: '缺少目的地描述' });
  let userId = null;
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
    } catch (err) { /* 忽略 */ }
  }
  try {
    const parsed = await parseUserInput(query);
    if (!parsed.destination) return res.status(400).json({ error: '无法识别目的地' });
    const routeData = await planRoute(origin, parsed.destination, parsed.preference);
    const result = { success: true, ...routeData };
    if (userId) {
      await pool.query(
        `INSERT INTO navigation_history (user_id, origin, destination, distance_km, duration_min, route_data)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, origin || 'auto', parsed.destination, routeData.raw_distance, routeData.raw_duration, result]
      );
    }
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || '导航服务异常' });
  }
});
app.get('/api/maps/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, origin, destination, distance_km, duration_min, created_at
       FROM navigation_history
       WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 50`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取历史失败' });
  }
});

// ---------- 浏览器 ----------
app.post('/api/browser/search', async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: '请输入要搜索的内容' });

  let userId = null;
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
    } catch (err) { /* token无效 */ }
  }

  const prompt = `你是一个智能网址导航助手。根据用户输入，返回对应的官方网站链接。输出必须为JSON数组，每个元素包含 name 和 url 字段。如果用户指定了国家/地区，请返回该国对应的官方域名。例如：
- 输入："我想去百度" → [{"name":"百度","url":"https://www.baidu.com"}]
- 输入："去中国的苹果官网" → [{"name":"Apple 中国","url":"https://www.apple.com.cn"}]
- 输入："韩国的苹果" → [{"name":"Apple 대한민국","url":"https://www.apple.com/kr/"}]
- 输入："我想看哔哩哔哩" → [{"name":"哔哩哔哩","url":"https://www.bilibili.com"}]
- 输入："去谷歌" → [{"name":"Google","url":"https://www.google.com"}]

现在用户输入：${query}
只输出JSON数组，不要其他文字。`;

  try {
    const response = await client.ChatCompletions({
      Model: 'hunyuan-lite',
      Messages: [{ Role: 'user', Content: prompt }],
    });
    const content = response.Choices[0].Message.Content;
    let results;
    try {
      results = JSON.parse(content);
    } catch (e) {
      const match = content.match(/\[[\s\S]*\]/);
      if (match) results = JSON.parse(match[0]);
      else throw new Error('AI 返回格式错误');
    }
    if (!Array.isArray(results)) results = [results];

    if (userId) {
      await pool.query(
        'INSERT INTO browser_history (user_id, query, results) VALUES ($1, $2, $3)',
        [userId, query, JSON.stringify(results)]
      );
    }

    res.json({ success: true, results });
  } catch (err) {
    console.error('浏览器搜索失败:', err);
    res.status(500).json({ error: '无法解析，请稍后再试' });
  }
});

// 获取当前用户的浏览器搜索历史（需登录）
app.get('/api/browser/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT query, results, created_at FROM browser_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取历史失败' });
  }
});

// ---------- 环境变量检查 ----------
if (!process.env.BASE_URL) console.warn('⚠️ 环境变量 BASE_URL 未设置，二维码生成可能失败。');
if (!AMAP_KEY) console.warn('⚠️ 环境变量 AMAP_KEY 未设置，地图导航将无法使用。');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});