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

// 腾讯混元SDK
const tencentcloud = require('tencentcloud-sdk-nodejs-hunyuan');
const HunyuanClient = tencentcloud.hunyuan.v20230901.Client;

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 静态文件
app.use(express.static(path.join(__dirname, 'public')));

// 根路由
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

    // 添加 current_session 字段（如果不存在）
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN current_session VARCHAR(255);`);
      console.log('✅ 字段 current_session 已添加到 users');
    } catch (err) {
      if (!err.message.includes('already exists')) {
        console.error('添加字段 current_session 时出错:', err);
      } else {
        console.log('ℹ️ 字段 current_session 已存在');
      }
    }

    // 添加 api_token 字段（用于快捷指令认证）
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN api_token VARCHAR(64) UNIQUE;`);
      console.log('✅ 字段 api_token 已添加到 users');
    } catch (err) {
      if (!err.message.includes('already exists')) {
        console.error('添加字段 api_token 时出错:', err);
      } else {
        console.log('ℹ️ 字段 api_token 已存在');
      }
    }

    // conversations 表
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

    // scan_codes 表（用于二维码登录）
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

    // 为 scan_codes 表创建索引
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_scan_codes_code ON scan_codes(code);
    `);
    console.log('✅ 索引 idx_scan_codes_code 已就绪');

    // digital_config 表（用于数字系列配置）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS digital_config (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        current_version VARCHAR(20) DEFAULT '1.0',
        features JSONB DEFAULT '{}',
        last_check TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id)
      );
    `);
    console.log('✅ 表 digital_config 已就绪');

  } catch (err) {
    console.error('❌ 自动建表失败:', err);
  }
})();

// JWT 密钥
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// 初始化腾讯混元客户端
const clientConfig = {
  credential: {
    secretId: process.env.TENCENT_SECRET_ID,
    secretKey: process.env.TENCENT_SECRET_KEY,
  },
  region: 'ap-guangzhou',
  profile: {
    httpProfile: {
      endpoint: 'hunyuan.tencentcloudapi.com',
    },
  },
};
const client = new HunyuanClient(clientConfig);

// ---------- 辅助函数：解析 JWT token（异步，验证会话） ----------
const getUserFromToken = async (req) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // 检查会话是否有效
    const result = await pool.query('SELECT current_session FROM users WHERE id = $1', [decoded.userId]);
    const currentSession = result.rows[0]?.current_session;
    if (currentSession && currentSession !== decoded.sessionId) {
      return null; // 会话已过期
    }
    return decoded;
  } catch (err) {
    return null;
  }
};

// Web 端认证中间件（使用 JWT）
const requireAuth = async (req, res, next) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: '未授权' });
  req.user = user;
  next();
};

// ---------- 混合认证中间件：先尝试 JWT，再尝试 API 令牌 ----------
const authenticateWebOrApi = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '缺少认证信息' });

  // 先尝试作为 JWT 验证（Web 端登录）
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // 可选：检查会话是否有效（如果需要）
    const result = await pool.query('SELECT current_session FROM users WHERE id = $1', [decoded.userId]);
    const currentSession = result.rows[0]?.current_session;
    if (currentSession && currentSession !== decoded.sessionId) {
      return res.status(401).json({ error: '会话已过期，请重新登录' });
    }
    req.userId = decoded.userId;
    return next();
  } catch (jwtErr) {
    // JWT 验证失败，尝试作为 API 令牌
    try {
      const result = await pool.query('SELECT id FROM users WHERE api_token = $1', [token]);
      if (result.rows.length === 0) {
        return res.status(401).json({ error: '认证无效' });
      }
      req.userId = result.rows[0].id;
      return next();
    } catch (apiErr) {
      return res.status(401).json({ error: '认证失败' });
    }
  }
};

// ---------- 用户认证接口 ----------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码必填' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    const user = result.rows[0];
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '7d' });
    // 更新当前会话
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [sessionId, user.id]);
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: '用户名已存在' });
    }
    console.error(err);
    res.status(500).json({ error: '注册失败' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '7d' });
    // 更新当前会话
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [sessionId, user.id]);
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '登录失败' });
  }
});

// ---------- 聊天接口（可选认证）----------
app.post('/api/chat', async (req, res) => {
  const { messages } = req.body;
  const user = await getUserFromToken(req); // 异步调用

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: '消息格式错误' });
  }

  try {
    const convertedMessages = messages.map(msg => ({
      Role: msg.role,
      Content: msg.content
    }));

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

// 获取历史记录（Web端使用 JWT）
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

// ---------- 二维码相关接口 ----------
// 生成二维码（Web端使用 JWT）
app.get('/api/qr/generate', requireAuth, async (req, res) => {
  try {
    const userId = req.user.userId;
    const sessionId = crypto.randomBytes(16).toString('hex'); // 当前会话标识

    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5分钟有效

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

// 扫码登录（无认证）
app.post('/api/qr/login', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: '缺少code' });

  try {
    const result = await pool.query(
      'SELECT * FROM scan_codes WHERE code = $1 AND used = FALSE AND expires_at > NOW()',
      [code]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: '二维码无效或已过期' });
    }
    const scanCode = result.rows[0];

    // 标记为已使用
    await pool.query('UPDATE scan_codes SET used = TRUE WHERE id = $1', [scanCode.id]);

    const newSessionId = crypto.randomBytes(16).toString('hex');
    await pool.query('UPDATE users SET current_session = $1 WHERE id = $2', [newSessionId, scanCode.user_id]);

    // 生成新 token
    const token = jwt.sign(
      { userId: scanCode.user_id, sessionId: newSessionId },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // 获取用户名（可选）
    const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [scanCode.user_id]);
    const username = userResult.rows[0]?.username || '';

    res.json({ token, user: { id: scanCode.user_id, username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '扫码登录失败' });
  }
});

// ---------- 用户令牌接口（供快捷指令使用）----------
// 获取或生成用户的 API 令牌（Web端使用 JWT）
app.get('/api/user/token', requireAuth, async (req, res) => {
  const userId = req.user.userId;
  try {
    // 查询是否已有令牌
    const result = await pool.query('SELECT api_token FROM users WHERE id = $1', [userId]);
    let token = result.rows[0]?.api_token;
    if (!token) {
      // 生成新令牌
      token = crypto.randomBytes(32).toString('hex');
      await pool.query('UPDATE users SET api_token = $1 WHERE id = $2', [token, userId]);
    }
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取令牌失败' });
  }
});

// ---------- 数字系列 API（使用混合认证，支持 Web 和快捷指令）----------
// 获取用户配置
app.get('/api/digital/config', authenticateWebOrApi, async (req, res) => {
  const userId = req.userId;
  try {
    let result = await pool.query('SELECT * FROM digital_config WHERE user_id = $1', [userId]);
    if (result.rows.length === 0) {
      const defaultFeatures = { voice_enabled: false, notification_enabled: true };
      await pool.query(
        'INSERT INTO digital_config (user_id, current_version, features) VALUES ($1, $2, $3)',
        [userId, '1.0', defaultFeatures]
      );
      result = await pool.query('SELECT * FROM digital_config WHERE user_id = $1', [userId]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取配置失败' });
  }
});

// 更新功能开关
app.post('/api/digital/config', authenticateWebOrApi, async (req, res) => {
  const userId = req.userId;
  const { features } = req.body;
  try {
    await pool.query(
      'UPDATE digital_config SET features = $1 WHERE user_id = $2',
      [features, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '更新配置失败' });
  }
});

// 获取最新版本信息（公开，无需认证）
app.get('/api/digital/latest-version', (req, res) => {
  res.json({
    version: '2.0',
    release_notes: '新增语音播报功能，优化稳定性',
    force_update: false
  });
});

// 上报当前版本（快捷指令调用）
app.post('/api/digital/report-version', authenticateWebOrApi, async (req, res) => {
  const userId = req.userId;
  const { version } = req.body;
  try {
    await pool.query(
      'UPDATE digital_config SET current_version = $1, last_check = NOW() WHERE user_id = $2',
      [version, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '上报失败' });
  }
});

// ---------- 环境变量检查 ----------
if (!process.env.BASE_URL) {
  console.warn('⚠️ 环境变量 BASE_URL 未设置，二维码生成可能失败。请设置 BASE_URL 为你的域名。');
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
