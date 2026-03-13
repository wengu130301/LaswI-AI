require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// 腾讯混元SDK
const tencentcloud = require('tencentcloud-sdk-nodejs-hunyuan');
const HunyuanClient = tencentcloud.hunyuan.v20230901.Client;

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 静态文件（前端）
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

// ---------- 辅助函数：解析 token（可选） ----------
const getUserFromToken = (req) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
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
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
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
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '登录失败' });
  }
});

// ---------- 聊天接口（可选认证）----------
app.post('/api/chat', async (req, res) => {
  const { messages } = req.body;
  const user = getUserFromToken(req); // 可能为 null

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: '消息格式错误' });
  }

  try {
    // 调用混元API
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

    // 如果用户已登录，保存对话记录
    if (user) {
      const userMsg = messages[messages.length - 1]; // 最后一条用户消息
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

// 获取历史记录（需认证）
app.get('/api/history', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: '未授权' });
  }
  try {
    const result = await pool.query(
      'SELECT role, content, timestamp FROM conversations WHERE user_id = $1 ORDER BY timestamp ASC',
      [user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '获取历史失败' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});