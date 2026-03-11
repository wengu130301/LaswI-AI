require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// 腾讯混元SDK
const tencentcloud = require('tencentcloud-sdk-nodejs-hunyuan');
const HunyuanClient = tencentcloud.hunyuan.v20230901.Client;

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 托管静态文件 (前端界面)
app.use(express.static(path.join(__dirname, 'public')));

// 显式指定根路由返回 index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 初始化腾讯混元客户端
const clientConfig = {
  credential: {
    secretId: process.env.TENCENT_SECRET_ID,
    secretKey: process.env.TENCENT_SECRET_KEY,
  },
  region: 'ap-guangzhou',  // 如果不行，可以尝试 ap-beijing 或 ap-shanghai
  profile: {
    httpProfile: {
      endpoint: 'hunyuan.tencentcloudapi.com',
    },
  },
};
const client = new HunyuanClient(clientConfig);

// 聊天API端点
app.post('/api/chat', async (req, res) => {
  try {
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: '消息格式错误' });
    }

    // 转换字段名：role -> Role, content -> Content（首字母大写）
    const convertedMessages = messages.map(msg => ({
      Role: msg.role,
      Content: msg.content
    }));

    // 调用混元API
    const response = await client.ChatCompletions({
      Model: process.env.MODEL || 'hunyuan-pro',
      Messages: convertedMessages,
      // 可选参数: Temperature, TopP 等
    });

    // 提取回复内容
    const reply = response.Choices?.[0]?.Message?.Content;
    if (!reply) {
      throw new Error('API返回内容为空');
    }

    res.json({ reply });
  } catch (error) {
    // 详细错误输出
    console.error('========== 腾讯混元API详细错误 ==========');
    console.error('错误对象:', error);
    if (error.code) console.error('错误码:', error.code);
    if (error.message) console.error('错误消息:', error.message);
    if (error.data) console.error('错误数据:', error.data);
    console.error('======================================');

    res.status(500).json({ 
      error: '服务器内部错误',
      detail: error.message || '未知错误',
      code: error.code || 'UNKNOWN'
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`LaswI AI 服务器运行在 http://localhost:${PORT}`);
});