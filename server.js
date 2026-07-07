const axios = require('axios');

app.post('/api/chat', async (req, res) => {
  const { messages } = req.body;
  const user = await getUserFromToken(req);
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: '消息格式错误' });
  }

  try {
    const convertedMessages = messages.map(msg => ({
      role: msg.role,      // OpenAI 使用小写 role
      content: msg.content
    }));

    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4o-mini',  // 或 'gpt-3.5-turbo'
        messages: convertedMessages,
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const reply = response.data.choices[0].message.content;
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
    console.error('OpenAI API 错误:', error.response?.data || error.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
