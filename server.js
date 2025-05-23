const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

const API_KEY_ID = process.env.API_KEY_ID;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

function generateJWT() {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: API_KEY_ID,
    iss: API_KEY_ID,
    iat: now,
    exp: now + 180
  };

  return jwt.sign(payload, PRIVATE_KEY, { algorithm: 'ES256' });
}

app.post('/webhook', async (req, res) => {
  try {
    const jwtToken = generateJWT();

    const response = await axios.post(
      'https://api.coinbase.com/api/v3/brokerage/orders',
      {
        client_order_id: 'bot-' + Date.now(),
        product_id: 'BTC-USD',
        side: 'BUY',
        order_configuration: {
          market_market_ioc: {
            quote_size: '50.00'
          }
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.status(200).json({ status: 'Order sent', data: response.data });
  } catch (error) {
    console.error('ERROR:', error.response?.data || error.message);
    res.status(500).json({ status: 'Failed', error: error.response?.data || error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Webhook running on port ${PORT}`);
});
