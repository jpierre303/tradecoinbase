const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

const API_KEY = process.env.API_KEY;
const API_SECRET = process.env.API_SECRET;

app.post("/order", async (req, res) => {
  try {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const method = "POST";
    const path = "/api/v3/brokerage/orders";
    const body = JSON.stringify(req.body);
    const prehash = timestamp + method + path + body;

    const signature = crypto
      .createHmac("sha256", API_SECRET)
      .update(prehash)
      .digest("base64");

    const response = await axios.post(
      "https://api.coinbase.com" + path,
      req.body,
      {
        headers: {
          "CB-ACCESS-KEY": API_KEY,
          "CB-ACCESS-SIGN": signature,
          "CB-ACCESS-TIMESTAMP": timestamp,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("❌ ERROR STATUS:", err.response?.status);
    console.error("❌ ERROR BODY:", err.response?.data);
    console.error("❌ FULL ERROR:", err.message);
    res.status(500).json({
      error: "Order failed",
      details: err.response?.data || err.message
    });
  }
});

app.get("/", (req, res) => {
  res.send("🚀 Webhook activo en Render");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
