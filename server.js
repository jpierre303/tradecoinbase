const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

const API_KEY_ID = process.env.API_KEY_ID.trim();
const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

// === FUNCIÓN PARA GENERAR JWT ===
function generateJWT() {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 60;

    const jwtPayload = {
        aud: "coinbase",
        iat: now,
        exp: exp,
        nbf: now,
        iss: API_KEY_ID,
        sub: API_KEY_ID
    };

    console.log("DEBUG_JWT: Payload:", jwtPayload);

    return jwt.sign(jwtPayload, PRIVATE_KEY, {
        algorithm: "ES256",
        header: {
            alg: "ES256",
            typ: "JWT"
        }
    });
}

// === RUTA DEL WEBHOOK ===
app.post("/webhook", async (req, res) => {
    try {
        const orderDetails = req.body;
        console.log("--> Webhook recibido:", orderDetails);

        if (!orderDetails || Object.keys(orderDetails).length === 0) {
            return res.status(400).json({ error: "Request body is empty or invalid" });
        }

        const coinbaseApiMethod = 'POST';
        const coinbaseApiPath = '/api/v3/brokerage/orders';
        const coinbaseApiUrl = `https://api.coinbase.com${coinbaseApiPath}`;

        const jwtToken = generateJWT();

        const coinbaseResponse = await axios.post(
            coinbaseApiUrl,
            orderDetails,
            {
                headers: {
                    Authorization: `Bearer ${jwtToken}`,
                    "Content-Type": "application/json"
                },
            }
        );

        console.log("<-- Éxito:", coinbaseResponse.data);

        res.status(200).json({
            status: "Orden enviada correctamente",
            data: coinbaseResponse.data,
        });

    } catch (error) {
        let errorMessage = "Unknown error";
        if (error.response) {
            console.error("<-- Error de Coinbase:", error.response.status, error.response.data);
            errorMessage = `Coinbase API error (${error.response.status}): ${JSON.stringify(error.response.data)}`;
        } else if (error.request) {
            console.error("<-- Timeout o sin respuesta de Coinbase:", error.request);
            errorMessage = "No response from Coinbase or timeout";
        } else {
            console.error("<-- Error local:", error.message);
            errorMessage = `Internal error: ${error.message}`;
        }

        res.status(500).json({
            error: "Error al procesar la orden",
            details: errorMessage,
        });
    }
});

// === INICIAR EL SERVIDOR ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Webhook running on PORT ${PORT}`);
});
