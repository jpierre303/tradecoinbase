// Importar módulos necesarios
const express = require("express");
const bodyParser = require("body-parser"); // Para parsear el cuerpo de las solicitudes HTTP
const jwt = require("jsonwebtoken"); // Para generar y verificar JSON Web Tokens
const axios = require("axios"); // Para hacer solicitudes HTTP a Coinbase
const crypto = require("crypto"); // Módulo nativo de Node.js para criptografía (¡NUEVA IMPORTACIÓN!)
require("dotenv").config(); // Para cargar variables de entorno (si las usas localmente, Render las maneja)

// Inicializar Express
const app = express();

// Middleware para parsear cuerpos de solicitud JSON
app.use(bodyParser.json());

// Variables de entorno (Render las proporciona, si corres local, asegúrate de tener .env)
const API_KEY_ID = process.env.API_KEY_ID;
// El PRIVATE_KEY necesita que los saltos de línea sean reales, no '\n' escapados.
// Render maneja esto bien si lo pegas directamente con los saltos de línea.
const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n'); 

// === FUNCIÓN PARA GENERAR EL JWT PARA AUTENTICACIÓN DE COINBASE ===
// Esta función ahora toma el método HTTP, la ruta de la API y el cuerpo de la solicitud
// porque estos son necesarios para construir el 'sub' claim (hash) del JWT.
function generateJWT(method, path, body) {
    const now = Math.floor(Date.now() / 1000); // Tiempo actual en segundos (nbf: Not Before)
    const exp = now + 60; // El token expira en 60 segundos (Coinbase recomienda tokens de corta vida)

    // Construir el 'content' para el hash SHA256 del claim 'sub'
    // Coinbase requiere: método + ruta + cuerpo_de_la_solicitud (si es POST/PUT y tiene cuerpo)
    let contentToHash = method + path;
    if (body && Object.keys(body).length > 0) {
        // Asegúrate de que el cuerpo sea una cadena JSON si existe.
        // Importante: No uses espacios o formato en el JSON si Coinbase es estricto.
        contentToHash += JSON.stringify(body); 
    }

    // Generar el hash SHA256 del contenido
    const subHash = crypto.createHash('sha256').update(contentToHash).digest('hex');

    // Carga útil (payload) del JWT para Coinbase
    const jwtPayload = {
        aud: "coinbase", // Audiencia fija para la API de Coinbase
        exp: exp,        // Tiempo de expiración
        nbf: now,        // No antes de (tiempo actual)
        iss: API_KEY_ID, // El ID de tu clave API
        sub: subHash     // EL HASH SHA256 DEL REQUEST (MÉTODO + RUTA + CUERPO)
        // Puedes agregar 'api: "retail_rest_api"' si los docs de Coinbase lo especifican para tu tipo de clave,
        // pero para la API de "Brokerage" a menudo no es necesario.
    };

    // Firmar el JWT con la clave privada
    return jwt.sign(jwtPayload, PRIVATE_KEY, {
        algorithm: "ES256", // Algoritmo de firma: Elliptic Curve (ES256)
        header: { // Encabezado JWT, necesario para el algoritmo
            alg: "ES256",
            typ: "JWT"
        }
    });
}

// === RUTA DEL WEBHOOK ===
// Esta es la ruta que Make.com llamará.
app.post("/webhook", async (req, res) => {
    try {
        // req.body contendrá el JSON que Make.com te envíe.
        // Asegúrate de que Make.com envíe un JSON válido aquí.
        const orderDetails = req.body; 
        
        console.log("--> Webhook recibido con los siguientes detalles de orden:", orderDetails);

        // Validar que orderDetails no esté vacío (si esperas un cuerpo de Make.com)
        if (!orderDetails || Object.keys(orderDetails).length === 0) {
            console.error("Error: El cuerpo de la solicitud de Make.com está vacío o no es válido.");
            return res.status(400).json({ error: "Request body is empty or invalid. Please configure Make.com to send order details." });
        }

        // Definir los detalles de la solicitud a Coinbase
        const coinbaseApiMethod = 'POST';
        const coinbaseApiPath = '/api/v3/brokerage/orders';
        const coinbaseApiUrl = `https://api.coinbase.com${coinbaseApiPath}`;

        // Generar el JWT para la solicitud específica a Coinbase
        const jwtToken = generateJWT(
            coinbaseApiMethod,
            coinbaseApiPath,
            orderDetails // El cuerpo que se enviará a Coinbase (los detalles de la orden)
        );

        console.log("--> JWT generado exitosamente.");

        // Realizar la solicitud a la API de Coinbase
        const coinbaseResponse = await axios.post(
            coinbaseApiUrl,
            orderDetails, // El cuerpo de la solicitud HTTP a Coinbase
            {
                headers: {
                    Authorization: `Bearer ${jwtToken}`, // Usar el JWT para autenticación
                    "Content-Type": "application/json"   // Indicar que el cuerpo es JSON
                },
            }
        );

        console.log("<-- Solicitud a Coinbase exitosa. Respuesta:", coinbaseResponse.data);

        // Enviar una respuesta exitosa a Make.com
        res.status(200).json({
            status: "Orden enviada a Coinbase exitosamente",
            data: coinbaseResponse.data,
        });

    } catch (error) {
        // Manejo de errores
        let errorMessage = "Un error desconocido ocurrió.";
        if (error.response) {
            // El error es de la respuesta HTTP (ej. de Coinbase)
            console.error("<-- Error de la API de Coinbase:", error.response.status, error.response.data);
            errorMessage = `Error de la API de Coinbase (${error.response.status}): ${JSON.stringify(error.response.data)}`;
        } else if (error.request) {
            // La solicitud fue hecha pero no se recibió respuesta (problema de red)
            console.error("<-- No se recibió respuesta de Coinbase:", error.request);
            errorMessage = "No se pudo conectar con la API de Coinbase.";
        } else {
            // Algo más causó el error (ej. error en el código local)
            console.error("<-- Error al configurar la solicitud:", error.message);
            errorMessage = `Error interno del servidor: ${error.message}`;
        }

        // Enviar respuesta de error a Make.com
        res.status(500).json({
            error: "Fallo al procesar la orden o al comunicarse con Coinbase.",
            details: errorMessage,
        });
    }
});

// === INICIAR EL SERVIDOR ===
const PORT = process.env.PORT || 3000; // Render asigna un puerto a través de process.env.PORT
app.listen(PORT, () => {
    console.log(`Webhook running on PORT ${PORT} - waiting for Make.com requests...`);
});
