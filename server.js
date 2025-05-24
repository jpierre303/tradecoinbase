// Importar módulos necesarios
const express = require("express");
const bodyParser = require("body-parser"); // Para parsear el cuerpo de las solicitudes HTTP
const jwt = require("jsonwebtoken"); // Para generar y verificar JSON Web Tokens
const axios = require("axios"); // Para hacer solicitudes HTTP a Coinbase
const crypto = require("crypto"); // Módulo nativo de Node.js para criptografía
require("dotenv").config(); // Para cargar variables de entorno (Render las maneja, pero la línea es necesaria para el módulo)

// Inicializar Express
const app = express();

// Middleware para parsear cuerpos de solicitud JSON
app.use(bodyParser.json());

// Variables de entorno (Render las proporciona)
const API_KEY_ID = process.env.API_KEY_ID;
// El PRIVATE_KEY necesita que los saltos de línea sean reales.
// La función .replace(/\\n/g, '\n') asegura que si los saltos de línea
// están escapados como '\n', se conviertan en caracteres de salto de línea reales.
const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

// === FUNCIÓN PARA GENERAR EL JWT PARA AUTENTICACIÓN DE COINBASE ===
// Esta función ahora toma el método HTTP, la ruta de la API y el cuerpo de la solicitud
// porque estos son necesarios para construir el 'sub' claim (hash) del JWT de Coinbase.
function generateJWT(method, path, body) {
    const now = Math.floor(Date.now() / 1000); // Tiempo actual en segundos (nbf: Not Before)
    const exp = now + 60; // El token expira en 60 segundos (Coinbase recomienda tokens de corta vida)

    // Construir el 'content' para el hash SHA256 del claim 'sub'
    // Coinbase requiere: método + ruta + cuerpo_de_la_solicitud (si es POST/PUT y tiene cuerpo)
    let contentToHash = method + path;
    let bodyString = '';
    if (body && Object.keys(body).length > 0) {
        // Asegúrate de que el cuerpo sea una cadena JSON si existe.
        // Importante: JSON.stringify(body) debe producir la misma cadena exacta que Coinbase usa internamente.
        // Asegúrate de no tener espacios o formato diferente.
        bodyString = JSON.stringify(body);
        contentToHash += bodyString;
    }

    // --- DEBUGGING: Logs para verificar el contenido del hash ---
    console.log("DEBUG_JWT: Method for hash:", method);
    console.log("DEBUG_JWT: Path for hash:", path);
    console.log("DEBUG_JWT: Body (stringified) for hash:", bodyString);
    console.log("DEBUG_JWT: Full contentToHash for SHA256:", contentToHash);
    // --- FIN DEBUGGING ---

    // Generar el hash SHA256 del contenido
    const subHash = crypto.createHash('sha256').update(contentToHash).digest('hex');

    // --- DEBUGGING: Log el subHash generado ---
    console.log("DEBUG_JWT: Generated subHash:", subHash);
    // --- FIN DEBUGGING ---

    // Carga útil (payload) del JWT para Coinbase
    const jwtPayload = {
        aud: "coinbase", // Audiencia fija para la API de Coinbase
        exp: exp,        // Tiempo de expiración
        nbf: now,        // No antes de (tiempo actual)
        iss: API_KEY_ID, // El ID de tu clave API
        sub: subHash     // EL HASH SHA256 DEL REQUEST (MÉTODO + RUTA + CUERPO)
        // Opcional: puedes agregar 'api: "retail_rest_api"' si los docs de Coinbase lo especifican para tu tipo de clave,
        // pero para la API de "Brokerage" a menudo no es necesario.
    };

    // --- DEBUGGING: Log el payload completo del JWT ---
    console.log("DEBUG_JWT: Full JWT Payload:", JSON.stringify(jwtPayload));
    // --- FIN DEBUGGING ---

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
        const orderDetails = req.body;

        console.log("--> Webhook recibido con los siguientes detalles de orden:", orderDetails);

        // Validar que orderDetails no esté vacío (si esperas un cuerpo de Make.com)
        if (!orderDetails || Object.keys(orderDetails).length === 0) {
            console.error("Error: El cuerpo de la solicitud de Make.com está vacío o no es válido.");
            return res.status(400).json({ error: "Request body is empty or invalid. Please configure Make.com to send order details." });
        }

        // Definir los detalles de la solicitud a Coinbase
        const coinbaseApiMethod = 'POST';
        const coinbaseApiPath = '/api/v3/brokerage/orders'; // La ruta exacta sin el dominio base
        const coinbaseApiUrl = `https://api.coinbase.com${coinbaseApiPath}`; // URL completa para axios

        // Generar el JWT para la solicitud específica a Coinbase
        // Asegúrate de pasar el mismo método, ruta y cuerpo que enviarás en la solicitud axios a Coinbase.
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
        // Manejo de errores detallado
        let errorMessage = "Un error desconocido ocurrió.";
        if (error.response) {
            // El error es de la respuesta HTTP (ej. de Coinbase)
            console.error("<-- Error de la API de Coinbase:", error.response.status, error.response.data);
            errorMessage = `Error de la API de Coinbase (${error.response.status}): ${JSON.stringify(error.response.data)}`;
        } else if (error.request) {
            // La solicitud fue hecha pero no se recibió respuesta (problema de red/timeout)
            console.error("<-- No se recibió respuesta de Coinbase (problema de red/timeout):", error.request);
            errorMessage = "No se pudo conectar con la API de Coinbase o la solicitud expiró.";
        } else {
            // Algo más causó el error (ej. error en el código local antes de la solicitud HTTP)
            console.error("<-- Error al configurar o ejecutar la solicitud (código local):", error.message);
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
