const express = require("express");
const bodyParser = require("body-parser"); // Para parsear el cuerpo de las solicitudes HTTP
const jwt = require("jsonwebtoken"); // Para generar y verificar JSON Web Tokens
const axios = require("axios"); // Para hacer solicitudes HTTP a Coinbase
const crypto = require("crypto"); // Módulo nativo de Node.js para criptografía
require("dotenv").config(); // Para cargar variables de entorno (Render las maneja, pero la línea es necesaria si lo corres localmente)

// Inicializar Express
const app = express();

// Middleware para parsear cuerpos de solicitud JSON
app.use(bodyParser.json());

// Variables de entorno (Render las proporciona a través de su interfaz)
const API_KEY_ID = process.env.API_KEY_ID;
// El PRIVATE_KEY necesita que los saltos de línea sean reales.
// La función .replace(/\\n/g, '\n') asegura que si los saltos de línea
// están escapados como '\n' (lo que podría ocurrir si se lee de un .env o algunos sistemas lo hacen),
// se conviertan en caracteres de salto de línea reales.
const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

// === FUNCIÓN AUXILIAR PARA CANONICALIZAR JSON ===
// Esta función ordena las claves de un objeto JSON alfabéticamente de forma recursiva.
// Esto es crucial para asegurar que JSON.stringify siempre produzca la misma cadena
// para el mismo conjunto de datos, lo cual es vital para el hash SHA256 del JWT 'sub' claim de Coinbase.
function sortObjectKeys(obj) {
    // Si no es un objeto o es nulo, retorna tal cual
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    // Si es un array, mapea recursivamente sus elementos
    if (Array.isArray(obj)) {
        return obj.map(sortObjectKeys);
    }
    // Si es un objeto, ordena sus claves y construye un nuevo objeto
    const sortedKeys = Object.keys(obj).sort();
    const sortedObj = {};
    for (const key of sortedKeys) {
        sortedObj[key] = sortObjectKeys(obj[key]); // Llama recursivamente para valores que también sean objetos
    }
    return sortedObj;
}


// === FUNCIÓN PARA GENERAR EL JWT PARA AUTENTICACIÓN DE COINBASE ===
// Esta función toma el método HTTP, la ruta de la API y el cuerpo de la solicitud
// para construir el 'sub' claim (hash) del JWT de Coinbase.
function generateJWT(method, path, body) {
    const now = Math.floor(Date.now() / 1000); // Tiempo actual en segundos (nbf: Not Before)
    const exp = now + 60; // El token expira en 60 segundos (Coinbase recomienda tokens de corta vida)

    let contentToHash = method + path;
    let bodyString = '';
    if (body && Object.keys(body).length > 0) {
        // --- CAMBIO CLAVE AQUÍ: CANONICALIZAR EL CUERPO ANTES DE STRINGIFICAR ---
        // Esto asegura que el orden de las claves en el JSON sea consistente para el hashing.
        const canonicalBody = sortObjectKeys(body);
        bodyString = JSON.stringify(canonicalBody);
        contentToHash += bodyString;
    }

    // --- DEBUGGING: Logs para verificar el contenido del hash ---
    console.log("DEBUG_JWT: Method for hash:", method);
    console.log("DEBUG_JWT: Path for hash:", path);
    console.log("DEBUG_JWT: Body (stringified) for hash:", bodyString); // Muestra el JSON canonicalizado
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
        exp: exp,        // Tiempo de expiración del token
        nbf: now,        // No antes de (tiempo actual)
        iss: API_KEY_ID, // El ID de tu clave API de Coinbase
        sub: subHash     // EL HASH SHA256 DEL REQUEST (MÉTODO + RUTA + CUERPO)
        // Puedes agregar 'api: "retail_rest_api"' si la documentación de Coinbase lo especifica para tu tipo de clave,
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
// Esta es la ruta que Make.com llamará para enviar los detalles de la orden.
app.post("/webhook", async (req, res) => {
    try {
        // req.body contendrá el JSON que Make.com te envíe.
        const orderDetails = req.body;

        console.log("--> Webhook recibido con los siguientes detalles de orden:", orderDetails);

        // Validar que orderDetails no esté vacío. Si Make.com no envía nada, podría ser un problema.
        if (!orderDetails || Object.keys(orderDetails).length === 0) {
            console.error("Error: El cuerpo de la solicitud de Make.com está vacío o no es válido.");
            return res.status(400).json({ error: "Request body is empty or invalid. Please configure Make.com to send order details." });
        }

        // Definir los detalles de la solicitud a la API de Coinbase
        const coinbaseApiMethod = 'POST';
        const coinbaseApiPath = '/api/v3/brokerage/orders'; // La ruta exacta de la API de Coinbase sin el dominio base
        const coinbaseApiUrl = `https://api.coinbase.com${coinbaseApiPath}`; // URL completa para la solicitud axios

        // Generar el JWT para la solicitud específica a Coinbase.
        // Es CRÍTICO que los argumentos (método, ruta, cuerpo) coincidan exactamente
        // con los de la solicitud axios que se hará a Coinbase.
        const jwtToken = generateJWT(
            coinbaseApiMethod,
            coinbaseApiPath,
            orderDetails // El cuerpo que se enviará a Coinbase (los detalles de la orden)
        );

        console.log("--> JWT generado exitosamente.");

        // Realizar la solicitud a la API de Coinbase para crear la orden
        const coinbaseResponse = await axios.post(
            coinbaseApiUrl,
            orderDetails, // El cuerpo de la solicitud HTTP (los detalles de la orden)
            {
                headers: {
                    Authorization: `Bearer ${jwtToken}`, // Usar el JWT para autenticación
                    "Content-Type": "application/json"   // Indicar que el cuerpo de la solicitud es JSON
                },
            }
        );

        console.log("<-- Solicitud a Coinbase exitosa. Respuesta:", coinbaseResponse.data);

        // Enviar una respuesta exitosa de vuelta a Make.com
        res.status(200).json({
            status: "Orden enviada a Coinbase exitosamente",
            data: coinbaseResponse.data,
        });

    } catch (error) {
        // Manejo de errores detallado
        let errorMessage = "Un error desconocido ocurrió.";
        if (error.response) {
            // El error es una respuesta HTTP recibida (ej. de la API de Coinbase)
            console.error("<-- Error de la API de Coinbase:", error.response.status, error.response.data);
            errorMessage = `Error de la API de Coinbase (${error.response.status}): ${JSON.stringify(error.response.data)}`;
        } else if (error.request) {
            // La solicitud fue hecha, pero no se recibió respuesta (problema de red o timeout)
            console.error("<-- No se recibió respuesta de Coinbase (problema de red/timeout):", error.request);
            errorMessage = "No se pudo conectar con la API de Coinbase o la solicitud expiró.";
        } else {
            // Algo más causó el error (ej. error en el código local antes de la solicitud HTTP)
            console.error("<-- Error al configurar o ejecutar la solicitud (código local):", error.message);
            errorMessage = `Error interno del servidor: ${error.message}`;
        }

        // Enviar respuesta de error a Make.com con el código de estado 500
        res.status(500).json({
            error: "Fallo al procesar la orden o al comunicarse con Coinbase.",
            details: errorMessage,
        });
    }
});

// === INICIAR EL SERVIDOR ===
// Render asignará un puerto a tu aplicación a través de process.env.PORT.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Webhook running on PORT ${PORT} - waiting for Make.com requests...`);
});
