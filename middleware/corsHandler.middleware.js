const cors = require("cors");
const CorsOrigin = require("../models/corsOrigin");

function normalizeOrigin(origin) {
    try {
        const url = new URL(origin);
        return url.origin;
    } catch {
        return String(origin || "").replace(/\/+$/, "");
    }
}

function readConfiguredOrigins() {
    const defaults = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5000",
        "https://joinshivam-bauth.vercel.app",
        "https://sbb7308z-3000.inc1.devtunnels.ms",
        "https://bauth-client.onrender.com",
        "https://joinshivam-global-chat.vercel.app"
    ];

    const configured = String(process.env.CORS_ORIGIN || "")
        .replace(/^\[/, "")
        .replace(/\]$/, "")
        .split(",")
        .map((origin) => origin.trim().replace(/^['"]|['"]$/g, ""))
        .filter(Boolean);

    return [...new Set([
        ...defaults,
        process.env.FRONTEND_URL,
        process.env.IDP_FRONTEND_BASE_URL,
        process.env.SAMPLE_CHAT_CLIENT_URL,
        ...configured,
    ]
        .filter(Boolean)
        .map(normalizeOrigin))];
}

const configuredOrigins = readConfiguredOrigins();

async function isOriginAllowed(origin) {
    if (!origin) return true;

    const normalizedOrigin = normalizeOrigin(origin);

    try {
        const managedOrigin = await CorsOrigin.getByOrigin(normalizedOrigin);

        if (managedOrigin) {
            return managedOrigin.status === "online" && managedOrigin.policy === "allow";
        }
    } catch {
        return configuredOrigins.includes(normalizedOrigin);
    }

    return configuredOrigins.includes(normalizedOrigin);
}

function createCorsHandler() {
    return cors({
        origin(origin, callback) {
            isOriginAllowed(origin)
                .then((allowed) => {
                    if (allowed) return callback(null, true);
                    return callback(new Error("Not allowed by CORS"));
                })
                .catch((err) => callback(err));
        },
        credentials: true
    });
}

function getSocketAllowedOrigins() {
    return configuredOrigins;
}

module.exports = {
    createCorsHandler,
    getSocketAllowedOrigins,
    readConfiguredOrigins,
};
