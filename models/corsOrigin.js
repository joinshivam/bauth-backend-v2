const { getDB } = require("../database/database");

function normalizeOrigin(origin) {
    try {
        const url = new URL(origin);
        return url.origin;
    } catch {
        return String(origin || "").replace(/\/+$/, "");
    }
}

function isValidOrigin(origin) {
    try {
        const url = new URL(origin);
        return ["http:", "https:"].includes(url.protocol) && url.origin === origin;
    } catch {
        return false;
    }
}

async function listAll() {
    const db = getDB();
    const [rows] = await db.query(
        `SELECT *
         FROM cors_origins
         ORDER BY updated_at DESC, created_at DESC`
    );
    return rows;
}

async function getById(id) {
    const db = getDB();
    const [rows] = await db.query(
        `SELECT *
         FROM cors_origins
         WHERE id = ?
         LIMIT 1`,
        [id]
    );
    return rows[0] || null;
}

async function getByOrigin(origin) {
    const db = getDB();
    const [rows] = await db.query(
        `SELECT *
         FROM cors_origins
         WHERE origin = ?
         LIMIT 1`,
        [normalizeOrigin(origin)]
    );
    return rows[0] || null;
}

async function create({ label, origin, description, createdByUserId }) {
    const normalizedOrigin = normalizeOrigin(origin);

    if (!label || !String(label).trim()) {
        throw new Error("Label is required");
    }

    if (!isValidOrigin(normalizedOrigin)) {
        throw new Error("Origin must be a valid http/https origin, for example http://localhost:3001");
    }

    const db = getDB();
    await db.query(
        `INSERT INTO cors_origins
         (label, origin, description, status, policy, created_by_user_id)
         VALUES (?, ?, ?, 'online', 'allow', ?)`,
        [
            String(label).trim(),
            normalizedOrigin,
            String(description || "").trim() || null,
            createdByUserId || null,
        ]
    );
}

async function update(id, { label, origin, description }) {
    const normalizedOrigin = normalizeOrigin(origin);

    if (!label || !String(label).trim()) {
        throw new Error("Label is required");
    }

    if (!isValidOrigin(normalizedOrigin)) {
        throw new Error("Origin must be a valid http/https origin");
    }

    const db = getDB();
    await db.query(
        `UPDATE cors_origins
         SET label = ?, origin = ?, description = ?
         WHERE id = ?`,
        [
            String(label).trim(),
            normalizedOrigin,
            String(description || "").trim() || null,
            id,
        ]
    );
}

async function remove(id) {
    const db = getDB();
    await db.query("DELETE FROM cors_origins WHERE id = ?", [id]);
}

async function markOnline(id) {
    const db = getDB();
    await db.query("UPDATE cors_origins SET status = 'online' WHERE id = ?", [id]);
}

async function markOffline(id) {
    const db = getDB();
    await db.query("UPDATE cors_origins SET status = 'offline' WHERE id = ?", [id]);
}

async function allow(id) {
    const db = getDB();
    await db.query("UPDATE cors_origins SET policy = 'allow' WHERE id = ?", [id]);
}

async function block(id) {
    const db = getDB();
    await db.query("UPDATE cors_origins SET policy = 'block' WHERE id = ?", [id]);
}

async function allowedOnlineOrigins() {
    const db = getDB();
    const [rows] = await db.query(
        `SELECT origin
         FROM cors_origins
         WHERE status = 'online' AND policy = 'allow'
         ORDER BY origin`
    );
    return rows.map((row) => row.origin);
}

module.exports = {
    normalizeOrigin,
    listAll,
    getById,
    getByOrigin,
    create,
    update,
    remove,
    markOnline,
    markOffline,
    allow,
    block,
    allowedOnlineOrigins,
};
