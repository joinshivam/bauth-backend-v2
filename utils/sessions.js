const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const Env = require("../env");
const { getDB } = require("../database/database");
const cookies = require("./cookies");

const LEGACY_SESSION_COOKIE_NAME = "user_sessions";
const SESSION_COOKIE_NAME = Env.SESSION_COOKIE_NAME || LEGACY_SESSION_COOKIE_NAME;
const ACTIVE_SESSION_COOKIE_NAME = process.env.ACTIVE_SESSION_COOKIE_NAME || "active_session";

function ttlHours() {
    const hours = Number(Env.SESSION_TTL_HOURS || 24);
    return Number.isFinite(hours) && hours > 0 ? hours : 24;
}

function tokenHash(value) {
    return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function randomToken() {
    return crypto.randomBytes(32).toString("hex");
}

function getSessionRefs(req) {
    if (req.__sessionRefs) {
        return req.__sessionRefs;
    }
    try {
        const token =
            cookies.getCookie(req, SESSION_COOKIE_NAME) ||
            cookies.getCookie(req, LEGACY_SESSION_COOKIE_NAME);

        if (!token) return {};

        const decoded = jwt.verify(token, Env.JWT_SECRET);
        if (decoded?.v === 2 && decoded?.sessions && typeof decoded.sessions === "object") {
            return decoded.sessions;
        }

        return {};
    } catch {
        return {};
    }
}

function setSessionRefs(res, refs) {
    const maxAge = ttlHours() * 60 * 60 * 1000;
    const token = jwt.sign(
        {
            v: 2,
            sessions: refs,
        },
        Env.JWT_SECRET,
        { expiresIn: `${ttlHours()}h` }
    );

    cookies.setCookie(res, SESSION_COOKIE_NAME, token, { maxAge });

    if (SESSION_COOKIE_NAME !== LEGACY_SESSION_COOKIE_NAME) {
        cookies.clearCookie(res, LEGACY_SESSION_COOKIE_NAME);
    }
}

function clearSessionCookies(res) {
    cookies.clearCookie(res, SESSION_COOKIE_NAME);
    cookies.clearCookie(res, ACTIVE_SESSION_COOKIE_NAME);

    if (SESSION_COOKIE_NAME !== LEGACY_SESSION_COOKIE_NAME) {
        cookies.clearCookie(res, LEGACY_SESSION_COOKIE_NAME);
    }
}

function safeUserSession(row) {
    return {
        sub: row.user_id,
        id: row.user_id,
        db_session_id: row.db_session_id,
        username: row.username,
        email: row.email,
        name: row.name,
        profilePhoto: row.photo,
        photo: row.photo,
        user_agent: row.user_agent,
        ip: row.ip_address,
        ip_address: row.ip_address,
        created_at: row.created_at,
        expires_at: row.expires_at,
    };
}

async function getSessions(req) {
    const refs = getSessionRefs(req);
    const sessionIds = Object.keys(refs).filter((sessionId) => refs[sessionId]);
    if (!sessionIds.length) return {};

    const hashes = sessionIds.map((sessionId) => tokenHash(refs[sessionId]));

    const placeholders = hashes.map(() => "?").join(",");
    const db = getDB();
    const [rows] = await db.query(
        `SELECT
           s.id AS db_session_id,
           s.user_id,
           s.session_token,
           s.user_agent,
           s.ip_address,
           s.expires_at,
           s.created_at,
           u.name,
           u.username,
           u.email,
           u.phone,
           u.photo,
           u.gender,
           u.dob
         FROM user_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.session_token IN (${placeholders})
           AND s.revoked = 0
           AND s.expires_at > NOW()`,
        hashes
    );
    console.log("Sessions fetched from DB:", rows.length, "hashes queried:", hashes.length, placeholders);
    console.log("DB ROWS:", rows);
    const rowsByToken = new Map(rows.map((row) => [row.session_token, row]));
    const sessions = {};

    for (const sessionId of sessionIds) {
        const row = rowsByToken.get(tokenHash(refs[sessionId]));
        if (row) {
            sessions[sessionId] = safeUserSession(row);
        }
    }
    console.log("4. Active sessions retrieved:", sessions);

    return sessions;
}

async function addSession(req, res, sessionPayload) {
    const sessions = await getSessions(req);
    const refs = getSessionRefs(req);
    const existingSessionId = Object.keys(sessions).find(
        (key) => String(sessions[key]?.sub) === String(sessionPayload?.sub)
    );
    if (existingSessionId && refs[existingSessionId]) {
        const db = getDB();
        await db.query(
            "UPDATE user_sessions SET expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR), revoked = 0 WHERE session_token = ?",
            [ttlHours(), tokenHash(refs[existingSessionId])]
        );
        cookies.setCookie(res, ACTIVE_SESSION_COOKIE_NAME, existingSessionId, {
            maxAge: ttlHours() * 60 * 60 * 1000,
        });
        return existingSessionId;
    }
    const rawToken = randomToken();
    const db = getDB();
    const [result] = await db.query(
        `INSERT INTO user_sessions
         (user_id, session_token, user_agent, ip_address, expires_at, revoked)
         VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), 0)`,
        [
            sessionPayload.sub,
            tokenHash(rawToken),
            sessionPayload.user_agent || null,
            sessionPayload.ip || null,
            ttlHours(),
        ]
    );

    const [debugRows] = await db.query(
        `SELECT *
     FROM user_sessions
     WHERE id = ?`,
        [result.insertId]
    );

    console.log(
        "DEBUG INSERTED SESSION:",
        debugRows[0]
    );

    const sessionId = `s_${result.insertId}`;
    refs[sessionId] = rawToken;
    req.__sessionRefs = refs;
    setSessionRefs(res, refs);
    cookies.setCookie(res, ACTIVE_SESSION_COOKIE_NAME, sessionId, {
        maxAge: ttlHours() * 60 * 60 * 1000,
    });

    return sessionId;
}

function getActiveSession(req) {
    const activeSession = cookies.getCookie(req, ACTIVE_SESSION_COOKIE_NAME);
    const refs = getSessionRefs(req);

    if (activeSession && refs[activeSession]) return activeSession;
    return Object.keys(refs)[0] || null;
}

async function getActiveUser(req, res) {
    const activeSession = getActiveSession(req);
    if (!activeSession) return null;

    const sessions = await getSessions(req);
    if (sessions[activeSession]) return sessions[activeSession];

    const fallbackSessionId = Object.keys(sessions)[0];
    if (!fallbackSessionId) return null;

    if (res) {
        cookies.setCookie(res, ACTIVE_SESSION_COOKIE_NAME, fallbackSessionId, {
            maxAge: ttlHours() * 60 * 60 * 1000,
        });
    }

    return sessions[fallbackSessionId];
}

async function switchSession(req, res, sessionId) {
    const sessions = await getSessions(req);
    if (!sessions[sessionId]) return false;

    cookies.setCookie(res, ACTIVE_SESSION_COOKIE_NAME, sessionId, {
        maxAge: ttlHours() * 60 * 60 * 1000,
    });
    return true;
}

async function clearSession(req, res, sessionId) {
    if (!sessionId) return;

    const refs = getSessionRefs(req);
    const rawToken = refs[sessionId];
    const wasActive = cookies.getCookie(req, ACTIVE_SESSION_COOKIE_NAME) === sessionId;

    if (rawToken) {
        const db = getDB();
        await db.query(
            "UPDATE user_sessions SET revoked = 1 WHERE session_token = ?",
            [tokenHash(rawToken)]
        );
    }

    delete refs[sessionId];

    const remaining = Object.keys(refs);
    if (remaining.length) {
        setSessionRefs(res, refs);
    } else {
        clearSessionCookies(res);
        return;
    }

    if (wasActive) {
        cookies.setCookie(res, ACTIVE_SESSION_COOKIE_NAME, remaining[0], {
            maxAge: ttlHours() * 60 * 60 * 1000,
        });
    }
}

async function clearSessions(req, res) {
    const refs = req ? getSessionRefs(req) : {};
    const tokens = Object.values(refs).filter(Boolean).map(tokenHash);

    if (tokens.length) {
        const db = getDB();
        const placeholders = tokens.map(() => "?").join(",");
        await db.query(
            `UPDATE user_sessions SET revoked = 1 WHERE session_token IN (${placeholders})`,
            tokens
        );
    }

    clearSessionCookies(res);
}

module.exports = {
    getSessions,
    addSession,
    getActiveSession,
    getActiveUser,
    switchSession,
    clearSession,
    clearSessions,
};
