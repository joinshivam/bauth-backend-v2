const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Env = require("../env");
const { getDB } = require("../database/database");
const Sessions = require("../utils/sessions");
const cookies = require("../utils/cookies");

function random(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function trimSlash(value) {
    return String(value || "").replace(/\/+$/, "");
}

function base64url(buffer) {
    return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256(value) {
    return base64url(crypto.createHash("sha256").update(value).digest());
}

function getAdminClientConfig() {
    const backendBase = trimSlash(Env.API_BASE_URL || "http://localhost:5000");

    return {
        frontendBase: trimSlash(Env.IDP_FRONTEND_BASE_URL || "http://localhost:3000"),
        backendBase,
        clientId: Env.ADMIN_PANEL_CLIENT_ID,
        clientSecret: Env.ADMIN_PANEL_CLIENT_SECRET,
        callbackUri: `${backendBase}/admin/callback`,
    };
}

function isValidUrl(value) {
    try {
        const url = new URL(value);
        return ["http:", "https:"].includes(url.protocol);
    } catch {
        return false;
    }
}

function safeAdminReturnTo(value) {
    const { backendBase } = getAdminClientConfig();

    try {
        const fallback = `${backendBase}/admin`;
        const url = new URL(value || fallback);
        const backend = new URL(backendBase);

        if (url.origin !== backend.origin || !url.pathname.startsWith("/admin")) {
            return fallback;
        }

        if (url.pathname === "/admin/login" || url.pathname === "/admin/callback") {
            return fallback;
        }

        return url.toString();
    } catch {
        return `${backendBase}/admin`;
    }
}

function setShortCookie(res, name, value) {
    cookies.setCookie(res, name, value, { maxAge: 5 * 60 * 1000 });
}

function clearAdminSsoCookies(res) {
    cookies.clearCookie(res, "admin_sso_state");
    cookies.clearCookie(res, "admin_sso_verifier");
    cookies.clearCookie(res, "admin_return_to");
}

function serviceType(value) {
    return value === "third_party" ? "third_party" : "first_party";
}

module.exports = {
    login: async (req, res) => {
        const { frontendBase, clientId, callbackUri } = getAdminClientConfig();
        const state = random(24);
        const codeVerifier = random(32);
        const codeChallenge = sha256(codeVerifier);
        const returnTo = safeAdminReturnTo(req.query.returnTo);

        setShortCookie(res, "admin_sso_state", state);
        setShortCookie(res, "admin_sso_verifier", codeVerifier);
        setShortCookie(res, "admin_return_to", returnTo);

        const url = new URL(`${frontendBase}/sso/select`);
        url.searchParams.set("client_id", clientId);
        url.searchParams.set("redirect_uri", callbackUri);
        url.searchParams.set("state", state);
        url.searchParams.set("code_challenge", codeChallenge);
        url.searchParams.set("code_challenge_method", "S256");
        url.searchParams.set("reqType", "auth");

        return res.redirect(url.toString());
    },

    callback: async (req, res) => {
        try {
            const { backendBase, clientId, clientSecret, callbackUri } = getAdminClientConfig();
            const { code, state } = req.query;
            const expectedState = cookies.getCookie(req, "admin_sso_state");
            const codeVerifier = cookies.getCookie(req, "admin_sso_verifier");
            const returnTo = safeAdminReturnTo(cookies.getCookie(req, "admin_return_to"));

            if (!code || !state || state !== expectedState || !codeVerifier) {
                clearAdminSsoCookies(res);
                return res.status(400).send("Invalid or expired admin login request");
            }

            const tokenRes = await fetch(`${backendBase}/api/idp/token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code,
                    redirect_uri: callbackUri,
                    code_verifier: codeVerifier,
                }),
            });

            const data = await tokenRes.json();

            if (!tokenRes.ok || !data.success || !data.user) {
                clearAdminSsoCookies(res);
                return res.status(401).send(data.message || "Admin login failed");
            }

            const user = data.user;
            const userAgent = req.headers["user-agent"] || "";
            const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

            await Sessions.addSession(req, res, {
                sub: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                profilePhoto: user.photo,
                user_agent: userAgent,
                ip: userIp,
            });

            clearAdminSsoCookies(res);
            return res.redirect(returnTo);
        } catch (err) {
            clearAdminSsoCookies(res);
            return res.status(500).send(err.message || "Admin callback failed");
        }
    },

    dashboard: async (req, res) => {
        const db = getDB();

        const [[stats]] = await db.query(`
      SELECT
        (SELECT COUNT(*) FROM idp_clients) AS services,
        (SELECT COUNT(*) FROM idp_clients WHERE status = 'active') AS active_services,
        (SELECT COUNT(*) FROM idp_clients WHERE status = 'inactive') AS inactive_services,
        (SELECT COUNT(*) FROM cors_origins) AS cors_origins,
        (SELECT COUNT(*) FROM cors_origins WHERE status = 'online' AND policy = 'allow') AS cors_allowed_online,
        (SELECT COUNT(*) FROM cors_origins WHERE policy = 'block') AS cors_blocked,
        (SELECT COUNT(*) FROM cors_origins WHERE status = 'offline') AS cors_offline,
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM users WHERE status = 'active') AS active_users,
        (SELECT COUNT(*) FROM idp_sso_flows) AS flows,
        (SELECT COUNT(*) FROM idp_sso_flows WHERE status = 'pending' AND expires_at > NOW()) AS pending_flows,
        (SELECT COUNT(*) FROM idp_sso_flows WHERE status = 'approved') AS approved_flows,
        (SELECT COUNT(*) FROM idp_sso_flows WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS flows_24h,
        (SELECT COUNT(*) FROM idp_auth_codes WHERE used_at IS NOT NULL) AS exchanged_codes
    `);

        const [recentServices] = await db.query(`
      SELECT id, name, client_id, client_type, client_uri, callback_uri, status, created_at, updated_at
      FROM idp_clients
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 6
    `);

        const [recentFlows] = await db.query(`
      SELECT f.flow_id, f.client_id, f.status, f.redirect_uri, f.created_at, f.expires_at, c.name AS service_name
      FROM idp_sso_flows f
      JOIN idp_clients c ON c.client_id = f.client_id
      ORDER BY f.created_at DESC
        LIMIT 8
    `);

        const [recentCorsOrigins] = await db.query(`
      SELECT id, label, origin, status, policy, updated_at
      FROM cors_origins
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 6
    `);

        res.render("admin/dashboard", {
            user: req.user,
            stats,
            recentServices,
            recentFlows,
            recentCorsOrigins,
        });
    },
    services: async (req, res) => {
        const db = getDB();

        const [services] = await db.query(`
      SELECT *
      FROM idp_clients
      ORDER BY created_at DESC
    `);

        res.render("admin/services", {
            user: req.user,
            services,
        });
    },
    createService: async (req, res) => {
        const db = getDB();

        const { name, client_uri, backend_uri, callback_uri, client_type } = req.body;

        try {
            for (const value of [name, client_uri, backend_uri, callback_uri]) {
                if (!value || !String(value).trim()) {
                    return res.status(400).send("All fields are required");
                }
            }

            if (![client_uri, backend_uri, callback_uri].every(isValidUrl)) {
                return res.status(400).send("Only valid http/https URLs are allowed");
            }

            const clientId = `bauth_${random(10)}`;
            const clientSecret = `bs_${random(32)}`;
            const secretHash = await bcrypt.hash(clientSecret, 10);
            const type = serviceType(client_type);

            await db.query(
                `INSERT INTO idp_clients
       (client_id, client_secret_hash, name, trusted, first_party, client_type, client_uri, backend_uri, callback_uri, status)
       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 'active')`,
                [
                    clientId,
                    secretHash,
                    name.trim(),
                    type === "first_party" ? 1 : 0,
                    type,
                    client_uri.trim(),
                    backend_uri.trim(),
                    callback_uri.trim(),
                ]
            );

            await db.query(
                `INSERT INTO idp_client_redirects (client_id, redirect_uri)
       VALUES (?, ?)`,
                [clientId, callback_uri.trim()]
            );

            res.render("admin/service-created", {
                clientId,
                clientSecret,
                callbackUri: callback_uri.trim(),
            });
        } catch (err) {
            res.status(400).send(err.message || "Unable to create service");
        }
    },
    createPage: async (req, res) => {
        res.render("admin/service-create", {
            user: req.user,
        });
    },
    detailPage: async (req, res) => {
        const db = getDB();

        const [rows] = await db.query(
            `SELECT * FROM idp_clients WHERE id = ? LIMIT 1`,
            [req.params.id]
        );

        if (!rows.length) {
            return res.redirect("/admin/services");
        }

        const service = rows[0];
        const [redirects] = await db.query(
            `SELECT id, redirect_uri
             FROM idp_client_redirects
             WHERE client_id = ?
             ORDER BY id DESC`,
            [service.client_id]
        );

        const [flows] = await db.query(
            `SELECT flow_id, status, redirect_uri, created_at, expires_at
             FROM idp_sso_flows
             WHERE client_id = ?
             ORDER BY created_at DESC
             LIMIT 10`,
            [service.client_id]
        );

        res.render("admin/service-detail", {
            user: req.user,
            service,
            redirects,
            flows,
        });
    },
    editPage: async (req, res) => {
        const db = getDB();

        const [rows] = await db.query(
            `SELECT * FROM idp_clients WHERE id = ? LIMIT 1`,
            [req.params.id]
        );

        if (!rows.length) {
            return res.redirect("/admin/services");
        }

        res.render("admin/service-edit", {
            user: req.user,
            service: rows[0],
        });
    },
    updateService: async (req, res) => {
        const db = getDB();

        if (![req.body.client_uri, req.body.backend_uri, req.body.callback_uri].every(isValidUrl)) {
            return res.status(400).send("Only valid http/https URLs are allowed");
        }

        const [rows] = await db.query(
            `SELECT client_id FROM idp_clients WHERE id = ? LIMIT 1`,
            [req.params.id]
        );

        if (!rows.length) {
            return res.redirect("/admin/services");
        }

        const clientId = rows[0].client_id;

        await db.query(
            `UPDATE idp_clients
       SET
         name = ?,
         client_uri = ?,
         backend_uri = ?,
         callback_uri = ?,
         client_type = ?,
         first_party = ?,
         status = ?
       WHERE id = ?`,
            [
                req.body.name.trim(),
                req.body.client_uri.trim(),
                req.body.backend_uri.trim(),
                req.body.callback_uri.trim(),
                serviceType(req.body.client_type),
                serviceType(req.body.client_type) === "first_party" ? 1 : 0,
                req.body.status,
                req.params.id,
            ]
        );

        await db.query("DELETE FROM idp_client_redirects WHERE client_id = ?", [clientId]);
        await db.query(
            "INSERT INTO idp_client_redirects (client_id, redirect_uri) VALUES (?, ?)",
            [clientId, req.body.callback_uri.trim()]
        );

        res.redirect(`/admin/services/${req.params.id}`);
    },
};
