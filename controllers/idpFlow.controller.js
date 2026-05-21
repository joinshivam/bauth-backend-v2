const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Env = require("../env");
const { getDB } = require("../database/database");
const Users = require("../models/users");

const ACCOUNT_CENTER_CLIENT_ID = "bauth_account_center";

function trimSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function randomId(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function hashHex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function s256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function positiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
    email: user.email,
    phone: user.phone,
    photo: user.photo,
    gender: user.gender,
    dob: user.dob,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

async function getClient(clientId) {
  const db = getDB();
  const [rows] = await db.query(
    `SELECT *
     FROM idp_clients
     WHERE client_id = ?
       AND status = 'active'
     LIMIT 1`,
    [clientId]
  );
  return rows[0] || null;
}

async function isAllowedRedirect(clientId, redirectUri) {
  const db = getDB();
  const [rows] = await db.query(
    `SELECT id
     FROM idp_client_redirects
     WHERE client_id = ?
       AND redirect_uri = ?
     LIMIT 1`,
    [clientId, redirectUri]
  );
  return rows.length > 0;
}

function accountCenterRedirectUri(value) {
  const frontendBase = trimSlash(Env.IDP_FRONTEND_BASE_URL || "http://localhost:3000");
  const fallback = `${frontendBase}/myaccount`;

  try {
    const url = new URL(value || fallback, frontendBase);
    const base = new URL(frontendBase);

    if (url.origin !== base.origin) return fallback;

    if (url.pathname === "/u") return fallback;
    if (url.pathname.startsWith("/u/")) {
      return `${frontendBase}/myaccount${url.pathname.slice(2)}${url.search}`;
    }

    if (url.pathname === "/myaccount" || url.pathname.startsWith("/myaccount/")) {
      return `${url.origin}${url.pathname}${url.search}`;
    }

    return fallback;
  } catch {
    return fallback;
  }
}

function isAccountCenterRedirect(client, redirectUri) {
  if (client?.client_type !== "account_center") return false;
  return accountCenterRedirectUri(redirectUri) === redirectUri;
}

async function createFlow({ clientId, redirectUri, state, codeChallenge, codeChallengeMethod }) {
  const client = await getClient(clientId);

  if (!client || !client.trusted) {
    const err = new Error("Invalid client");
    err.status = 400;
    throw err;
  }

  const allowed = isAccountCenterRedirect(client, redirectUri) || await isAllowedRedirect(clientId, redirectUri);
  if (!allowed) {
    const err = new Error("Invalid redirect_uri");
    err.status = 400;
    throw err;
  }

  if (client.client_type !== "account_center") {
    if (!state || !codeChallenge || codeChallengeMethod !== "S256") {
      const err = new Error("Missing SSO security parameters");
      err.status = 400;
      throw err;
    }
  }

  const flowId = randomId();
  const db = getDB();

  await db.query(
    `INSERT INTO idp_sso_flows
     (flow_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, 'S256', DATE_ADD(NOW(), INTERVAL ? MINUTE))`,
    [
      flowId,
      client.client_id,
      redirectUri,
      state || null,
      codeChallenge || null,
      positiveInt(Env.OAUTH_STATE_TTL_MINUTES, 5),
    ]
  );

  return {
    flowId,
    client: {
      client_id: client.client_id,
      name: client.name,
      client_type: client.client_type,
      first_party: !!client.first_party,
      client_uri: client.client_uri,
    },
  };
}

module.exports = {
  initAccountCenterFlow: async (req, res) => {
    try {
      const returnTo = req.body.returnTo || req.body.continue || req.query.returnTo || req.query.continue;

      const result = await createFlow({
        clientId: ACCOUNT_CENTER_CLIENT_ID,
        redirectUri: accountCenterRedirectUri(returnTo),
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      return res.status(err.status || 500).json({
        success: false,
        message: err.message || "Unable to start Account Center flow",
      });
    }
  },

  initExternalFlow: async (req, res) => {
    try {
      const result = await createFlow({
        clientId: req.body.client_id,
        redirectUri: req.body.redirect_uri,
        state: req.body.state,
        codeChallenge: req.body.code_challenge,
        codeChallengeMethod: req.body.code_challenge_method,
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      return res.status(err.status || 500).json({
        success: false,
        message: err.message || "Unable to start SSO flow",
      });
    }
  },

  getFlow: async (req, res) => {
    try {
      const db = getDB();

      const [rows] = await db.query(
        `SELECT
           f.flow_id,
           f.client_id,
           f.status,
           f.expires_at,
           c.name,
           c.client_type,
           c.first_party,
           c.client_uri
         FROM idp_sso_flows f
         JOIN idp_clients c ON c.client_id = f.client_id
         WHERE f.flow_id = ?
           AND f.status = 'pending'
           AND f.expires_at > NOW()
         LIMIT 1`,
        [req.params.flowId]
      );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message: "Invalid or expired flow",
        });
      }

      return res.json({
        success: true,
        flow: rows[0],
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Unable to load flow",
      });
    }
  },

  approveFlow: async (req, res) => {
    try {
      const db = getDB();

      const [rows] = await db.query(
        `SELECT f.*, c.client_type
         FROM idp_sso_flows f
         JOIN idp_clients c ON c.client_id = f.client_id
         WHERE f.flow_id = ?
           AND f.status = 'pending'
           AND f.expires_at > NOW()
         LIMIT 1`,
        [req.params.flowId]
      );

      if (!rows.length) {
        return res.status(400).json({
          success: false,
          message: "Invalid or expired flow",
        });
      }

      const flow = rows[0];

      await db.query(
        "UPDATE idp_sso_flows SET status = 'approved' WHERE id = ?",
        [flow.id]
      );

      if (flow.client_type === "account_center") {
        return res.json({
          success: true,
          redirectTo: flow.redirect_uri,
        });
      }

      const code = randomId();

      await db.query(
        `INSERT INTO idp_auth_codes
         (code_hash, flow_id, client_id, user_id, redirect_uri, expires_at)
         VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
        [
          hashHex(code),
          flow.flow_id,
          flow.client_id,
          req.user.id,
          flow.redirect_uri,
          positiveInt(Env.AUTH_CODE_TTL_SECONDS, 120),
        ]
      );

      const redirectTo = new URL(flow.redirect_uri);
      redirectTo.searchParams.set("code", code);
      if (flow.state) redirectTo.searchParams.set("state", flow.state);

      return res.json({
        success: true,
        redirectTo: redirectTo.toString(),
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Unable to approve flow",
      });
    }
  },

  token: async (req, res) => {
    try {
      const { client_id, client_secret, code, redirect_uri, code_verifier } = req.body;

      const client = await getClient(client_id);
      if (!client || client.client_type === "account_center") {
        return res.status(401).json({
          success: false,
          message: "Invalid client",
        });
      }

      const secretOk = await bcrypt.compare(client_secret || "", client.client_secret_hash);
      if (!secretOk) {
        return res.status(401).json({
          success: false,
          message: "Invalid client secret",
        });
      }

      const db = getDB();

      const [codes] = await db.query(
        `SELECT c.*, f.code_challenge
         FROM idp_auth_codes c
         JOIN idp_sso_flows f ON f.flow_id = c.flow_id
         WHERE c.code_hash = ?
           AND c.client_id = ?
           AND c.redirect_uri = ?
           AND c.used_at IS NULL
           AND c.expires_at > NOW()
         LIMIT 1`,
        [hashHex(code || ""), client_id, redirect_uri]
      );

      if (!codes.length) {
        return res.status(400).json({
          success: false,
          message: "Invalid or expired code",
        });
      }

      const authCode = codes[0];

      if (!code_verifier || s256(code_verifier) !== authCode.code_challenge) {
        return res.status(400).json({
          success: false,
          message: "Invalid PKCE verifier",
        });
      }

      await db.query("UPDATE idp_auth_codes SET used_at = NOW() WHERE id = ?", [authCode.id]);

      const [userRows] = await Users.findById(authCode.user_id);
      if (!userRows.length) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const user = userRows[0];

      const accessToken = jwt.sign(
        {
          iss: Env.IDP_ISSUER,
          aud: client_id,
          sub: String(user.id),
          username: user.username,
        },
        Env.IDP_ACCESS_TOKEN_SECRET,
        { expiresIn: positiveInt(Env.ACCESS_TOKEN_TTL_SECONDS, 900) }
      );

      return res.json({
        success: true,
        token_type: "Bearer",
        access_token: accessToken,
        expires_in: positiveInt(Env.ACCESS_TOKEN_TTL_SECONDS, 900),
        user: safeUser(user),
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Token exchange failed",
      });
    }
  },
};
