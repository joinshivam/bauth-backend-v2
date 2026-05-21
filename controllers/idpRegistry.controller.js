const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { getDB } = require("../database/database");

const hash = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const random = (bytes = 32) => crypto.randomBytes(bytes).toString("hex");

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
}

function safeClient(client) {
  if (!client) return null;
  const { client_secret_hash, ...safe } = client;
  return safe;
}

async function getServiceClient(req) {
  const clientId = req.headers["x-client-id"] || req.body?.client_id || req.query?.client_id;
  const clientSecret = req.headers["x-client-secret"] || req.body?.client_secret;

  if (!clientId || !clientSecret) {
    const err = new Error("x-client-id and x-client-secret are required");
    err.status = 401;
    throw err;
  }

  const db = getDB();
  const [rows] = await db.query(
    `SELECT *
     FROM idp_clients
     WHERE client_id = ?
       AND status IN ('active','inactive')
     LIMIT 1`,
    [clientId]
  );

  const client = rows[0];

  if (!client || client.client_type === "account_center") {
    const err = new Error("Invalid service client");
    err.status = 401;
    throw err;
  }

  const ok = await bcrypt.compare(String(clientSecret), client.client_secret_hash);
  if (!ok) {
    const err = new Error("Invalid service client secret");
    err.status = 401;
    throw err;
  }

  return client;
}

module.exports = {
  createProject: async (req, res) => {
    try {
      const name = req.body.name?.trim();

      if (!name) {
        return res.status(400).json({
          success: false,
          message: "Project name is required",
        });
      }

      const db = getDB();

      const [result] = await db.query(
        "INSERT INTO idp_projects (name, owner_user_id) VALUES (?, ?)",
        [name, req.user.id]
      );

      await db.query(
        "INSERT INTO idp_project_members (project_id, user_id, role) VALUES (?, ?, 'owner')",
        [result.insertId, req.user.id]
      );

      return res.json({
        success: true,
        projectId: result.insertId,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Unable to create project",
      });
    }
  },

  createRegistrationToken: async (req, res) => {
    try {
      const db = getDB();
      const token = `reg_${random(32)}`;

      await db.query(
        `INSERT INTO idp_registration_tokens
         (project_id, token_hash, label, expires_at)
         VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
        [req.params.projectId, hash(token), req.body.label || null]
      );

      return res.json({
        success: true,
        registrationToken: token,
        message: "Save this token now. It will not be shown again.",
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Unable to create registration token",
      });
    }
  },

  registerService: async (req, res) => {
    try {
      const {
        registrationToken,
        name,
        clientUri,
        backendUri,
        callbackUri,
      } = req.body;

      if (!registrationToken || !name || !clientUri || !backendUri || !callbackUri) {
        return res.status(400).json({
          success: false,
          message: "registrationToken, name, clientUri, backendUri and callbackUri are required",
        });
      }

      if (![clientUri, backendUri, callbackUri].every(isValidUrl)) {
        return res.status(400).json({
          success: false,
          message: "clientUri, backendUri and callbackUri must be valid URLs",
        });
      }

      const db = getDB();

      const [tokens] = await db.query(
        `SELECT *
         FROM idp_registration_tokens
         WHERE token_hash = ?
           AND used_at IS NULL
           AND expires_at > NOW()
         LIMIT 1`,
        [hash(registrationToken)]
      );

      if (!tokens.length) {
        return res.status(403).json({
          success: false,
          message: "Invalid or expired registration token",
        });
      }

      const reg = tokens[0];
      const clientId = `bauth_${random(10)}`;
      const clientSecret = `bs_${random(32)}`;
      const clientSecretHash = await bcrypt.hash(clientSecret, 10);

      await db.query(
        `INSERT INTO idp_clients
         (project_id, client_id, client_secret_hash, name, trusted, first_party, client_type, client_uri, backend_uri, callback_uri, status)
         VALUES (?, ?, ?, ?, 1, 1, 'first_party', ?, ?, ?, 'active')`,
        [
          reg.project_id,
          clientId,
          clientSecretHash,
          name.trim(),
          clientUri,
          backendUri,
          callbackUri,
        ]
      );

      await db.query(
        "INSERT INTO idp_client_redirects (client_id, redirect_uri) VALUES (?, ?)",
        [clientId, callbackUri]
      );

      await db.query(
        "UPDATE idp_registration_tokens SET used_at = NOW() WHERE id = ?",
        [reg.id]
      );

      return res.json({
        success: true,
        clientId,
        clientSecret,
        callbackUri,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: err.message || "Unable to register service",
      });
    }
  },

  serviceDetails: async (req, res) => {
    try {
      const client = await getServiceClient(req);
      const db = getDB();

      const [redirects] = await db.query(
        `SELECT redirect_uri
         FROM idp_client_redirects
         WHERE client_id = ?
         ORDER BY id DESC`,
        [client.client_id]
      );

      const [[stats]] = await db.query(
        `SELECT
           (SELECT COUNT(*) FROM idp_sso_flows WHERE client_id = ?) AS total_flows,
           (SELECT COUNT(*) FROM idp_sso_flows WHERE client_id = ? AND status = 'approved') AS approved_flows,
           (SELECT COUNT(*) FROM idp_auth_codes WHERE client_id = ? AND used_at IS NOT NULL) AS exchanged_codes`,
        [client.client_id, client.client_id, client.client_id]
      );

      return res.json({
        success: true,
        service: {
          ...safeClient(client),
          redirects: redirects.map((row) => row.redirect_uri),
          stats,
        },
      });
    } catch (err) {
      return res.status(err.status || 500).json({
        success: false,
        message: err.message || "Unable to load service details",
      });
    }
  },

  updateServiceDetails: async (req, res) => {
    try {
      const client = await getServiceClient(req);
      const db = getDB();

      const name = req.body.name?.trim() || client.name;
      const clientUri = req.body.clientUri?.trim() || req.body.client_uri?.trim() || client.client_uri;
      const backendUri = req.body.backendUri?.trim() || req.body.backend_uri?.trim() || client.backend_uri;
      const callbackUri = req.body.callbackUri?.trim() || req.body.callback_uri?.trim() || client.callback_uri;

      if (![clientUri, backendUri, callbackUri].every(isValidUrl)) {
        return res.status(400).json({
          success: false,
          message: "clientUri, backendUri and callbackUri must be valid URLs",
        });
      }

      await db.query(
        `UPDATE idp_clients
         SET name = ?, client_uri = ?, backend_uri = ?, callback_uri = ?
         WHERE client_id = ?`,
        [name, clientUri, backendUri, callbackUri, client.client_id]
      );

      await db.query("DELETE FROM idp_client_redirects WHERE client_id = ?", [client.client_id]);
      await db.query(
        "INSERT INTO idp_client_redirects (client_id, redirect_uri) VALUES (?, ?)",
        [client.client_id, callbackUri]
      );

      return res.json({
        success: true,
        message: "Service details updated",
        service: {
          ...safeClient({
            ...client,
            name,
            client_uri: clientUri,
            backend_uri: backendUri,
            callback_uri: callbackUri,
          }),
          redirects: [callbackUri],
        },
      });
    } catch (err) {
      return res.status(err.status || 500).json({
        success: false,
        message: err.message || "Unable to update service details",
      });
    }
  },
};
