const Env = require("../env");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const { corsTablesSQL } = require("./cors");

const createTablesSQL = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  username VARCHAR(100) UNIQUE NOT NULL,
  postfix VARCHAR(50) DEFAULT '@bauth.com',
  email VARCHAR(150) NOT NULL,
  phone VARCHAR(20),
  password VARCHAR(255) NOT NULL,
  dob VARCHAR(255),
  gender ENUM('male','female','other'),
  photo VARCHAR(255),
  email_verified TINYINT(1) DEFAULT 0,
  phone_verified TINYINT(1) DEFAULT 0,
  agreement TINYINT(1) DEFAULT 0,
  status ENUM('active','inactive','banned') DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_sessions (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  session_token CHAR(64) UNIQUE NOT NULL,
  user_agent VARCHAR(255),
  ip_address VARCHAR(45),
  expires_at TIMESTAMP,
  revoked TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS otp (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  otp_token VARCHAR(255) UNIQUE NOT NULL,
  otp VARCHAR(12),
  purpose ENUM('email','phone','2fa') DEFAULT 'phone',
  used TINYINT(1) DEFAULT 0,
  expires_at TIMESTAMP,
  issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_logs (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  action VARCHAR(100),
  description TEXT,
  ip_address VARCHAR(45),
  user_agent VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_preferences (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  theme ENUM('light','dark','system') DEFAULT 'system',
  language VARCHAR(10) DEFAULT 'en',
  timezone VARCHAR(50) DEFAULT 'UTC',
  two_factor_enabled TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS two_factor_auth (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  secret_key VARCHAR(255) NOT NULL,
  enabled TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS account_recovery (
  id SERIAL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  type ENUM('email','phone','backup_code'),
  value VARCHAR(255),
  verified TINYINT(1) DEFAULT 0,
  used TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_projects (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  owner_user_id BIGINT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_project_members (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  project_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  role ENUM('owner','admin','viewer') DEFAULT 'viewer',
  UNIQUE KEY uniq_project_user (project_id, user_id),
  FOREIGN KEY (project_id) REFERENCES idp_projects(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_registration_tokens (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  project_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) UNIQUE NOT NULL,
  label VARCHAR(120),
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES idp_projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_clients (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  project_id BIGINT UNSIGNED NULL,
  client_id VARCHAR(80) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255) NOT NULL,
  name VARCHAR(120) NOT NULL,
  trusted TINYINT(1) DEFAULT 1,
  first_party TINYINT(1) DEFAULT 0,
  client_type ENUM('account_center','first_party','third_party') DEFAULT 'first_party',
  client_uri VARCHAR(255) NOT NULL,
  backend_uri VARCHAR(255) NOT NULL,
  callback_uri VARCHAR(255) NOT NULL,
  status ENUM('active','inactive') DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES idp_projects(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_client_redirects (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  client_id VARCHAR(80) NOT NULL,
  redirect_uri VARCHAR(255) NOT NULL,
  UNIQUE KEY uniq_client_redirect (client_id, redirect_uri)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_sso_flows (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  flow_id CHAR(64) UNIQUE NOT NULL,
  client_id VARCHAR(80) NOT NULL,
  redirect_uri VARCHAR(255) NOT NULL,
  state VARCHAR(255),
  code_challenge VARCHAR(128),
  code_challenge_method ENUM('S256') DEFAULT 'S256',
  status ENUM('pending','approved','expired','cancelled') DEFAULT 'pending',
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS idp_auth_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code_hash CHAR(64) UNIQUE NOT NULL,
  flow_id CHAR(64) NOT NULL,
  client_id VARCHAR(80) NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  redirect_uri VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
`;

let pool;

function trimSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

async function columnExists(table, column) {
  const [rows] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [table, column]
  );

  return rows.length > 0;
}

async function ensureColumn(table, column, definition) {
  if (await columnExists(table, column)) return;
  await pool.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
async function ensureNullableColumn(table, column, definition) {
  const [rows] = await pool.query(
    `SELECT IS_NULLABLE
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [table, column]
  );

  if (!rows.length) {
    await ensureColumn(table, column, definition);
    return;
  }

  if (rows[0].IS_NULLABLE !== "YES") {
    await pool.query(`ALTER TABLE ${table} MODIFY COLUMN ${column} ${definition}`);
  }
}

async function runCompatibilityMigrations() {
  await ensureNullableColumn(
    "idp_projects",
    "owner_user_id",
    "BIGINT UNSIGNED NULL"
  );

  await ensureNullableColumn(
    "idp_clients",
    "project_id",
    "BIGINT UNSIGNED NULL"
  );

  await ensureColumn("idp_clients", "first_party", "TINYINT(1) DEFAULT 0");

  await ensureColumn(
    "idp_clients",
    "client_type",
    "ENUM('account_center','first_party','third_party') DEFAULT 'first_party'"
  );

  await ensureColumn(
    "idp_clients",
    "updated_at",
    "TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
  );

  await ensureColumn("idp_auth_codes", "flow_id", "CHAR(64) NULL");
  await ensureNullableColumn("idp_sso_flows", "state", "VARCHAR(255) NULL");
  await ensureNullableColumn("idp_sso_flows", "code_challenge", "VARCHAR(128) NULL");
}

async function seedAccountCenterClient() {
  const frontendBase = trimSlash(Env.IDP_FRONTEND_BASE_URL || "http://localhost:3000");
  const backendBase = trimSlash(Env.API_BASE_URL || "http://localhost:5000");
  const redirectUri = `${frontendBase}/myaccount`;

  await pool.query(
    `INSERT INTO idp_projects (id, name, owner_user_id)
     VALUES (1, 'BAuth Account Center', NULL)
     ON DUPLICATE KEY UPDATE name = VALUES(name)`
  );

  await pool.query(
    `INSERT INTO idp_clients
     (project_id, client_id, client_secret_hash, name, trusted, first_party, client_type, client_uri, backend_uri, callback_uri, status)
     VALUES (1, 'bauth_account_center', 'internal', 'Account Center', 1, 1, 'account_center', ?, ?, ?, 'active')
     ON DUPLICATE KEY UPDATE
       name = VALUES(name),
       trusted = 1,
       first_party = 1,
       client_type = 'account_center',
       client_uri = VALUES(client_uri),
       backend_uri = VALUES(backend_uri),
       callback_uri = VALUES(callback_uri),
       status = 'active'`,
    [frontendBase, backendBase, redirectUri]
  );

  await pool.query(
    `INSERT IGNORE INTO idp_client_redirects (client_id, redirect_uri)
     VALUES ('bauth_account_center', ?), ('bauth_account_center', ?)`,
    [redirectUri, `${frontendBase}/u`]
  );
}

async function seedAdminPanelClient() {
  const backendBase = trimSlash(Env.API_BASE_URL || "http://localhost:5000");
  const clientId = Env.ADMIN_PANEL_CLIENT_ID;
  const clientSecret = Env.ADMIN_PANEL_CLIENT_SECRET;
  const redirectUri = `${backendBase}/admin/callback`;
  const secretHash = await bcrypt.hash(clientSecret, 10);

  await pool.query(
    `INSERT INTO idp_clients
     (project_id, client_id, client_secret_hash, name, trusted, first_party, client_type, client_uri, backend_uri, callback_uri, status)
     VALUES (1, ?, ?, 'BAuth Admin Panel', 1, 1, 'first_party', ?, ?, ?, 'active')
     ON DUPLICATE KEY UPDATE
       client_secret_hash = VALUES(client_secret_hash),
       name = VALUES(name),
       trusted = 1,
       first_party = 1,
       client_type = 'first_party',
       client_uri = VALUES(client_uri),
       backend_uri = VALUES(backend_uri),
       callback_uri = VALUES(callback_uri),
       status = 'active'`,
    [clientId, secretHash, `${backendBase}/admin`, backendBase, redirectUri]
  );

  await pool.query(
    `INSERT IGNORE INTO idp_client_redirects (client_id, redirect_uri)
     VALUES (?, ?)`,
    [clientId, redirectUri]
  );
}

async function seedSampleChatClient() {
  const clientSecret = process.env.SAMPLE_CHAT_CLIENT_SECRET;
  if (!clientSecret) return;

  const clientId = process.env.SAMPLE_CHAT_CLIENT_ID || "bauth_sample_chat";
  const clientName = process.env.SAMPLE_CHAT_CLIENT_NAME || "BAuth Sample Chat";
  const clientBase = trimSlash(process.env.SAMPLE_CHAT_CLIENT_URL || "http://localhost:3001");
  const backendUri = trimSlash(process.env.SAMPLE_CHAT_BACKEND_URL || clientBase);
  const callbackUri = process.env.SAMPLE_CHAT_CALLBACK_URL || `${clientBase}/api/auth/callback`;
  const secretHash = await bcrypt.hash(clientSecret, 10);

  await pool.query(
    `INSERT INTO idp_clients
     (project_id, client_id, client_secret_hash, name, trusted, first_party, client_type, client_uri, backend_uri, callback_uri, status)
     VALUES (1, ?, ?, ?, 1, 1, 'first_party', ?, ?, ?, 'active')
     ON DUPLICATE KEY UPDATE
       client_secret_hash = VALUES(client_secret_hash),
       name = VALUES(name),
       trusted = 1,
       first_party = 1,
       client_type = 'first_party',
       client_uri = VALUES(client_uri),
       backend_uri = VALUES(backend_uri),
       callback_uri = VALUES(callback_uri),
       status = 'active'`,
    [clientId, secretHash, clientName, clientBase, backendUri, callbackUri]
  );

  await pool.query(
    `INSERT IGNORE INTO idp_client_redirects (client_id, redirect_uri)
     VALUES (?, ?)`,
    [clientId, callbackUri]
  );
}

function readCorsSeedOrigins() {
  const defaults = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5000",
  ];

  const configured = String(process.env.CORS_ORIGIN || "")
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .split(",")
    .map((origin) => origin.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);

  return [...new Set([
    ...defaults,
    Env.FRONTEND_URL,
    Env.IDP_FRONTEND_BASE_URL,
    process.env.SAMPLE_CHAT_CLIENT_URL,
    ...configured,
  ]
    .filter(Boolean)
    .map(trimSlash))];
}

async function seedCorsOrigins() {
  const origins = readCorsSeedOrigins();

  for (const origin of origins) {
    await pool.query(
      `INSERT IGNORE INTO cors_origins (label, origin, description, status, policy)
       VALUES (?, ?, 'Seeded from environment/default local development origins', 'online', 'allow')`,
      [origin.replace(/^https?:\/\//, ""), origin]
    );
  }
}

const connectDB = async () => {
  try {
    pool = mysql.createPool({
      host: Env.MYSQL_HOST,
      user: Env.MYSQL_USER,
      password: Env.MYSQL_PASSWORD,
      database: Env.MYSQL_DATABASE,
      port: Env.MYSQL_PORT || 3306,
      waitForConnections: true,
      connectionLimit: 20,
      multipleStatements: true,
      ssl: {
        rejectUnauthorized: true
      }
    });

    await pool.query("SELECT 1");
    await pool.query(createTablesSQL);
    await pool.query(corsTablesSQL);
    await runCompatibilityMigrations();
    await seedAccountCenterClient();
    await seedAdminPanelClient();
    await seedSampleChatClient();
    await seedCorsOrigins();

    console.log("MySQL connected, tables ready, Account Center, Admin Panel, and CORS origins seeded");
  } catch (err) {
    console.error("DB connection failed:", err.message);
    process.exit(1);
  }
};

const getDB = () => {
  if (!pool) throw new Error("DB not initialized");
  return pool;
};

module.exports = { connectDB, getDB };
