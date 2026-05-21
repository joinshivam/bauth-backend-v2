const crypto = require("crypto");
const { getDB } = require("../database/database");

function createRawToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function createEmailVerification(userId) {
  const token = createRawToken();
  const tokenHash = hashToken(token);
  const db = getDB();

  await db.query(
    `INSERT INTO email_verifications (user_id, token_hash, expires_at)
     VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE))`,
    [userId, tokenHash]
  );

  return token;
}

async function verifyEmailToken(token) {
  const tokenHash = hashToken(token);
  const db = getDB();

  const [rows] = await db.query(
    `SELECT * FROM email_verifications
     WHERE token_hash = ?
       AND used = 0
       AND expires_at > NOW()
     LIMIT 1`,
    [tokenHash]
  );

  if (!rows.length) {
    return { success: false, message: "Invalid or expired verification link" };
  }

  const record = rows[0];

  await db.query("UPDATE users SET email_verified = 1, status = 'active' WHERE id = ?", [
    record.user_id,
  ]);

  await db.query("UPDATE email_verifications SET used = 1 WHERE id = ?", [
    record.id,
  ]);

  return { success: true, message: "Email verified successfully" };
}

module.exports = {
  createEmailVerification,
  verifyEmailToken,
};