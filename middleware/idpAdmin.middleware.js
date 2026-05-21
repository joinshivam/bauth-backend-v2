// backend/middleware/idpAdmin.middleware.js

const { getDB } = require("../database/database");

async function requireProjectAdmin(req, res, next) {
  const projectId = req.params.projectId || req.body.projectId;

  if (!projectId) {
    return res.status(400).json({ success: false, message: "projectId required" });
  }

  const db = getDB();

  const [rows] = await db.query(
    `SELECT role FROM idp_project_members
     WHERE project_id = ? AND user_id = ? AND role IN ('owner','admin')
     LIMIT 1`,
    [projectId, req.user.id]
  );

  if (!rows.length) {
    return res.status(403).json({
      success: false,
      message: "Project admin access required",
    });
  }

  next();
}

module.exports = { requireProjectAdmin };