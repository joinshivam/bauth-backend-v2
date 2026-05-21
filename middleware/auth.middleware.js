const Users = require("../models/users");
const Sessions = require("../utils/sessions");

module.exports = async (req, res, next) => {
    try {
        const sessionUser = await Sessions.getActiveUser(req, res);
        if (!sessionUser) {
            await Sessions.clearSessions(req, res);
            return res.status(401).json({ ok: false, message: "Unauthorized access" });
        }
        const userId = sessionUser.sub;
        if (!userId) {
            await Sessions.clearSession(req, res, Sessions.getActiveSession(req));
            return res.status(401).json({ ok: false, success: false, message: "Invalid session" });
        }
        const [rows] = await Users.findById(userId);
        if (!rows || rows.length === 0) {
            await Sessions.clearSession(req, res, Sessions.getActiveSession(req));
            return res.status(401).json({ ok: false, success: false, message: "User not found" });
        }
        req.user = rows[0];
        req.session = sessionUser;
        req.sessionId = Sessions.getActiveSession(req);
        next();
    } catch (err) {
        return res.status(500).json({ ok: false, success: false, message: "Server error" });
    }
};
