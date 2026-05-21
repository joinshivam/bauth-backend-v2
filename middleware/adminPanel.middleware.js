const Users = require("../models/users");
const Sessions = require("../utils/sessions");

function getAdminUrl(req, pathname = "/admin/login") {
  const protocol = req.protocol || "http";
  const host = req.get("host");
  return `${protocol}://${host}${pathname}`;
}

function redirectToAdminLogin(req, res) {
  const returnTo = `${req.protocol}://${req.get("host")}${req.originalUrl || "/admin"}`;
  const url = new URL(getAdminUrl(req));
  url.searchParams.set("returnTo", returnTo);
  return res.redirect(url.toString());
}

async function requireAdminPanelAuth(req, res, next) {
  try {
    const sessionUser = await Sessions.getActiveUser(req);
    const userId = sessionUser?.sub;

    if (!userId) {
      return redirectToAdminLogin(req, res);
    }

    const [rows] = await Users.findById(userId);

    if (!rows || rows.length === 0) {
      await Sessions.clearSession(req, res, Sessions.getActiveSession(req));
      return redirectToAdminLogin(req, res);
    }

    req.user = rows[0];
    req.session = sessionUser;
    req.sessionId = Sessions.getActiveSession(req);
    next();
  } catch (err) {
    return res.status(500).send("Unable to authenticate admin panel request");
  }
}

module.exports = { requireAdminPanelAuth };
