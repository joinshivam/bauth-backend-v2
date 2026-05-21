function requireGlobalAdmin(req, res, next) {
  const admins = [
    process.env.ADMIN_EMAILS,
    process.env.ADMIN_EMAIL,
    process.env.DEFAULT_ADMIN_EMAIL,
  ]
    .filter(Boolean)
    .flatMap((value) => String(value).split(","))
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  const userEmail = String(req.user?.email || "").toLowerCase();
  const username = String(req.user?.username || "").toLowerCase();

  if (!admins.length || (!admins.includes(userEmail) && !admins.includes(username))) {
    return res.status(403).send("Admin access required");
  }

  next();
}

module.exports = { requireGlobalAdmin };
