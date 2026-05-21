const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth.controller");
const auth = require("../middleware/auth.middleware");

// PUBLIC ROUTES
router.post("/signup", authController.register);
router.post("/signin", authController.login);
router.post("/username", authController.username_check);
router.get("/sessions",auth, authController.getSessionsC);

module.exports = router;
