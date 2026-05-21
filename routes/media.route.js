const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
const { AvatarSvg } = require("../utils/avtar")
const auth = require("../middleware/auth.middleware");
const Users = require("../models/users");
const Sessions = require("../utils/sessions")

router.get("/profile/:username", auth, async (req, res) => {
    try {
        const Username = req.params.username.toString().toLowerCase().trim();
        const sessions = await Sessions.getSessions(req);
        if (!sessions || sessions?.length === 0) {
            return res.status(403).json({ message: "401 Media Restricted" });
        }

        const [rows] = await Users.findByUsername(Username);
        if (!rows.length) {
            return res.status(403).json({ message: "401 Media Restricted" });
        }

        const user = rows[0];
        const isMatch = Object.values(sessions).some(u => u.username === user.username);
        if (!isMatch) {
            return res.status(403).json({ message: "403 Media Restricted forbidden" });
        }
        if (user.photo) {
            const filePath = path.join(__dirname, "../uploads/profile", path.basename(user.photo));

            if (fs.existsSync(filePath)) {
                return res.sendFile(filePath);
            }
        }

        const svg = AvatarSvg(user.name);
        res.setHeader("Content-Type", "image/svg+xml");
        return res.send(svg);


    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
});
router.get("/resources/:filename", auth, async (req, res) => {
    try {
        const requestedFile = path.basename(req.params.filename);
        const filePath = path.join(__dirname, "../uploads/resources", requestedFile);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ ok: false, message: "File not found" });
        }

        res.sendFile(filePath);

    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
});
router.get("/:filename", async (req, res) => {
    try {
        const requestedFile = path.basename(req.params.filename);

        const filePath = path.join(__dirname, "../uploads/public", requestedFile);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ ok: false, message: "File not found" });
        }

        res.sendFile(filePath);

    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
});

module.exports = router;
