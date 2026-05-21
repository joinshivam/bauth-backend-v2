const Users = require("../models/users");
const bcrypt = require("bcryptjs");
const UAParser = require('ua-parser-js');
const { getDB } = require("../database/database");
const path = require("path");
const Sessions = require("../utils/sessions");
const { sendVerificationEmail } = require("../utils/mailer");
const { createEmailVerification, verifyEmailToken, } = require("../utils/emailVerification");
module.exports = {
    register: async (req, res) => {
        try {
            let { name, dob, gender, username, password, aggrement } = req.body;
            const parser = new UAParser(req.headers['user-agent']);
            const deviceInfo = parser.getResult();
            const USER_AGENT = `${deviceInfo.browser.name}-${deviceInfo.os.name}-${deviceInfo.device.type || 'desktop'}-req:${req.headers['user-agent']}`;
            const USER_IP =
                req.headers['x-forwarded-for']?.split(',')[0] ||
                req.socket.remoteAddress;
            ;
            const ValidName = Users.validateName(name);
            const ValidDob = Users.validateDob(dob);
            const ValidGender = Users.validateGender(gender);
            const ValidUsername = Users.validateUsername(username);
            const ValidPassword = Users.validatePassword(password);

            if (aggrement === false) return res.status(400).json({ success: false, message: `Please accept agreement to continue.`, field: "aggrement" });

            const db = getDB();
            const postfix = `@${process.env.DOMAIN || "onemb.com"}`
            const [exists] = await Users.findByUsername(ValidUsername);

            if (exists.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: "Username already Taken!",
                    field: "username"
                });
            }
            const email = ValidUsername + postfix;
            const hashedPassword = await bcrypt.hash(ValidPassword, 10);

            const [Result] = await db.query(
                `INSERT INTO users (name,dob,gender, username,email,postfix, password , agreement) 
                 VALUES (?, ?, ?, ? , ? , ? , ?, ?)`,
                [ValidName, ValidDob, ValidGender, ValidUsername, email, postfix, hashedPassword, aggrement ? 1 : 0]
            );
            const userId = Result.insertId;
            const [userRows] = await Users.findById(userId);
            const user = userRows[0];
            const Email = user?.email

            const sessionId = await Sessions.addSession(req, res, { sub: user.id, username: user.username, email: user.email, name: user.name, profilePhoto: user.photo, user_agent: USER_AGENT, ip: USER_IP });
            return res.json({
                success: true,
                sessionId: sessionId,
                message: "Signup Successful!",
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    username: user?.username,
                    phone: user.phone,
                    phone_verify: user.phone_verified,
                    photo: user.photo,
                    gender: user.gender,
                    dob: user.dob,
                    created_at: user.created_at,
                    updated_at: user.updated_at
                }
            });
        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "Global",
                message: `Signup Error :${err?.message || "Unknown Type Error"}`
            });
        }
    },
    login: async (req, res) => {
        try {
            let { username, password } = req.body;
            const parser = new UAParser(req.headers['user-agent']);
            const deviceInfo = parser.getResult();
            const USER_AGENT = `${deviceInfo.browser.name}-${deviceInfo.os.name}-${deviceInfo.device.type || 'desktop'}-req:${req.headers['user-agent']}`;
            const USER_IP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
            username = username.trim().toLowerCase();
            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: !username ? "Invalid Username." : "Enter Password to Login"
                });
            }

            const [rows] = await Users.findByUsername(username?.toLowerCase().trim());

            if (!rows || rows.length === 0) return res.status(400).json({ field: "username", success: false, message: "Users not found" });

            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (!match) return res.status(400).json({ field: "password", success: false, message: "Incorrect password" });

            const sessionId = await Sessions.addSession(req, res, { sub: user.id, username: user.username, email: user.email, name: user.name, profilePhoto: user.photo, user_agent: USER_AGENT, ip: USER_IP });
            return res.json({
                success: true,
                sessionId: sessionId,
                message: "Login Successful!",
                user: {
                    id: user?.id,
                    name: user?.name,
                    email: user?.email,
                    username: user?.username,
                    phone: user?.phone,
                    photo: user?.photo,
                    gender: user?.gender,
                    dob: user?.dob,
                    verified: user?.phone_verified,
                    created_at: user?.created_at,
                    updated_at: user?.updated_at
                }
            });

        } catch (err) {
            return res.status(500).json({ message: err?.message || "Login Failed! Internal Server Error.", success: false, });
        }
    },
    username_check: async (req, res) => {
        try {
            let { username } = req.body
            username = username.trim().toLowerCase();

            const usernameRegex = /^[a-z0-9]+(\.[a-z0-9]+)*$/;
            if (!usernameRegex.test(username)) {
                return res.status(400).json({
                    success: false,
                    available: false,
                    message: "Invalid username.",
                    field: "username"
                });
            }
            if (!username) {
                return res.json({ success: false, available: false, message: "enter any input." });
            }

            const [rows] = await Users.findByUsername(username);

            if (rows.length > 0) {
                return res.json({
                    success: false,
                    available: false,
                    message: "username not available."
                });
            }
            return res.json({
                success: true,
                available: true,
                message: "Username is available"
            });
        } catch (err) {
            return res.json({
                success: false,
                available: false,
                message: "unabale to check username! Internal Server Error."
            })
        }
    },
    getSessionsC: async (req, res) => {
        try {
            const sessions = await Sessions.getSessions(req);
            return res.json({
                success: true,
                active: Sessions.getActiveSession(req),
                total: Object.keys(sessions).length,
                sessions
            });

        } catch (err) {
            return res.status(500).json({
                success: false,
                message: "Failed to fetch sessions"
            });
        }
    },

};
