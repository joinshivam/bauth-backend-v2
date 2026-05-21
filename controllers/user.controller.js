const Users = require("../models/users");
const bcrypt = require("bcryptjs");
const UAParser = require('ua-parser-js');
const { getDB } = require("../database/database");
const { replacePhoto } = require("../utils/avtar");
const path = require("path");
const Sessions = require("../utils/sessions");

module.exports = {
    getMe: async (req, res) => {
        try {
            const UsersId = req.user.id;
            const [rows] = await Users.findById(UsersId);
            if (!rows || rows.length === 0) {
                return res.status(404).json({ success: false, message: "Session Invalid" });
            }
            const sessionId = Sessions.getActiveSession(req);
            const user = rows[0];
            if (user.id !== req.user.id) {
                return res.status(403).json({ success: false, message: "Forbidden" });
            }
            return res.json({
                success: true,
                sessionId: sessionId,
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
            res.status(500).json({ success: false, message: err.message });
        }

    },
    getByUsername: async (req, res) => {
        try {
            const Username = req.params.username || null;
            const [rows] = await Users.findByUsername(Username);
            if (!rows || rows.length === 0) {
                return res.status(404).json({ success: false, message: "Session Invalid" });
            }
            const sessionId = Sessions.getActiveSession(req);
            const user = rows[0];
            return res.json({
                success: true,
                sessionId: sessionId,
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
            res.status(500).json({ success: false, message: err.message });
        }

    },
    logout: async (req, res) => {
        try {
            const activeSession = Sessions.getActiveSession(req);
            if (!activeSession) {
                return res.json({ success: false, message: "No active session" });
            }
            await Sessions.clearSession(req, res, activeSession);

            return res.json({
                success: true,
                message: "Logged out"
            });
        } catch (err) {
            return res.status(500).json({
                success: false,
                message: err.message
            });
        }
    },
    logoutAll: async (req, res) => {
        try {
            await Sessions.clearSessions(req, res);

            return res.json({
                success: true,
                message: "Logged out from all accounts"
            });

        } catch (err) {

            return res.status(500).json({
                success: false,
                message: err.message
            });
        }
    },
    switchAccount: async (req, res) => {
        try {
            const sessionId = req.body.sessionId || req.body.accountId;
            const switched = await Sessions.switchSession(req, res, sessionId);

            if (!switched) {
                return res.status(404).json({
                    success: false,
                    message: "Session not found"
                });
            }
            return res.json({
                success: true,
                activeSession: sessionId
            });
        } catch (err) {
            return res.status(500).json({
                success: false,
                message: err.message
            });
        }
    },
    removeAccount: async (req, res) => {
        try {
            const sessionId = req.body.sessionId || req.body.accountId;
            await Sessions.clearSession(req, res, sessionId);
            return res.json({
                success: true,
                message: "Account removed"
            });

        } catch (err) {

            return res.status(500).json({
                success: false,
                message: err.message
            });
        }
    },


    //---------- CUrd - u
    updateName: async (req, res) => {
        try {
            const id = req.user.id;
            const { name } = req.body;

            await Users.updateName(id, name);
            return res.json({ success: true, message: "Name updated" });

        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "name",
                message: err?.message || "Invalid Name"
            });
        }
    },
    updateDOB: async (req, res) => {
        try {
            const id = req.user.id;
            const { dob } = req.body;

            await Users.updateDOB(id, dob);
            return res.json({ success: true, message: "DOB updated" });

        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "dob",
                message: err?.message || "Invalid DOB"
            });
        }
    },
    updateGender: async (req, res) => {
        try {
            const id = req.user.id;
            const { gender } = req.body;

            await Users.updateGender(id, gender);
            return res.json({ success: true, message: "Gender updated" });

        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "gender",
                message: err?.message || "Invalid Gender"
            });
        }
    },
    updatePhone: async (req, res) => {
        try {
            const id = req.user.id;
            const { phone } = req.body;

            await Users.updatePhone(id, phone);
            return res.json({ success: true, message: "Phone updated" });

        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "phone",
                message: err?.message || "Invalid Phone"
            });
        }
    },
    updateUsername: async (req, res) => {
        const id = req.user.id;
        const { username } = req.body;

        try {
            await Users.updateUsername(id, username);
            return res.json({ success: true, message: "Username updated" });
        } catch (err) {
            return res.status(err.status || 400).json({
                success: false,
                field: err?.field || "username",
                message: err?.message || "Invalid Username"
            });
        }
    },
    updatePassword: async (req, res) => {
        try {
            const id = req.user.id;
            const { oldPassword, newPassword } = req.body;

            const [rows] = await Users.findById(id);
            if (rows.length === 0) return res.json({ success: false, message: "Invalid user" });

            const user = rows[0];
            const match = await bcrypt.compare(oldPassword, user.password);

            if (!match) return res.json({ success: false, message: "Old password incorrect" });
            const ValidPassword = Users.validatePassword(newPassword);
            const hashed = await bcrypt.hash(ValidPassword, 10);

            await Users.updatePassword(id, hashed);

            return res.json({ success: true, message: "Password updated" });
        } catch (err) {
            return res.status(500).json({ success: false, message: err.message });
        }
    },
    updatePhoto: async (req, res) => {
        try {
            const id = req.user.id;

            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    message: "No file uploaded"
                });
            }

            const filename = req.file;

            const result = await replacePhoto(id, filename);

            return res.json({
                success: true,
                message: "Photo updated",
                profilePhoto: result?.photo,
                updated_at: result?.updated_at
            });

        } catch (err) {
            return res.status(500).json({
                success: false,
                message: err.message
            });
        }
    },
    delete: async (req, res) => {
        const userId = req.user.id;

        try {
            const [rows] = await Users.findById(userId);
            if (!rows || rows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Unauthorized"
                });
            }

            await Users.delete(userId);
            return res.json({ success: true, message: "User Account Deleted! You are unable to Login" });

        } catch (err) {
            return res.status(500).json({ success: false, message: err.message });
        }
    },

};
