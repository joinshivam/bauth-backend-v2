const { getDB } = require("../database/database");
const { throwError } = require("../utils/functions.js")
const ACCESS_TOTKEN_Expire = parseInt(process.env.ACCESS_TOKEN_EXPIRES) * 60;
const Users = {

    create: (data) => {
        const db = getDB();
        return db.query("INSERT INTO users SET ?", data);
    },

    findById: (id) => {
        const db = getDB();
        return db.query("SELECT * FROM users WHERE id = ?", [id]);
    },

    findByEmail: (email) => {
        const db = getDB();
        return db.query("SELECT * FROM users WHERE email = ?", [email]);
    },
    findByUsername: async (username) => {
        if (typeof username !== "string") return;
        const db = getDB();
        return await db.query("SELECT * FROM users WHERE username = ?", [username?.toLowerCase()]);
    },

    findAll: () => {
        const db = getDB();
        return db.query("SELECT * FROM users ORDER BY id DESC");
    },

    findByPhoto: (filename) => {
        const db = getDB();
        return db.query("SELECT id, photo FROM users WHERE photo = ?", [filename]);
    },

    update: (id, data) => {
        const db = getDB();
        return db.query("UPDATE users SET ? WHERE id = ?", [data, id]);
    },
    updateName: async (id, name) => {
        try {
            const ValidName = Users.validateName(name);
            const db = getDB();
            const [result] = await db.query("UPDATE users SET name = ? WHERE id = ?", [ValidName, id]);
            if (result.affectedRows === 0) {
                throwError("User not found", "name", 404);
            }
            return result;
        }
        catch (err) {
            if (err?.field) throw err;
            throwError(err.message || "Database error", "name", 500);
        }
    },
    updateDOB: async (id, dob) => {
        try {
            const ValidDOB = Users.validateDob(dob);
            const db = getDB();
            const [result] = await db.query("UPDATE users SET dob = ? WHERE id = ?", [ValidDOB, id]);
            if (result.affectedRows === 0) {
                throwError("User not found", "dob", 404);
            }
            return result;
        }
        catch (err) {
            if (err?.field) throw err;
            throwError(err.message || "Database error", "dob", 500);
        }
    },
    updateGender: async (id, gender) => {
        try {
            const ValidGender = Users.validateGender(gender);
            const db = getDB();
            const [result] = await db.query("UPDATE users SET gender = ? WHERE id = ?", [ValidGender, id]);
            if (result.affectedRows === 0) {
                throwError("User not found", "gender", 404);
            }
            return result;
        }
        catch (err) {
            if (err?.field) throw err;
            throwError(err.message || "Database error", "gender", 500);
        }
    },
    updateUsername: async (id, username) => {
        try {
            const ValidUsername = Users.validateUsername(username);

            const [exists] = await Users.findByUsername(ValidUsername);
            const conflict = exists.find(row => String(row.id) !== String(id));
            if (conflict) {
                throwError("Username already taken", "username", 400);
            }

            const db = getDB();
            const [result] = await db.query("UPDATE users SET username = ? ,email = CONCAT(?, postfix) WHERE id = ?", [ValidUsername, ValidUsername, id]);
            if (result.affectedRows === 0) {
                throwError("User not found", "username", 404);
            }
            return result;
        }
        catch (err) {
            if (err?.field) throw err;
            throwError(err.message || "Database error", "username", 500);
        }
    },
    updatePhone: async (id, phone) => {
        try {
            const ValidPhone = Users.validatePhone(phone);
            const db = getDB();
            const [result] = await db.query("UPDATE users SET phone = ? WHERE id = ?", [ValidPhone, id]);
            if (result.affectedRows === 0) {
                throwError("User not found", "phone", 404);
            }
            return result;
        }
        catch (err) {
            if (err?.field) throw err;
            throwError(err.message || "Database error", "phone", 500);
        }
    },

    updateEmail: (id, email) => {
        const db = getDB();
        return db.query("UPDATE users SET email = ? WHERE id = ?", [email, id]);
    },
    updatePhoto: async (userId, filename) => {
        const db = getDB();
        const [result] = await db.query(
            "UPDATE users SET photo = ? WHERE id = ?",
            [filename, userId]
        );

        if (result.affectedRows === 0) {
            throw new Error("User not found");
        }

        return filename;
    },


    updatePassword: (id, hashedPassword) => {
        const db = getDB();
        return db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, id]);
    },

    delete: (id) => {
        const db = getDB();
        return db.query("DELETE FROM users WHERE id = ?", [id]);
    },

    login: (email) => {
        const db = getDB();
        return db.query("SELECT * FROM users WHERE email = ?", [email]);
    },

    updateRoles: (id, recovery) => {
        const db = getDB();
        return db.query(
            "UPDATE users SET recovery = ? WHERE id = ?",
            [recovery, id]
        );
    },
    setSession: async ({ id, accessToken, agent, ip, expire = ACCESS_TOTKEN_Expire }) => {
        if (id === "" || !accessToken || !agent || ip === "") {
            throwError("Invalid session set parameters");
        }
        const db = await getDB();
        const [Session] = await db.query(
            `INSERT INTO user_sessions (user_id, session_token,user_agent, ip_address, expires_at , revoked) 
             VALUES (?, ?, ?,?, DATE_ADD(NOW(), INTERVAL ? SECOND) , 0)`,
            [id, accessToken, agent, ip, expire]
        )
        return Session.insertId || null;
    },
    getSessionByToken: async (token) => {
        if (!token) return null;

        const db = await getDB();
        const [rows] = await db.query(
            `SELECT * FROM user_sessions
     WHERE session_token = ?
     AND revoked = 0
     AND expires_at > NOW()
     LIMIT 1`,
            [token]
        );

        return rows[0] || null;
    },
    findSessionsByUser: async (userId, limit = 10) => {
        const db = getDB();

        return db.query(
            `
    (
      SELECT
        id,
        user_agent,
        ip_address,
        revoked,
        created_at AS sort_time,
        expires_at
      FROM user_sessions
      WHERE user_id = ?
        AND revoked = 0
      ORDER BY sort_time DESC
    )
    UNION ALL
    (
      SELECT
        id,
        user_agent,
        ip_address,
        revoked,
        created_at AS sort_time,
        expires_at
      FROM user_sessions
      WHERE user_id = ?
        AND revoked != 0
      ORDER BY sort_time DESC
      LIMIT ?
    )
    ORDER BY sort_time DESC
    `,
            [userId, userId, limit]
        );
    },
    revokeSession: async (token) => {
        try {
            if (token === 0 || !token) {
                return `Invalid token to get Session `;
            }
            const db = await getDB();
            const Session = await db.query(
                "UPDATE user_sessions SET `revoked` = '1' WHERE session_token = ?",
                [token]
            )
            return Session.affectedRows;
        } catch (err) {
            return err;
        }
    },
    revokeSessionAll: async (token, user_id) => {
        try {
            if (token === 0 || !token || user_id === "") {
                return `unable to logout from this device `;
            }
            const db = await getDB();
            const Session = await db.query(
                "UPDATE user_sessions SET `revoked` = '1' WHERE user_id = ?",
                [user_id]
            )
            return Session.affectedRows;
        } catch (err) {
            return err;
        }
    },
    validateName: (name) => {
        const ValidName = name?.toLowerCase().trim();
        const nameRegex = /^[A-Za-z]+(?:\s[A-Za-z]+)*$/;
        if (!ValidName || typeof ValidName !== "string") {
            throwError("Name cannot be blank", "name");
        };
        if (!nameRegex.test(ValidName)) {
            throwError("Invalid name format", "name");
        };
        return ValidName;
    },
    validateUsername: (username) => {
        const ValidUsername = username?.toLowerCase().trim();
        const usernameRegex = /^[a-z0-9]+(\.[a-z0-9]+)*$/;
        if (!ValidUsername || typeof ValidUsername !== "string") throw new Error("Username field cannot Blank! or Invalid")
        if (!usernameRegex.test(ValidUsername)) throw new Error("Invalid username format");
        return ValidUsername;
    },
    validatePassword: (password) => {
        const ValidPassword = password?.trim();
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&^#()_+\-={}[\]|\\:;"'<>,./?]).{8,}$/;
        if (!ValidPassword || typeof ValidPassword !== "string") throw new Error("Password field cannot Blank! or Invalid")
        if (!passwordRegex.test(ValidPassword)) throw new Error("Invalid Password Format, it must length of 8 and at least one Caps ,lowercase , number and special char ");
        return ValidPassword;
    },
    validatePhone: (phone) => {
        const ValidPhone = phone?.trim();
        // const phoneRegex = /^(\+)+([0-9]{2,3})+([0-9]{10})*$/;
        const phoneRegex = /^[6-9][0-9]{9}$/;
        if (!ValidPhone || typeof ValidPhone !== "string") throw new Error("Phone field cannot Blank!");
        if (!phoneRegex.test(ValidPhone)) throw new Error("Invalid Phone Number! phone no. 10 digit indian number");
        return ValidPhone;
    },
    validateDob: (dob) => {
        const MIN_AGE = 13;
        const dobRegex = /^\d{2}\/\d{2}\/\d{4}$/;
        const ValidDob = dob?.replace(/\s+/g, "");

        if (!ValidDob || typeof ValidDob !== "string" || ValidDob.length !== 10) throw new Error("Date of Birth field cannot Blank! or Invalid")
        if (!dobRegex.test(ValidDob)) {
            throw new Error("Invalid DOB format (use DD/MM/YYYY)");
        }
        const [dd, mm, yyyy] = ValidDob.split("/").map(Number);
        const date = new Date(yyyy, mm - 1, dd);
        const isInvalid = date.getFullYear() !== yyyy || date.getMonth() !== mm - 1 || date.getDate() !== dd;
        const today = new Date();
        let age = today.getFullYear() - yyyy;
        const m = today.getMonth() - (mm - 1);

        if (isInvalid) throw new Error("Invalid DOB");
        if (date > new Date()) throw new Error("Date of birth cannot be in the future");
        if (m < 0 || (m === 0 && today.getDate() < dd)) age--;
        if (age < MIN_AGE) throw new Error("you must age of 13 to create account.");
        return ValidDob;
    },
    validateGender: (gender) => {
        const ValidGender = gender?.toLowerCase().trim();
        if (!ValidGender || typeof ValidGender !== "string") throw new Error("Gender not selected")
        if (!["male", "female", "other"].includes(ValidGender)) {
            throw new Error("Please input Valid Gender . [male , female or other]");
        }
        return ValidGender;
    },
};

module.exports = Users;
