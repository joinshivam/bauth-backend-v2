const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const path = require("path");
require('dotenv').config({ path: __dirname + '/.env' });
const { connectDB } = require('./database/database');
const http = require("http");
const { Server } = require("socket.io");
const setupSocket = require("./chat/socket");
const { createCorsHandler, getSocketAllowedOrigins } = require("./middleware/corsHandler.middleware");


const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, "public")));
app.use("/v2/components/header", express.static(path.join(__dirname, "public/v2/components/header")));
app.use("/v2", express.static(path.join(__dirname, "public/v2/")));
const PORT = process.env.PORT || 5000;
const server = http.createServer(app);
let DB_HEALTH = false;

app.use(createCorsHandler());
app.use(cookieParser());
app.use(bodyParser.json());
app.set('trust proxy', true);
const io = new Server(server, {
    cors: {
        origin: getSocketAllowedOrigins(),
        methods: ["GET", "POST"]
    }
});
(async () => {
    console.log(`start ${new Date()} // ${process.env.NODE_ENV} // ${PORT}`);
    try {
        await connectDB();
        app.use("/bauth/account/signup", express.static(path.join(__dirname, "public/auth/")));
        app.use("/", require("./routes/admin.route"));
        app.use("/api/media", require("./routes/media.route"));
        app.use("/api/auth", require("./routes/auth.route"));
        app.use("/api/idp", require("./routes/idp.route"));
        app.use("/api", require("./routes/user.route"));
        DB_HEALTH = true;
    } catch (err) {
        console.log("Database Error : ", {
            msg: err.message || "Error Found",
            db_health: DB_HEALTH ? "alive" : "died",
            ERR_OBJECT: err
        });
    }
})()

app.use("/api/health", (req, res) => {
    try {
        res.json({
            ok: DB_HEALTH,
            database: DB_HEALTH ? "alive" : "died",
            backend: "alive"
        })
    } catch (err) {
        res.json({
            ok: false,
            message: `failed to connect : ${err.message}`,
            status_code: err?.status_code
        });
    }
})
setupSocket(io);
app.get("/", (req, res) => {
    res.status(200).send("ok");
})

server.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});
