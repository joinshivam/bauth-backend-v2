const Env = require("../env");
const isProduction = Env.NODE_ENV === "production";

function baseCookieOptions() {
    return {
        httpOnly: true,
        secure: Env.COOKIE_SECURE || isProduction,
        sameSite: isProduction ? "none" : "lax",
        ...(Env.COOKIE_DOMAIN ? { domain: Env.COOKIE_DOMAIN } : {}),
    };
}

module.exports = {
    setCookie: (res, name, value, options = {}) => {
        const cookieOptions = {
            ...baseCookieOptions(),
            ...options
        };
        res.cookie(name, value, cookieOptions);
    },

    clearCookie: (res, name) => {
        res.clearCookie(name, {
            ...baseCookieOptions()
        });
    },

    getCookie: (req, name) => {
        return (req.cookies[name] || null);
    }
}
