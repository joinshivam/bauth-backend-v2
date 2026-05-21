const getEnv = (varName, isRequired = true) => {
    const value = process.env[varName];
    if (isRequired && (value === undefined || value === null)) {
        process.exit(1);
    }
    return value;
}

const getProductionSecret = (varName, devFallback) => {
    const value = process.env[varName];
    if (value) return value;

    if (process.env.NODE_ENV !== "production" && devFallback) {
        return devFallback;
    }
    process.exit(1);
}

module.exports = {
    PORT: getEnv('PORT'),
    NODE_ENV: getEnv('NODE_ENV'),
    API_BASE_URL: getEnv('API_BASE_URL'),
    IDP_FRONTEND_BASE_URL: getEnv('IDP_FRONTEND_BASE_URL'),
    MYSQL_HOST: getEnv('MYSQL_HOST'),
    MYSQL_PORT: getEnv('MYSQL_PORT'),
    MYSQL_USER: getEnv('MYSQL_USER'),
    MYSQL_PASSWORD: getEnv('MYSQL_PASSWORD'),
    MYSQL_DATABASE: getEnv('MYSQL_DATABASE'),
    DB_SSL: process.env.DB_SSL === 'true',
    SESSION_COOKIE_NAME: getEnv('SESSION_COOKIE_NAME'),
    SESSION_TTL_HOURS: parseInt(process.env.SESSION_TTL_HOURS) || getEnv('SESSION_TTL_HOURS'),
    ACCESS_TOKEN_TTL_SECONDS: parseInt(process.env.ACCESS_TOKEN_TTL_SECONDS) || getEnv('ACCESS_TOKEN_TTL_SECONDS'),
    REFRESH_TOKEN_TTL_DAYS: parseInt(process.env.REFRESH_TOKEN_TTL_DAYS) || getEnv('REFRESH_TOKEN_TTL_DAYS'),
    OAUTH_STATE_TTL_MINUTES: parseInt(process.env.OAUTH_STATE_TTL_MINUTES) || getEnv('OAUTH_STATE_TTL_MINUTES'),
    AUTH_CODE_TTL_SECONDS: parseInt(process.env.AUTH_CODE_TTL_SECONDS) || getEnv('AUTH_CODE_TTL_SECONDS'),
    COOKIE_SECURE: process.env.COOKIE_SECURE === 'true',
    COOKIE_DOMAIN: process.env.COOKIE_DOMAIN,
    // CORS_ORIGIN: JSON.parse(process.env.CORS_ORIGIN || '[]'),
    // REDIS_URL: process.env.REDIS_URL || getEnv('REDIS_URL'),
    DEFAULT_ADMIN_EMAIL: getEnv('DEFAULT_ADMIN_EMAIL'),
    DEFAULT_ADMIN_PASSWORD: getEnv('DEFAULT_ADMIN_PASSWORD'),
    JWT_SECRET: getEnv('JWT_SECRET'),
    IDP_ACCESS_TOKEN_SECRET: getProductionSecret('IDP_ACCESS_TOKEN_SECRET', process.env.JWT_SECRET),
    IDP_ISSUER: getEnv('IDP_ISSUER', false) || getEnv('API_BASE_URL'),
    ADMIN_PANEL_CLIENT_ID: getEnv('ADMIN_PANEL_CLIENT_ID', process.env.NODE_ENV === 'production') || 'bauth_admin_panel',
    ADMIN_PANEL_CLIENT_SECRET: getProductionSecret('ADMIN_PANEL_CLIENT_SECRET', process.env.JWT_SECRET),
    SMTP_HOST: getEnv('SMTP_HOST'),
    SMTP_PORT: getEnv('SMTP_PORT'),
    SMTP_SECURE: process.env.SMTP_SECURE === 'true',
    SMTP_USER: getEnv('SMTP_USER'),
    SMTP_PASS: getEnv('SMTP_PASS'),
    EMAIL_FROM: getEnv('EMAIL_FROM'),
    FRONTEND_URL: getEnv('FRONTEND_URL')
};
