const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendVerificationEmail({ to, name, token }) {
  const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${encodeURIComponent(token)}`;

  return transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject: "Verify your BAuth account",
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>Verify your account</h2>
        <p>Hello ${name || "there"},</p>
        <p>Click the button below to verify your email address.</p>
        <p>
          <a href="${verifyUrl}" style="display:inline-block;padding:10px 16px;background:#2563eb;color:white;text-decoration:none;border-radius:6px">
            Verify email
          </a>
        </p>
        <p>This link expires in 30 minutes.</p>
      </div>
    `,
  });
}

module.exports = { sendVerificationEmail };