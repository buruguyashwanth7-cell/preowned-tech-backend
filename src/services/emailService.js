// src/services/emailService.js
// Sends emails. Right now there is NO real email provider connected.
// In development the link is printed in the terminal instead.
// To send real emails later, replace the body of sendEmail() with a call to
// an email provider (Resend, SendGrid, or SMTP).

const { env } = require("../config/env");

async function sendEmail(to, label, link) {
  if (env.NODE_ENV === "production") {
    console.warn(`Email provider not configured: ${label} email was NOT sent.`);
    return { sent: false };
  }

  if (env.NODE_ENV === "development") {
    console.log(`[DEV EMAIL] ${label} link for ${to}: ${link}`);
  }
  return { sent: false, devOnly: true };
}

async function sendVerificationEmail(user, token) {
  const link = `${env.CLIENT_ORIGIN}/verify-email?token=${token}`;
  return sendEmail(user.email, "Verification", link);
}

async function sendPasswordResetEmail(user, token) {
  const link = `${env.CLIENT_ORIGIN}/reset-password?token=${token}`;
  return sendEmail(user.email, "Password reset", link);
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };