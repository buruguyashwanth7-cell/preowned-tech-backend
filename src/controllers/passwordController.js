// src/controllers/passwordController.js
// Forgot password, reset password, and change password.

const User = require("../models/User");
const { generateToken, hashToken } = require("../utils/tokens");
const { sendPasswordResetEmail } = require("../services/emailService");
const {
  destroyUserSessions,
  regenerateSession,
  saveSession,
} = require("../services/sessionService");
const { ensureCsrfToken } = require("../middleware/csrf");
const { env } = require("../config/env");

const RESET_TTL_MS = 60 * 60 * 1000; // reset links work for 1 hour

// The same answer whether or not the email exists, so nobody can use this
// endpoint to find out which emails are registered.
const GENERIC_MESSAGE =
  "If an account with that email exists, a password reset link has been sent.";

// POST /api/auth/forgot-password
async function forgotPassword(req, res) {
  const body = { message: GENERIC_MESSAGE };

  const user = await User.findOne({ email: req.body.email });

  if (user) {
    const { token, tokenHash } = generateToken();

    await User.updateOne(
      { _id: user._id },
      {
        $set: {
          passwordResetTokenHash: tokenHash,
          passwordResetExpires: new Date(Date.now() + RESET_TTL_MS),
        },
      }
    );

    await sendPasswordResetEmail(user, token);

    // Development/test only. NEVER included in production.
    if (env.NODE_ENV !== "production") {
      body.devResetToken = token;
    }
  }

  res.json(body);
}

// POST /api/auth/reset-password
async function resetPassword(req, res) {
  const { token, newPassword } = req.body;

  const newHash = await User.hashPassword(newPassword);

  // One atomic step: find a matching, unexpired token, change the password,
  // and remove the token, so a reset link can only be used once.
  const user = await User.findOneAndUpdate(
    {
      passwordResetTokenHash: hashToken(token),
      passwordResetExpires: { $gt: new Date() },
    },
    {
      $set: { passwordHash: newHash, passwordChangedAt: new Date() },
      $unset: { passwordResetTokenHash: "", passwordResetExpires: "" },
    },
    { new: true }
  );

  if (!user) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }

  // Log the user out everywhere.
  await destroyUserSessions(user.id);

  res.json({ message: "Password has been reset. Please log in with your new password." });
}

// POST /api/auth/change-password   (requireAuth has already checked the login)
async function changePassword(req, res) {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user.id).select("+passwordHash");

  if (!(await user.verifyPassword(currentPassword))) {
    return res.status(400).json({ message: "Current password is incorrect" });
  }

  if (currentPassword === newPassword) {
    return res
      .status(400)
      .json({ message: "New password must be different from the current password" });
  }

  const newHash = await User.hashPassword(newPassword);

  await User.updateOne(
    { _id: user._id },
    {
      $set: { passwordHash: newHash, passwordChangedAt: new Date() },
      // Any reset link sent earlier must stop working too.
      $unset: { passwordResetTokenHash: "", passwordResetExpires: "" },
    }
  );

  // Log out every OTHER device, then give this device a fresh session ID.
  await destroyUserSessions(user.id, req.sessionID);
  await regenerateSession(req);
  req.session.userId = user.id;
  const csrfToken = ensureCsrfToken(req);
  await saveSession(req);

  res.json({
    message: "Password changed successfully. Your other devices were logged out.",
    csrfToken,
  });
}

module.exports = { forgotPassword, resetPassword, changePassword };