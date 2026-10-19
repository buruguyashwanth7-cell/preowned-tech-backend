// src/routes/authRoutes.js
// All /api/auth/... routes.

const express = require("express");
const { ensureCsrfToken } = require("../middleware/csrf");
const validate = require("../middleware/validate");
const { requireAuth } = require("../middleware/auth");
const {
  registerLimiter,
  loginLimiter,
  passwordRecoveryLimiter,
  changePasswordLimiter,
} = require("../middleware/rateLimiters");
const {
  registerSchema,
  verifyEmailSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} = require("../utils/authSchemas");
const {
  register,
  verifyEmail,
  login,
  logout,
  me,
} = require("../controllers/authController");
const {
  forgotPassword,
  resetPassword,
  changePassword,
} = require("../controllers/passwordController");

const router = express.Router();

// GET /api/auth/csrf-token -> gives the frontend/Postman a token to send back.
router.get("/csrf-token", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ csrfToken: ensureCsrfToken(req) });
});

// The limiter always runs BEFORE validation and the controller.
router.post("/register", registerLimiter, validate(registerSchema), register);
router.post("/verify-email", validate(verifyEmailSchema), verifyEmail);
router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/logout", logout);
router.get("/me", requireAuth, me);

router.post(
  "/forgot-password",
  passwordRecoveryLimiter,
  validate(forgotPasswordSchema),
  forgotPassword
);
router.post(
  "/reset-password",
  passwordRecoveryLimiter,
  validate(resetPasswordSchema),
  resetPassword
);
router.post(
  "/change-password",
  requireAuth,
  changePasswordLimiter,
  validate(changePasswordSchema),
  changePassword
);

module.exports = router;
