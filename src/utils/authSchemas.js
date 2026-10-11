// src/utils/authSchemas.js
// Rules for the data each auth endpoint accepts (using Zod).
// "strictObject" rejects any extra, unexpected fields.

const { z } = require("zod");

// Emails are trimmed and made lowercase BEFORE they are checked.
const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.email("Enter a valid email address").max(254));

// bcrypt only reads the first 72 characters, so we cap the length at 72.
const passwordSchema = z
  .string()
  .min(10, "Password must be at least 10 characters")
  .max(72, "Password must be at most 72 characters")
  .regex(/[A-Za-z]/, "Password must contain at least one letter")
  .regex(/[0-9]/, "Password must contain at least one number");

// A token from our links is 64 hex characters (see utils/tokens.js).
const tokenSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, "Invalid or expired token");

const registerSchema = z.strictObject({
  name: z.string().trim().min(2, "Name is too short").max(80, "Name is too long"),
  email: emailSchema,
  password: passwordSchema,
  // Only buyer or seller. "moderator" and "admin" are rejected.
  role: z.enum(["buyer", "seller"], { error: "Role must be buyer or seller" }),
});

const verifyEmailSchema = z.strictObject({
  token: tokenSchema,
});

const loginSchema = z.strictObject({
  email: emailSchema,
  password: z.string().min(1, "Password is required").max(128),
});

const forgotPasswordSchema = z.strictObject({
  email: emailSchema,
});

const resetPasswordSchema = z.strictObject({
  token: tokenSchema,
  newPassword: passwordSchema,
});

const changePasswordSchema = z.strictObject({
  currentPassword: z.string().min(1, "Current password is required").max(128),
  newPassword: passwordSchema,
});

module.exports = {
  registerSchema,
  verifyEmailSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
};