// src/controllers/authController.js
// The code that runs for each /api/auth/... endpoint.

const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { generateToken, hashToken } = require("../utils/tokens");
const { sendVerificationEmail } = require("../services/emailService");
const { ensureCsrfToken } = require("../middleware/csrf");
const { env } = require("../config/env");

const VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Same name and options as in src/config/session.js (needed to clear the cookie).
const SESSION_COOKIE_NAME = "ptbc.sid";

// A fake hash. When an email doesn't exist we still compare against this,
// so "unknown email" and "wrong password" take about the same time.
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password-for-timing", 12);

// Small helpers that turn session callbacks into promises.
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });
}

// POST /api/auth/register
async function register(req, res) {
  const { name, email, password, role } = req.body; // already cleaned by validate()

  if (await User.exists({ email })) {
    return res.status(409).json({ message: "An account with this email already exists" });
  }

  const { token, tokenHash } = generateToken();

  let user;
  try {
    user = await User.create({
      name,
      email,
      role, // validation only allows "buyer" or "seller"
      passwordHash: await User.hashPassword(password),
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpires: new Date(Date.now() + VERIFICATION_TTL_MS),
    });
  } catch (error) {
    // Two people registering the same email at the same moment.
    if (error.code === 11000) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }
    throw error;
  }

  await sendVerificationEmail(user, token);

  const body = {
    message: "Registration successful. Please verify your email before continuing.",
    user,
  };

  // Development/test only: lets you finish verification without a real email provider.
  // This field is NEVER included in production.
  if (env.NODE_ENV !== "production") {
    body.devVerificationToken = token;
  }

  res.status(201).json(body);
}

// POST /api/auth/verify-email
async function verifyEmail(req, res) {
  const tokenHash = hashToken(req.body.token);

  // One atomic step: find a matching, unexpired token AND remove it,
  // so a token can only ever be used once.
  const user = await User.findOneAndUpdate(
    {
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpires: { $gt: new Date() },
    },
    {
      $set: { isEmailVerified: true },
      $unset: { emailVerificationTokenHash: "", emailVerificationExpires: "" },
    },
    { new: true }
  );

  if (!user) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }

  res.json({ message: "Email verified successfully" });
}

// POST /api/auth/login
async function login(req, res) {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select("+passwordHash");

  const passwordMatches = await bcrypt.compare(
    password,
    user ? user.passwordHash : DUMMY_HASH
  );

  // Same message for "no such email" and "wrong password".
  if (!user || !passwordMatches) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  if (user.isSuspended) {
    return res.status(403).json({ message: "This account has been suspended" });
  }

  // New session ID after login, so an attacker can't reuse an old one.
  await regenerateSession(req);
  req.session.userId = user.id;
  const csrfToken = ensureCsrfToken(req); // the new session needs a new CSRF token
  await saveSession(req);

  res.json({ message: "Logged in successfully", user, csrfToken });
}

// POST /api/auth/logout
function logout(req, res, next) {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: true,
      sameSite: "lax",
      secure: env.NODE_ENV === "production",
    });
    res.json({ message: "Logged out successfully" });
  });
}

// GET /api/auth/me   (requireAuth has already loaded req.user)
function me(req, res) {
  res.set("Cache-Control", "no-store");
  res.json({ user: req.user });
}

module.exports = { register, verifyEmail, login, logout, me };