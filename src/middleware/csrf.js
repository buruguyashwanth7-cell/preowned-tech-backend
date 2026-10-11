// src/middleware/csrf.js
// CSRF protection using a token stored in the session.

const crypto = require("crypto");

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// Makes a CSRF token for this session if it doesn't have one yet.
function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

// Compares two strings in a way that doesn't leak timing information.
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Blocks state-changing requests that don't carry the right token.
function verifyCsrf(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const sentToken = req.get("x-csrf-token");
  const expectedToken = req.session && req.session.csrfToken;

  if (!sentToken || !expectedToken || !safeEqual(sentToken, expectedToken)) {
    return res.status(403).json({ message: "Invalid or missing CSRF token" });
  }
  next();
}

module.exports = { ensureCsrfToken, verifyCsrf };