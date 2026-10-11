// src/middleware/rateLimiters.js
// Limits how many requests one IP address can make in a time window.
// NOTE: counters live in the server's memory, so they reset when the server restarts.
// (A real deployment with several servers would use a shared store such as Redis.)

const rateLimit = require("express-rate-limit");

function createLimiter({ windowMs, limit, message, skipSuccessfulRequests = false }) {
  return rateLimit({
    windowMs, // the time window, in milliseconds
    limit, // how many requests are allowed in that window
    standardHeaders: "draft-7", // adds RateLimit-* headers to responses
    legacyHeaders: false,
    skipSuccessfulRequests, // true = only failed requests are counted
    message: { message }, // sent as JSON together with the 429 status
  });
}

const registerLimiter = createLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  limit: 10,
  message: "Too many accounts created from this address. Please try again later.",
});

// Only FAILED logins count, so normal users are not affected.
const loginLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 10,
  skipSuccessfulRequests: true,
  message: "Too many login attempts. Please try again in 15 minutes.",
});

// Forgot-password and reset-password share one counter.
const passwordRecoveryLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: "Too many password recovery attempts. Please try again later.",
});

const changePasswordLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  message: "Too many attempts. Please try again later.",
});

module.exports = {
  createLimiter,
  registerLimiter,
  loginLimiter,
  passwordRecoveryLimiter,
  changePasswordLimiter,
};