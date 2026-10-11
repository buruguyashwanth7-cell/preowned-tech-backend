// src/utils/tokens.js
// Helpers for secure, random, single-use tokens.

const crypto = require("crypto");

// Scrambles a token so we never store the raw one.
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Makes a new random token.
// "token" goes to the user (in a link). "tokenHash" is what we save in the database.
function generateToken() {
  const token = crypto.randomBytes(32).toString("hex");
  return { token, tokenHash: hashToken(token) };
}

module.exports = { generateToken, hashToken };