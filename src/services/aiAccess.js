// src/services/aiAccess.js
// The permission gate for AI features.
// An AI feature must NEVER receive a raw database record. It goes through
// authorizeForAI first. The AI only sees what the asking user is allowed to see,
// and only the allowlisted fields.

const { sameId } = require("../middleware/authorize");

// Ready-made "may this user access this?" checks.
function isOwner(field = "seller") {
  return (user, resource) => sameId(resource[field], user.id);
}

function isParticipant(fields = ["buyer", "seller"]) {
  return (user, resource) =>
    fields.some((field) => sameId(resource[field], user.id));
}

function deny(status, message) {
  return { allowed: false, status, message };
}

// user      -> req.user (from requireAuth)
// resource  -> the record the AI feature wants to use
// canAccess -> (user, resource) => true/false (for example isParticipant())
// serialize -> picks the allowed fields (for example makeSerializer([...]))
//
// Returns { allowed: true, data } or { allowed: false, status, message }.
async function authorizeForAI({ user, resource, canAccess, serialize }) {
  if (typeof canAccess !== "function" || typeof serialize !== "function") {
    throw new Error("authorizeForAI needs both a canAccess and a serialize function");
  }

  if (!user) return deny(401, "Authentication required");

  if (!user.isEmailVerified) {
    return deny(403, "Please verify your email address first");
  }

  // "Missing" and "not yours" give the same answer on purpose.
  if (!resource || !(await canAccess(user, resource))) {
    return deny(404, "Not found");
  }

  return { allowed: true, data: serialize(resource) };
}

module.exports = { authorizeForAI, isOwner, isParticipant };