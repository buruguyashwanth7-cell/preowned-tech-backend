// src/services/sessionService.js
// Helpers for working with sessions.

const mongoose = require("mongoose");
const { env } = require("../config/env");
const { sessionStore } = require("../config/session");

// Gives the user a brand-new session ID (the old one stops working).
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

// Deletes ALL saved sessions of one user (every browser/device).
// keepSessionId (optional) is a session that should NOT be deleted.
async function destroyUserSessions(userId, keepSessionId) {
  const id = String(userId);

  if (env.NODE_ENV === "test") {
    // Tests use the memory store.
    const all = await new Promise((resolve, reject) => {
      sessionStore.all((err, sessions) => (err ? reject(err) : resolve(sessions || {})));
    });
    for (const [sid, data] of Object.entries(all)) {
      if (data.userId === id && sid !== keepSessionId) {
        await new Promise((resolve) => sessionStore.destroy(sid, () => resolve()));
      }
    }
    return;
  }

  // Real use: sessions are saved in the "sessions" collection in MongoDB.
  const filter = { "session.userId": id };
  if (keepSessionId) filter._id = { $ne: keepSessionId };
  await mongoose.connection.collection("sessions").deleteMany(filter);
}

module.exports = { regenerateSession, saveSession, destroyUserSessions };