// src/middleware/auth.js
// Reusable check: "you must be logged in" (more checks will be added later).

const User = require("../models/User");

async function requireAuth(req, res, next) {
  const userId = req.session && req.session.userId;

  if (!userId) {
    return res.status(401).json({ message: "Authentication required" });
  }

  const user = await User.findById(userId);

  // The account was deleted or suspended after the user logged in.
  if (!user || user.isSuspended) {
    return req.session.destroy(() => {
      res.status(401).json({ message: "Authentication required" });
    });
  }

  req.user = user;
  next();
}

module.exports = { requireAuth };