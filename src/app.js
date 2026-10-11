// src/app.js
// Builds the Express app. It does NOT connect to the database or start listening.
// (server.js does that, so tests can use this app on its own.)

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { env } = require("./config/env");
const { sessionMiddleware } = require("./config/session");
const { verifyCsrf } = require("./middleware/csrf");
const authRoutes = require("./routes/authRoutes");

const app = express();

// Behind a hosting proxy (production), trust it so Secure cookies work.
if (env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// Security headers
app.use(helmet());

// Only our own frontend may call this API from a browser, and cookies are allowed.
app.use(cors({ origin: env.CLIENT_ORIGIN, credentials: true }));

// Read JSON bodies, but refuse very large ones.
app.use(express.json({ limit: "10kb" }));

// Sessions, then CSRF checks for every state-changing /api request.
app.use(sessionMiddleware);
app.use("/api", verifyCsrf);

app.get("/", (req, res) => {
  res.json({ message: "Preowned Tech Buying Companion API is running!" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Backend is healthy" });
});

app.use("/api/auth", authRoutes);

// Unknown route -> 404
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Safe error handler: never shows stack traces or internal details to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Invalid JSON in request body" });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ message: "Request body is too large" });
  }
  console.error("Unexpected error:", err.message);
  res.status(500).json({ message: "Something went wrong" });
});

module.exports = app;