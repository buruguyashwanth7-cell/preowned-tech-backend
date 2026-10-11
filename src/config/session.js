// src/config/session.js
// Server-side sessions. Only a random session ID goes in the browser cookie;
// the real session data lives in MongoDB.

const session = require("express-session");
const MongoStoreModule = require("connect-mongo");
const { env } = require("./env");

const MongoStore = MongoStoreModule.default || MongoStoreModule;

const isProduction = env.NODE_ENV === "production";
const SESSION_MAX_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours

function buildStore() {
  // Tests use a built-in memory store, so no database is needed.
  if (env.NODE_ENV === "test") return new session.MemoryStore();

  return MongoStore.create({
    mongoUrl: env.MONGODB_URI,
    collectionName: "sessions",
    // Store sessions as objects (not text) so we can find and delete
    // all sessions of one user when their password changes.
    stringify: false,
    ttl: SESSION_MAX_AGE_MS / 1000,
  });
}

const sessionStore = buildStore();

const sessionMiddleware = session({
  name: "ptbc.sid", // custom name instead of the default "connect.sid"
  secret: env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false, // no cookie until we actually store something
  rolling: true, // active users stay logged in
  store: sessionStore,
  cookie: {
    httpOnly: true, // JavaScript in the browser cannot read this cookie
    sameSite: "lax",
    secure: isProduction, // HTTPS only in production
    maxAge: SESSION_MAX_AGE_MS,
  },
});

module.exports = { sessionMiddleware, sessionStore, SESSION_MAX_AGE_MS };