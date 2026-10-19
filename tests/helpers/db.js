// tests/helpers/db.js
// Starts a temporary MongoDB that lives only in memory, for tests.
// It can never reach your real Atlas database.

const os = require("os");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const User = require("../../src/models/User");

let mongod;

async function connectTestDB() {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), {
    dbName: "capstone_test",
    // Workaround: newer MongoDB drivers load "os" in a way that Jest blocks, which
    // makes the database reject the connection. Passing it in ourselves avoids that.
    runtimeAdapters: { os },
  });
  await User.init(); // makes sure the unique-email rule exists
}

// Safety check: true ONLY when we are connected to the in-memory test database.
function isTestDatabase() {
  const db = mongoose.connection.db;
  return Boolean(mongod) && Boolean(db) && db.databaseName === "capstone_test";
}

// Empties every collection, so each test starts clean.
async function clearDB() {
  if (!isTestDatabase()) {
    throw new Error("Refusing to clear: not connected to the in-memory test database");
  }

  const collections = mongoose.connection.collections;
  for (const name of Object.keys(collections)) {
    await collections[name].deleteMany({});
  }
}

async function disconnectTestDB() {
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
}

module.exports = { connectTestDB, clearDB, disconnectTestDB };