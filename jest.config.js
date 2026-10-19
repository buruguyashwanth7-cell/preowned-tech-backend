// jest.config.js
// Settings for the automated tests.

module.exports = {
  testEnvironment: "node",
  setupFiles: ["<rootDir>/tests/setupEnv.js"],
  testMatch: ["<rootDir>/tests/**/*.test.js"],
  testTimeout: 60000,
};