// tests/setupEnv.js
// Runs before every test file. It sets SAFE test values, so the tests never
// use your real .env file (and never touch your Atlas database).

process.env.NODE_ENV = "test";
process.env.PORT = "5999";
process.env.MONGODB_URI = "mongodb://127.0.0.1:27017/capstone_test_placeholder";
process.env.SESSION_SECRET = "test-only-secret-test-only-secret-1234567890";
process.env.CLIENT_ORIGIN = "http://localhost:3000";