// tests/helpers/client.js
// A small "fake browser" for tests: it keeps cookies and the CSRF token.

const request = require("supertest");
const defaultApp = require("../../src/app");

// Pass a different app to talk to it instead of the real one.
async function createClient(app = defaultApp) {
  const agent = request.agent(app); // an agent remembers cookies
  let csrf = (await agent.get("/api/auth/csrf-token")).body.csrfToken;

  return {
    get: (url) => agent.get(url),

    async post(url, body = {}) {
      const res = await agent.post(url).set("x-csrf-token", csrf).send(body);
      // After login the server gives us a fresh CSRF token. Keep using it.
      if (res.body && res.body.csrfToken) csrf = res.body.csrfToken;
      return res;
    },
  };
}

let counter = 0;

// Makes valid registration data, with a different email each time.
function newUser(overrides = {}) {
  counter += 1;
  return {
    name: "Test User",
    email: `user${counter}@example.com`,
    password: "Passw0rdLong1",
    role: "buyer",
    ...overrides,
  };
}

module.exports = { createClient, newUser };