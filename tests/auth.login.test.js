// tests/auth.login.test.js
// Tests for login, /me, logout, sessions.

const request = require("supertest");
const app = require("../src/app");
const User = require("../src/models/User");
const { connectTestDB, clearDB, disconnectTestDB } = require("./helpers/db");
const { createClient, newUser } = require("./helpers/client");

beforeAll(async () => {
  process.env.DISABLE_RATE_LIMIT = "1"; // rate limits are tested in their own file
  await connectTestDB();
}, 300000);

afterEach(async () => {
  await clearDB();
});

afterAll(async () => {
  delete process.env.DISABLE_RATE_LIMIT;
  await disconnectTestDB();
});

// Registers a user (and verifies the email unless told not to).
async function createUser({ verified = true, ...overrides } = {}) {
  const data = newUser(overrides);
  const client = await createClient();
  const reg = await client.post("/api/auth/register", data);
  if (verified) {
    await client.post("/api/auth/verify-email", {
      token: reg.body.devVerificationToken,
    });
  }
  return data;
}

// Reads the session cookie ("ptbc.sid=...") from a response.
function sessionCookie(res) {
  const list = res.headers["set-cookie"] || [];
  const found = list.find((cookie) => cookie.startsWith("ptbc.sid="));
  return found ? found.split(";")[0] : undefined;
}

// Logs in with a "browser" (agent) that remembers cookies, and keeps the details.
async function loginWithAgent(data) {
  const agent = request.agent(app);
  const first = await agent.get("/api/auth/csrf-token");
  const oldCsrf = first.body.csrfToken;
  const res = await agent
    .post("/api/auth/login")
    .set("x-csrf-token", oldCsrf)
    .send({ email: data.email, password: data.password });
  return { agent, first, res, oldCsrf };
}

describe("POST /api/auth/login", () => {
  test("logs in, returns the user without secrets, sets a safe cookie", async () => {
    const data = await createUser();
    const { res } = await loginWithAgent(data);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(data.email);
    expect(res.body.user).not.toHaveProperty("passwordHash");
    expect(res.body.csrfToken).toMatch(/^[a-f0-9]{64}$/);

    const cookie = res.headers["set-cookie"].join(";");
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
  });

  test("the email is not case-sensitive", async () => {
    const data = await createUser();
    const client = await createClient();
    const res = await client.post("/api/auth/login", {
      email: data.email.toUpperCase(),
      password: data.password,
    });
    expect(res.status).toBe(200);
  });

  test("wrong password and unknown email give the SAME answer", async () => {
    const data = await createUser();
    const client = await createClient();

    const wrongPassword = await client.post("/api/auth/login", {
      email: data.email,
      password: "WrongPassword99",
    });
    const unknownEmail = await client.post("/api/auth/login", {
      email: "nobody@example.com",
      password: "WrongPassword99",
    });

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(wrongPassword.body).toEqual(unknownEmail.body);
    expect(wrongPassword.body.message).toBe("Invalid email or password");
  });

  test("rejects a missing password", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/login", { email: "a@example.com" });
    expect(res.status).toBe(400);
  });

  test("rejects unexpected fields", async () => {
    const data = await createUser();
    const client = await createClient();
    const res = await client.post("/api/auth/login", {
      email: data.email,
      password: data.password,
      role: "admin",
    });
    expect(res.status).toBe(400);
  });

  test("an unverified user can log in but is marked unverified", async () => {
    const data = await createUser({ verified: false });
    const { agent, res } = await loginWithAgent(data);

    expect(res.status).toBe(200);
    expect(res.body.user.isEmailVerified).toBe(false);

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.user.isEmailVerified).toBe(false);
  });

  test("a suspended account cannot log in", async () => {
    const data = await createUser();
    await User.updateOne({ email: data.email }, { $set: { isSuspended: true } });

    const { agent, res } = await loginWithAgent(data);
    expect(res.status).toBe(403);

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(401);
  });
});

describe("sessions, /me and logout", () => {
  test("GET /me needs a login", async () => {
    const client = await createClient();
    const res = await client.get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  test("GET /me returns the logged-in user without secrets", async () => {
    const data = await createUser();
    const { agent } = await loginWithAgent(data);

    const res = await agent.get("/api/auth/me");
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(data.email);
    expect(res.body.user).not.toHaveProperty("passwordHash");
    expect(res.headers["cache-control"]).toMatch(/no-store/);
  });

  test("the session ID changes when you log in", async () => {
    const data = await createUser();
    const { first, res } = await loginWithAgent(data);

    const before = sessionCookie(first);
    const after = sessionCookie(res);
    expect(before).toBeDefined();
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
  });

  test("the CSRF token from before login stops working", async () => {
    const data = await createUser();
    const { agent, oldCsrf } = await loginWithAgent(data);

    const blocked = await agent.post("/api/auth/logout").set("x-csrf-token", oldCsrf);
    expect(blocked.status).toBe(403);

    // ...and we are still logged in, because the request was blocked.
    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(200);
  });

  test("logout ends the session", async () => {
    const data = await createUser();
    const client = await createClient();
    await client.post("/api/auth/login", {
      email: data.email,
      password: data.password,
    });
    expect((await client.get("/api/auth/me")).status).toBe(200);

    const out = await client.post("/api/auth/logout");
    expect(out.status).toBe(200);

    expect((await client.get("/api/auth/me")).status).toBe(401);
  });

  test("an old session cookie is useless after logout", async () => {
    const data = await createUser();
    const { agent, res } = await loginWithAgent(data);
    const cookie = sessionCookie(res);

    // Before logout, the cookie works on its own.
    const before = await request(app).get("/api/auth/me").set("Cookie", cookie);
    expect(before.status).toBe(200);

    await agent.post("/api/auth/logout").set("x-csrf-token", res.body.csrfToken);

    // After logout, the same cookie no longer works: the session is gone on the server.
    const after = await request(app).get("/api/auth/me").set("Cookie", cookie);
    expect(after.status).toBe(401);
  });

  test("logout without a CSRF token is blocked", async () => {
    const data = await createUser();
    const { agent } = await loginWithAgent(data);

    const res = await agent.post("/api/auth/logout");
    expect(res.status).toBe(403);
  });
});