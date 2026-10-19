// tests/auth.ratelimit.test.js
// Tests for rate limiting. Here the limits are switched ON.
// The tests are written so they do not depend on what ran before them.

const { connectTestDB, clearDB, disconnectTestDB } = require("./helpers/db");
const { createClient, newUser } = require("./helpers/client");

beforeAll(async () => {
  delete process.env.DISABLE_RATE_LIMIT; // here we WANT the limits switched on
  await connectTestDB();
}, 300000);

afterEach(async () => {
  await clearDB();
});

afterAll(async () => {
  await disconnectTestDB();
});

// Sends requests one after another until the server answers 429 (or we give up).
async function hitUntilBlocked(sendOnce, maxTries = 15) {
  const statuses = [];
  for (let i = 0; i < maxTries; i++) {
    const res = await sendOnce();
    statuses.push(res.status);
    if (res.status === 429) return { statuses, res };
  }
  return { statuses, res: null };
}

describe("rate limiting", () => {
  // This test comes FIRST because the limit for failed logins is shared inside this file.
  test("successful logins are not counted against the login limit", async () => {
    const data = newUser();
    const client = await createClient();
    const reg = await client.post("/api/auth/register", data);
    await client.post("/api/auth/verify-email", {
      token: reg.body.devVerificationToken,
    });

    for (let i = 0; i < 12; i++) {
      const res = await client.post("/api/auth/login", {
        email: data.email,
        password: data.password,
      });
      expect(res.status).toBe(200);
    }

    const bad = await client.post("/api/auth/login", {
      email: data.email,
      password: "WrongPassword99",
    });
    expect(bad.status).toBe(401); // not blocked
  });

  test("too many failed logins are blocked with 429", async () => {
    const client = await createClient();
    const { statuses, res } = await hitUntilBlocked(() =>
      client.post("/api/auth/login", {
        email: "nobody@example.com",
        password: "WrongPassword99",
      })
    );

    expect(res).not.toBeNull();
    expect(res.body.message).toMatch(/too many login attempts/i);
    expect(statuses.length).toBeLessThanOrEqual(11);
    // Everything before the block was an ordinary "wrong password" answer.
    expect(statuses.slice(0, -1).every((status) => status === 401)).toBe(true);
  });

  test("too many registrations from one address are blocked", async () => {
    const client = await createClient();
    const { statuses, res } = await hitUntilBlocked(() =>
      client.post("/api/auth/register", newUser())
    );

    expect(res).not.toBeNull();
    expect(res.body.message).toMatch(/too many accounts/i);
    expect(statuses.length).toBeLessThanOrEqual(11);
    expect(statuses.slice(0, -1).every((status) => status === 201)).toBe(true);
  });

  test("too many password recovery requests are blocked", async () => {
    const client = await createClient();
    const { statuses, res } = await hitUntilBlocked(() =>
      client.post("/api/auth/forgot-password", { email: "nobody@example.com" })
    );

    expect(res).not.toBeNull();
    expect(res.body.message).toMatch(/too many password recovery/i);
    expect(statuses.length).toBeLessThanOrEqual(11);
    expect(statuses.slice(0, -1).every((status) => status === 200)).toBe(true);
  });
});