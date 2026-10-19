// tests/auth.password.test.js
// Tests for forgot-password, reset-password and change-password.

const User = require("../src/models/User");
const { hashToken } = require("../src/utils/tokens");
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

const NEW_PASSWORD = "NewPassw0rd456";

// Registers and verifies a user. Returns the registration data.
async function createUser() {
  const data = newUser();
  const client = await createClient();
  const reg = await client.post("/api/auth/register", data);
  await client.post("/api/auth/verify-email", {
    token: reg.body.devVerificationToken,
  });
  return data;
}

// A "browser" that is logged in.
async function loggedInClient(data) {
  const client = await createClient();
  const res = await client.post("/api/auth/login", {
    email: data.email,
    password: data.password,
  });
  return { client, res };
}

async function tryLogin(email, password) {
  const client = await createClient();
  return client.post("/api/auth/login", { email, password });
}

// Asks for a reset link and returns the dev token.
async function requestResetToken(email) {
  const client = await createClient();
  const res = await client.post("/api/auth/forgot-password", { email });
  return res.body.devResetToken;
}

describe("POST /api/auth/forgot-password", () => {
  test("a real email gets the generic message and a dev token", async () => {
    const data = await createUser();
    const client = await createClient();
    const res = await client.post("/api/auth/forgot-password", { email: data.email });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/if an account/i);
    expect(res.body.devResetToken).toMatch(/^[a-f0-9]{64}$/);
  });

  test("an unknown email gets the SAME message and no token", async () => {
    const data = await createUser();
    const client = await createClient();

    const known = await client.post("/api/auth/forgot-password", { email: data.email });
    const unknown = await client.post("/api/auth/forgot-password", {
      email: "nobody@example.com",
    });

    expect(unknown.status).toBe(200);
    expect(unknown.body.message).toBe(known.body.message);
    expect(unknown.body).not.toHaveProperty("devResetToken");
  });

  test("only the token hash is stored, and it expires within an hour", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);

    const saved = await User.findOne({ email: data.email }).select(
      "+passwordResetTokenHash +passwordResetExpires"
    );
    expect(saved.passwordResetTokenHash).not.toBe(token);
    expect(saved.passwordResetTokenHash).toBe(hashToken(token));

    const msLeft = saved.passwordResetExpires.getTime() - Date.now();
    expect(msLeft).toBeGreaterThan(0);
    expect(msLeft).toBeLessThanOrEqual(60 * 60 * 1000);
  });

  test("rejects a badly formed email", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/forgot-password", { email: "not-an-email" });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/auth/reset-password", () => {
  test("resets the password: the new one works and the old one does not", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);

    const client = await createClient();
    const res = await client.post("/api/auth/reset-password", {
      token,
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(200);

    expect((await tryLogin(data.email, data.password)).status).toBe(401);
    expect((await tryLogin(data.email, NEW_PASSWORD)).status).toBe(200);
  });

  test("a reset token can only be used once", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);
    const client = await createClient();

    const first = await client.post("/api/auth/reset-password", {
      token,
      newPassword: NEW_PASSWORD,
    });
    const second = await client.post("/api/auth/reset-password", {
      token,
      newPassword: "AnotherPass789",
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(400);
    // The second attempt must not have changed the password.
    expect((await tryLogin(data.email, NEW_PASSWORD)).status).toBe(200);
  });

  test("an expired token is rejected", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);

    await User.updateOne(
      { email: data.email },
      { $set: { passwordResetExpires: new Date(Date.now() - 1000) } }
    );

    const client = await createClient();
    const res = await client.post("/api/auth/reset-password", {
      token,
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(400);
    expect((await tryLogin(data.email, data.password)).status).toBe(200);
  });

  test("a weak new password is rejected, and the token still works afterwards", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);
    const client = await createClient();

    const weak = await client.post("/api/auth/reset-password", {
      token,
      newPassword: "short",
    });
    expect(weak.status).toBe(400);

    const good = await client.post("/api/auth/reset-password", {
      token,
      newPassword: NEW_PASSWORD,
    });
    expect(good.status).toBe(200);
  });

  test("a made-up token is rejected", async () => {
    await createUser();
    const client = await createClient();
    const res = await client.post("/api/auth/reset-password", {
      token: "b".repeat(64),
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(400);
  });

  test("a reset logs the user out of every session", async () => {
    const data = await createUser();
    const a = await loggedInClient(data);
    const b = await loggedInClient(data);

    expect((await a.client.get("/api/auth/me")).status).toBe(200);
    expect((await b.client.get("/api/auth/me")).status).toBe(200);

    const token = await requestResetToken(data.email);
    const other = await createClient();
    const reset = await other.post("/api/auth/reset-password", {
      token,
      newPassword: NEW_PASSWORD,
    });
    expect(reset.status).toBe(200);

    expect((await a.client.get("/api/auth/me")).status).toBe(401);
    expect((await b.client.get("/api/auth/me")).status).toBe(401);
  });
});

describe("POST /api/auth/change-password", () => {
  test("needs a login", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/change-password", {
      currentPassword: "Passw0rdLong1",
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(401);
  });

  test("rejects a wrong current password", async () => {
    const data = await createUser();
    const { client } = await loggedInClient(data);

    const res = await client.post("/api/auth/change-password", {
      currentPassword: "WrongOne123",
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/current password is incorrect/i);
  });

  test("rejects a new password that is the same as the current one", async () => {
    const data = await createUser();
    const { client } = await loggedInClient(data);

    const res = await client.post("/api/auth/change-password", {
      currentPassword: data.password,
      newPassword: data.password,
    });
    expect(res.status).toBe(400);
  });

  test("rejects a weak new password", async () => {
    const data = await createUser();
    const { client } = await loggedInClient(data);

    const res = await client.post("/api/auth/change-password", {
      currentPassword: data.password,
      newPassword: "short",
    });
    expect(res.status).toBe(400);
  });

  test("changes the password, keeps this session, and logs out the others", async () => {
    const data = await createUser();
    const a = await loggedInClient(data);
    const b = await loggedInClient(data);

    const res = await a.client.post("/api/auth/change-password", {
      currentPassword: data.password,
      newPassword: NEW_PASSWORD,
    });
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toMatch(/^[a-f0-9]{64}$/);

    // This session (A) still works. The other one (B) is logged out.
    expect((await a.client.get("/api/auth/me")).status).toBe(200);
    expect((await b.client.get("/api/auth/me")).status).toBe(401);

    expect((await tryLogin(data.email, data.password)).status).toBe(401);
    expect((await tryLogin(data.email, NEW_PASSWORD)).status).toBe(200);
  });

  test("a password change cancels any older reset link", async () => {
    const data = await createUser();
    const token = await requestResetToken(data.email);

    const { client } = await loggedInClient(data);
    const changed = await client.post("/api/auth/change-password", {
      currentPassword: data.password,
      newPassword: NEW_PASSWORD,
    });
    expect(changed.status).toBe(200);

    const other = await createClient();
    const res = await other.post("/api/auth/reset-password", {
      token,
      newPassword: "AnotherPass789",
    });
    expect(res.status).toBe(400);
  });
});