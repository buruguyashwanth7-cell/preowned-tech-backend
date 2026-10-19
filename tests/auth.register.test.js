// tests/auth.register.test.js
// Tests for registration and email verification.

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

describe("POST /api/auth/register", () => {
  test("registers a buyer and never returns secrets", async () => {
    const client = await createClient();
    const body = newUser({ role: "buyer" });
    const res = await client.post("/api/auth/register", body);

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe(body.email);
    expect(res.body.user.role).toBe("buyer");
    expect(res.body.user.isEmailVerified).toBe(false);
    expect(res.body.user).not.toHaveProperty("passwordHash");
    expect(res.body.user).not.toHaveProperty("emailVerificationTokenHash");
    expect(res.body.devVerificationToken).toHaveLength(64);
  });

  test("registers a seller", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/register", newUser({ role: "seller" }));
    expect(res.status).toBe(201);
    expect(res.body.user.role).toBe("seller");
  });

  test("stores a bcrypt hash, not the password", async () => {
    const client = await createClient();
    const body = newUser();
    await client.post("/api/auth/register", body);

    const saved = await User.findOne({ email: body.email }).select("+passwordHash");
    expect(saved.passwordHash).not.toBe(body.password);
    expect(saved.passwordHash.startsWith("$2")).toBe(true);
  });

  test("cleans up the email (spaces and capital letters)", async () => {
    const client = await createClient();
    const res = await client.post(
      "/api/auth/register",
      newUser({ email: "  MiXeD.Case@Example.COM  " })
    );
    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe("mixed.case@example.com");
  });

  test.each(["admin", "moderator"])("refuses to register as %s", async (role) => {
    const client = await createClient();
    const res = await client.post("/api/auth/register", newUser({ role }));
    expect(res.status).toBe(400);
    expect(await User.countDocuments()).toBe(0);
  });

  test("rejects unexpected fields such as isEmailVerified", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/register", {
      ...newUser(),
      isEmailVerified: true,
    });
    expect(res.status).toBe(400);
    expect(await User.countDocuments()).toBe(0);
  });

  test.each(["short1", "onlyletterslong", "12345678901"])(
    "rejects the weak password %s",
    async (password) => {
      const client = await createClient();
      const res = await client.post("/api/auth/register", newUser({ password }));
      expect(res.status).toBe(400);
    }
  );

  test("rejects a duplicate email with 409", async () => {
    const client = await createClient();
    const body = newUser();
    expect((await client.post("/api/auth/register", body)).status).toBe(201);
    expect((await client.post("/api/auth/register", body)).status).toBe(409);
    expect(await User.countDocuments()).toBe(1);
  });
});

describe("POST /api/auth/verify-email", () => {
  async function registerUser(client) {
    const body = newUser();
    const res = await client.post("/api/auth/register", body);
    return { body, token: res.body.devVerificationToken };
  }

  test("verifies the email with a valid token", async () => {
    const client = await createClient();
    const { body, token } = await registerUser(client);

    const res = await client.post("/api/auth/verify-email", { token });
    expect(res.status).toBe(200);

    const saved = await User.findOne({ email: body.email });
    expect(saved.isEmailVerified).toBe(true);
  });

  test("a token can only be used once", async () => {
    const client = await createClient();
    const { token } = await registerUser(client);

    expect((await client.post("/api/auth/verify-email", { token })).status).toBe(200);
    expect((await client.post("/api/auth/verify-email", { token })).status).toBe(400);
  });

  test("an expired token is rejected", async () => {
    const client = await createClient();
    const { body, token } = await registerUser(client);

    // Pretend the token expired one second ago.
    await User.updateOne(
      { email: body.email },
      { $set: { emailVerificationExpires: new Date(Date.now() - 1000) } }
    );

    const res = await client.post("/api/auth/verify-email", { token });
    expect(res.status).toBe(400);

    const saved = await User.findOne({ email: body.email });
    expect(saved.isEmailVerified).toBe(false);
  });

  test("a made-up token is rejected", async () => {
    const client = await createClient();
    await registerUser(client);
    const res = await client.post("/api/auth/verify-email", { token: "a".repeat(64) });
    expect(res.status).toBe(400);
  });

  test("a badly formed token is rejected by validation", async () => {
    const client = await createClient();
    const res = await client.post("/api/auth/verify-email", { token: "abc" });
    expect(res.status).toBe(400);
  });

  test("only the token hash is stored in the database", async () => {
    const client = await createClient();
    const { body, token } = await registerUser(client);

    const saved = await User.findOne({ email: body.email }).select(
      "+emailVerificationTokenHash"
    );
    expect(saved.emailVerificationTokenHash).not.toBe(token);
    expect(saved.emailVerificationTokenHash).toBe(hashToken(token));
  });
});