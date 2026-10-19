// tests/auth.csrf.test.js
// Tests for CSRF protection. These need no database.

const request = require("supertest");
const app = require("../src/app");

const POST_ENDPOINTS = [
  "/api/auth/register",
  "/api/auth/verify-email",
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/forgot-password",
  "/api/auth/reset-password",
  "/api/auth/change-password",
];

describe("CSRF protection", () => {
  test.each(POST_ENDPOINTS)("POST %s is blocked without a token", async (url) => {
    const res = await request(app).post(url).send({});
    expect(res.status).toBe(403);
    expect(res.body.message).toMatch(/CSRF/i);
  });

  test("a wrong token is blocked", async () => {
    const agent = request.agent(app);
    await agent.get("/api/auth/csrf-token");

    const res = await agent
      .post("/api/auth/login")
      .set("x-csrf-token", "a".repeat(64))
      .send({});
    expect(res.status).toBe(403);
  });

  test("a token from a different session is blocked", async () => {
    const agentA = request.agent(app);
    const agentB = request.agent(app);

    const tokenA = (await agentA.get("/api/auth/csrf-token")).body.csrfToken;
    await agentB.get("/api/auth/csrf-token"); // B gets its own session and token

    const res = await agentB
      .post("/api/auth/login")
      .set("x-csrf-token", tokenA)
      .send({});
    expect(res.status).toBe(403);
  });

  test("GET requests do not need a token", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
  });

  test("the token endpoint returns a 64-character token and is not cached", async () => {
    const res = await request(app).get("/api/auth/csrf-token");
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toMatch(/^[a-f0-9]{64}$/);
    expect(res.headers["cache-control"]).toMatch(/no-store/);
  });
});