// tests/health.test.js
// A first, simple test file. It needs no database.

const request = require("supertest");
const app = require("../src/app");

describe("health and basic security", () => {
  test("GET /api/health says the backend is ok", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
  });

  test("an unknown route returns 404", async () => {
    const res = await request(app).get("/api/does-not-exist");
    expect(res.status).toBe(404);
  });

  test("a POST without a CSRF token is blocked with 403", async () => {
    const res = await request(app).post("/api/auth/login").send({});
    expect(res.status).toBe(403);
  });

  test("Helmet security headers are present", async () => {
    const res = await request(app).get("/api/health");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  test("the session cookie is HttpOnly and SameSite=Lax", async () => {
    const res = await request(app).get("/api/auth/csrf-token");
    const cookie = res.headers["set-cookie"].join(";");
    expect(cookie).toMatch(/ptbc\.sid=/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
  });
});