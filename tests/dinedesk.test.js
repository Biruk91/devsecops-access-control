const request = require("supertest");
const jwt = require("jsonwebtoken");
const app = require("../src/app");
const config = require("../src/config");

// Helper function to create test tokens with controllable attributes
function createTestToken(userId, overrides = {}) {
  const secret = overrides.secret || config.JWT_SECRET;
  const payload = { sub: userId };
  const signOptions = {
    algorithm: "HS256",
    expiresIn: overrides.expiresIn || "15m",
    issuer: overrides.issuer !== undefined ? overrides.issuer : config.JWT_ISSUER,
    audience: overrides.audience !== undefined ? overrides.audience : config.JWT_AUDIENCE,
  };
  return jwt.sign(payload, secret, signOptions);
}

describe("DineDesk Access Control & Security Test Suite", () => {
  // Test 1: Missing token -> 401
  test("1. Request with no token returns 401 Unauthorized", async () => {
    const res = await request(app).get("/api/orders");
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  // Test 2: Token signed with wrong key -> 401
  test("2. Token signed with wrong key returns 401 Unauthorized", async () => {
    const forgedToken = createTestToken("u_waiter_bole", {
      secret: "malicious_attacker_key_that_does_not_match_the_real_secret_at_all",
    });
    const res = await request(app)
      .get("/api/orders")
      .set("Authorization", `Bearer ${forgedToken}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  // Test 3: Expired token -> 401
  test("3. Expired token returns 401 Unauthorized", async () => {
    const expiredToken = createTestToken("u_waiter_bole", {
      expiresIn: "-10s",
    });
    const res = await request(app)
      .get("/api/orders")
      .set("Authorization", `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  // Test 4: Waiter calling GET /api/admin/users -> 403
  test("4. Waiter calling GET /api/admin/users returns 403 Forbidden", async () => {
    const waiterToken = createTestToken("u_waiter_bole");
    const res = await request(app)
      .get("/api/admin/users")
      .set("Authorization", `Bearer ${waiterToken}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden/i);
  });

  // Test 5: Administrator calling GET /api/admin/users -> 200, no password hashes
  test("5. Administrator calling GET /api/admin/users returns 200 with no password hashes", async () => {
    const adminToken = createTestToken("u_admin");
    const res = await request(app)
      .get("/api/admin/users")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);

    // Verify absolutely no password hashes or sensitive fields are leaked
    res.body.forEach((user) => {
      expect(user).toHaveProperty("id");
      expect(user).toHaveProperty("email");
      expect(user).toHaveProperty("role");
      expect(user.passwordHash).toBeUndefined();
      expect(user.password).toBeUndefined();
    });
  });

  // Test 6: Waiter creating an order -> 201
  test("6. Waiter creating an order returns 201 Created", async () => {
    const waiterToken = createTestToken("u_waiter_bole");
    const res = await request(app)
      .post("/api/orders")
      .set("Authorization", `Bearer ${waiterToken}`)
      .send({
        tableNumber: 8,
        items: [{ name: "Kitfo Special", price: 350, quantity: 1 }],
        totalAmount: 350,
      });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body.branchId).toBe("bole");
    expect(res.body.tableNumber).toBe(8);
  });

  // Test 7: Cashier creating an order -> 403
  test("7. Cashier creating an order returns 403 Forbidden", async () => {
    const cashierToken = createTestToken("u_cashier_bole");
    const res = await request(app)
      .post("/api/orders")
      .set("Authorization", `Bearer ${cashierToken}`)
      .send({
        tableNumber: 3,
        items: [{ name: "Beef Tibs", price: 300, quantity: 1 }],
        totalAmount: 300,
      });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden/i);
  });

  // Test 8: Bole manager reading a Bole order -> 200
  test("8. Bole manager reading a Bole order returns 200 OK", async () => {
    const boleManagerToken = createTestToken("u_manager_bole");
    const res = await request(app)
      .get("/api/orders/ord_bole_101")
      .set("Authorization", `Bearer ${boleManagerToken}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe("ord_bole_101");
    expect(res.body.branchId).toBe("bole");
  });

  // Test 9: Bole manager reading a Piassa order -> 404 (denied & un-enumerable)
  test("9. Bole manager reading a Piassa order returns 404 (denied & un-enumerable)", async () => {
    const boleManagerToken = createTestToken("u_manager_bole");
    const res = await request(app)
      .get("/api/orders/ord_piassa_201")
      .set("Authorization", `Bearer ${boleManagerToken}`);
    // 404 prevents IDOR enumeration: caller cannot tell whether the order exists
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  // Test 10: Waiter calling GET /api/reports/branch -> 403
  test("10. Waiter calling GET /api/reports/branch returns 403 Forbidden", async () => {
    const waiterToken = createTestToken("u_waiter_bole");
    const res = await request(app)
      .get("/api/reports/branch")
      .set("Authorization", `Bearer ${waiterToken}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden/i);
  });

  // Test 11: Piassa manager calling /api/reports/branch?branchId=bole -> returns only Piassa data
  test("11. Piassa manager querying ?branchId=bole still receives only Piassa report data", async () => {
    const piassaManagerToken = createTestToken("u_manager_piassa");
    const res = await request(app)
      .get("/api/reports/branch?branchId=bole")
      .set("Authorization", `Bearer ${piassaManagerToken}`);
    expect(res.status).toBe(200);
    expect(res.body.branch).toBe("piassa"); // Ignored query param; stayed locked to caller's branch
  });

  // Test 12: Missing or malformed Bearer prefix -> 401
  test("12. Malformed Authorization header scheme returns 401 Unauthorized", async () => {
    const token = createTestToken("u_waiter_bole");
    const res = await request(app)
      .get("/api/orders")
      .set("Authorization", `Basic ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  // Test 13: Mismatched audience -> 401
  test("13. Token with invalid audience returns 401 Unauthorized", async () => {
    const badAudToken = createTestToken("u_waiter_bole", {
      audience: "unauthorized-external-api",
    });
    const res = await request(app)
      .get("/api/orders")
      .set("Authorization", `Bearer ${badAudToken}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  // Test 14: Cashier creating a payment -> 201
  test("14. Cashier creating a payment returns 201 Created", async () => {
    const cashierToken = createTestToken("u_cashier_bole");
    const res = await request(app)
      .post("/api/payments")
      .set("Authorization", `Bearer ${cashierToken}`)
      .send({
        orderId: "ord_bole_101",
        amount: 700,
        paymentMethod: "card",
      });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body.amount).toBe(700);
  });

  // Test 15: Waiter creating a payment -> 403
  test("15. Waiter creating a payment returns 403 Forbidden", async () => {
    const waiterToken = createTestToken("u_waiter_bole");
    const res = await request(app)
      .post("/api/payments")
      .set("Authorization", `Bearer ${waiterToken}`)
      .send({
        orderId: "ord_bole_101",
        amount: 700,
      });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden/i);
  });

  // Test 16: Bole manager listing orders -> sees only Bole branch orders
  test("16. Bole manager listing orders receives only Bole orders", async () => {
    const boleManagerToken = createTestToken("u_manager_bole");
    const res = await request(app)
      .get("/api/orders")
      .set("Authorization", `Bearer ${boleManagerToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.every((o) => o.branchId === "bole")).toBe(true);
  });
});
