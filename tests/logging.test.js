const request = require("supertest");
const jwt = require("jsonwebtoken");
const app = require("../src/app");
const config = require("../src/config");
const logger = require("../src/logger");
const { register } = require("../src/metrics");

// Helper function to create test JWT tokens
function createTestToken(userId, overrides = {}) {
  const secret = overrides.secret || config.JWT_SECRET;
  const payload = { sub: userId };
  const signOptions = {
    algorithm: "HS256",
    expiresIn: overrides.expiresIn || "15m",
    issuer:
      overrides.issuer !== undefined ? overrides.issuer : config.JWT_ISSUER,
    audience:
      overrides.audience !== undefined
        ? overrides.audience
        : config.JWT_AUDIENCE,
  };
  return jwt.sign(payload, secret, signOptions);
}

describe("Task 3 & 4 — Security Logging, Audit Trail, and Metrics Test Suite", () => {
  beforeEach(() => {
    logger.startCapture();
  });

  afterEach(() => {
    logger.stopCapture();
  });

  // Test 1: Failed login produces login_failed with right fields and no password
  test("1. Failed login produces login_failed log with userId for existing account and no password", async () => {
    const res = await request(app).post("/api/auth/login").send({
      email: "waiter.bole@dinedesk.et",
      password: "WrongPassword999!",
    });

    expect(res.status).toBe(401);
    const logs = logger.getCapturedLogs();
    const failLog = logs.find((l) => l.event === "login_failed");

    expect(failLog).toBeDefined();
    expect(failLog.level).toBe("warn");
    expect(failLog.service).toBe("dinedesk-api");
    expect(failLog.userId).toBe("u_waiter_bole");
    expect(failLog.requestId).toBeDefined();
    expect(JSON.stringify(failLog)).not.toContain("WrongPassword999!");
  });

  // Test 2: Failed login for unknown user does not log typed email
  test("2. Failed login for non-existent user produces login_failed with accountExists: false and no typed email", async () => {
    const typedEmail = "attacker_random_input@unknown.com";
    const res = await request(app).post("/api/auth/login").send({
      email: typedEmail,
      password: "SomePassword123!",
    });

    expect(res.status).toBe(401);
    const logs = logger.getCapturedLogs();
    const failLog = logs.find((l) => l.event === "login_failed");

    expect(failLog).toBeDefined();
    expect(failLog.accountExists).toBe(false);
    expect(failLog.userId).toBeUndefined();
    // Must not log the typed email to protect mistyped credentials in email field
    expect(JSON.stringify(failLog)).not.toContain(typedEmail);
  });

  // Test 3: Successful login produces login_succeeded
  test("3. Successful login produces login_succeeded with role and branch", async () => {
    const res = await request(app).post("/api/auth/login").send({
      email: "waiter.bole@dinedesk.et",
      password: "WaiterBole123!",
    });

    expect(res.status).toBe(200);
    const logs = logger.getCapturedLogs();
    const successLog = logs.find((l) => l.event === "login_succeeded");

    expect(successLog).toBeDefined();
    expect(successLog.level).toBe("info");
    expect(successLog.userId).toBe("u_waiter_bole");
    expect(successLog.role).toBe("waiter");
    expect(successLog.branch).toBe("bole");
    expect(JSON.stringify(successLog)).not.toContain("WaiterBole123!");
  });

  // Test 4: Missing token produces authentication_failed
  test("4. Missing Authorization header produces authentication_failed with reason missing_token", async () => {
    const res = await request(app).get("/api/orders");
    expect(res.status).toBe(401);

    const logs = logger.getCapturedLogs();
    const authFailLog = logs.find((l) => l.event === "authentication_failed");

    expect(authFailLog).toBeDefined();
    expect(authFailLog.level).toBe("warn");
    expect(authFailLog.reason).toBe("missing_token");
  });

  // Test 5: 403 Forbidden produces authorization_denied with userId and role
  test("5. A 403 produces authorization_denied with userId, role, and required privileges", async () => {
    const token = createTestToken("u_waiter_bole");
    const res = await request(app)
      .get("/api/admin/users")
      .set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(403);
    const logs = logger.getCapturedLogs();
    const deniedLog = logs.find((l) => l.event === "authorization_denied");

    expect(deniedLog).toBeDefined();
    expect(deniedLog.level).toBe("warn");
    expect(deniedLog.userId).toBe("u_waiter_bole");
    expect(deniedLog.role).toBe("waiter");
    expect(deniedLog.required).toBe("role:admin");
  });

  // Test 6: Cross-branch order request produces branch_access_denied
  test("6. Cross-branch order request produces branch_access_denied with branch IDs and orderId", async () => {
    const boleManagerToken = createTestToken("u_manager_bole");
    // ord_piassa_201 belongs to Piassa branch
    const res = await request(app)
      .get("/api/orders/ord_piassa_201")
      .set("Authorization", `Bearer ${boleManagerToken}`);

    // Client gets 404 to prevent IDOR enumeration
    expect(res.status).toBe(404);

    const logs = logger.getCapturedLogs();
    const branchLog = logs.find((l) => l.event === "branch_access_denied");

    expect(branchLog).toBeDefined();
    expect(branchLog.level).toBe("warn");
    expect(branchLog.userId).toBe("u_manager_bole");
    expect(branchLog.userBranch).toBe("bole");
    expect(branchLog.targetBranch).toBe("piassa");
    expect(branchLog.orderId).toBe("ord_piassa_201");
  });

  // Test 7: Audit event for successful administrative action
  test("7. Audit event: Admin changing staff role produces user_role_changed with outcome success and before/after", async () => {
    const adminToken = createTestToken("u_admin");
    const res = await request(app)
      .put("/api/admin/users/u_waiter_piassa/role")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ role: "manager" });

    expect(res.status).toBe(200);

    const logs = logger.getCapturedLogs();
    const auditLog = logs.find(
      (l) => l.event === "user_role_changed" && l.outcome === "success"
    );

    expect(auditLog).toBeDefined();
    expect(auditLog.level).toBe("info");
    expect(auditLog.audit).toBe(true);
    expect(auditLog.actor).toBe("u_admin");
    expect(auditLog.target).toBe("u_waiter_piassa");
    expect(auditLog.from).toBe("waiter");
    expect(auditLog.to).toBe("manager");
    expect(auditLog.outcome).toBe("success");
  });

  // Test 8: Audit event for rejected administrative action
  test("8. Audit event: Non-admin changing staff role produces user_role_changed with outcome denied", async () => {
    const waiterToken = createTestToken("u_waiter_bole");
    const res = await request(app)
      .put("/api/admin/users/u_cashier_bole/role")
      .set("Authorization", `Bearer ${waiterToken}`)
      .send({ role: "admin" });

    expect(res.status).toBe(403);

    const logs = logger.getCapturedLogs();
    const auditLog = logs.find(
      (l) => l.event === "user_role_changed" && l.outcome === "denied"
    );

    expect(auditLog).toBeDefined();
    expect(auditLog.level).toBe("warn");
    expect(auditLog.audit).toBe(true);
    expect(auditLog.actor).toBe("u_waiter_bole");
    expect(auditLog.target).toBe("u_cashier_bole");
    expect(auditLog.outcome).toBe("denied");
  });

  // Test 9: Server error log line and response share the same request id and no stack trace in response
  test("9. Server error response and log share the same request id, response hides stack trace", async () => {
    const res = await request(app).get("/api/test/error");

    expect(res.status).toBe(500);
    expect(res.body.error).toBe("Internal server error");
    expect(res.body.requestId).toBeDefined();
    expect(res.body.stack).toBeUndefined();

    const logs = logger.getCapturedLogs();
    const errorLog = logs.find((l) => l.event === "server_error");

    expect(errorLog).toBeDefined();
    expect(errorLog.level).toBe("error");
    expect(errorLog.requestId).toBe(res.body.requestId);
    expect(errorLog.errorName).toBe("TestError");
    expect(errorLog.stack).toBeDefined(); // Internal log keeps stack trace for debugging
  });

  // Test 10: Incoming valid X-Request-Id is reused; invalid is replaced
  test("10. Request ID handling: strict UUIDv4 is reused, malformed is replaced", async () => {
    const validUuid = "12345678-1234-4234-8234-123456789abc";
    const res1 = await request(app)
      .get("/health")
      .set("X-Request-Id", validUuid);

    expect(res1.headers["x-request-id"]).toBe(validUuid);

    // Malformed request id containing injection / bad format
    const res2 = await request(app)
      .get("/health")
      .set("X-Request-Id", "malicious-id; DROP TABLE users;");

    expect(res2.headers["x-request-id"]).not.toBe(
      "malicious-id; DROP TABLE users;"
    );
    expect(res2.headers["x-request-id"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  // Test 11: Route pattern normalization in Prometheus metrics
  test("11. Route pattern normalization: /api/orders/1 and /api/orders/2 are counted under route pattern /api/orders/:id", async () => {
    const boleManagerToken = createTestToken("u_manager_bole");

    await request(app)
      .get("/api/orders/ord_bole_101")
      .set("Authorization", `Bearer ${boleManagerToken}`);

    await request(app)
      .get("/api/orders/ord_bole_102")
      .set("Authorization", `Bearer ${boleManagerToken}`);

    const metricsOutput = await register.metrics();

    // Verify both calls were recorded under /api/orders/:id pattern
    expect(metricsOutput).toContain(
      'http_requests_total{method="GET",route="/api/orders/:id",status_code="200"}'
    );
    // Verify specific IDs are not exposed as label values (preventing cardinality explosion)
    expect(metricsOutput).not.toContain('route="/api/orders/ord_bole_101"');
    expect(metricsOutput).not.toContain('route="/api/orders/ord_bole_102"');
  });

  // Test 12: API port does not serve /metrics (returns 404)
  test("12. Port isolation: GET /metrics on the main API port returns 404 Not Found", async () => {
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(404);
  });

  // Test 13: Negative Secret Leak Test
  test("13. NEGATIVE CHECK: Asserts password, raw token, and JWT secret appear NOWHERE in captured logs", async () => {
    const plainPassword = "WaiterBole123!";

    // Step A: Login request
    const loginRes = await request(app).post("/api/auth/login").send({
      email: "waiter.bole@dinedesk.et",
      password: plainPassword,
    });
    expect(loginRes.status).toBe(200);
    const token = loginRes.body.token;
    expect(token).toBeDefined();

    // Step B: Authenticated request using the token
    const orderRes = await request(app)
      .get("/api/orders")
      .set("Authorization", `Bearer ${token}`);
    expect(orderRes.status).toBe(200);

    // Step C: Inspect all raw output captured by the logger
    const rawOutput = logger.getRawCapturedOutput();

    // 1. Password must never appear in log output
    expect(rawOutput).not.toContain(plainPassword);

    // 2. Raw JWT Bearer token must never appear in log output
    expect(rawOutput).not.toContain(token);
    expect(rawOutput).not.toContain(`Bearer ${token}`);

    // 3. Application signing key must never appear in log output
    expect(rawOutput).not.toContain(config.JWT_SECRET);
  });
});
