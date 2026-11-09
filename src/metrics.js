const client = require("prom-client");
const http = require("http");

// Create dedicated Prometheus registry
const register = new client.Registry();

// Collect Node.js default process and runtime metrics
client.collectDefaultMetrics({ register });

// http_requests_total counter
const httpRequestsTotal = new client.Counter({
  name: "http_requests_total",
  help: "Total number of HTTP requests processed",
  labelNames: ["method", "route", "status_code"],
  registers: [register],
});

// security_events_total counter
const securityEventsCounter = new client.Counter({
  name: "security_events_total",
  help: "Total number of security events logged",
  labelNames: ["event"],
  registers: [register],
});

// Normalize route to its parameterized pattern
function getRoutePattern(req) {
  // If Express matched a route definition
  if (req.route && req.route.path) {
    const baseUrl = req.baseUrl || "";
    const cleanPath = `${baseUrl}${req.route.path}`.replace(/\/+/g, "/");
    return cleanPath;
  }

  // Fallback pattern matching for common parametrized paths
  const rawPath = (req.originalUrl || req.url || "/").split("?")[0];
  if (/^\/api\/orders\/[^\/]+$/.test(rawPath)) {
    return "/api/orders/:id";
  }
  if (/^\/api\/admin\/users\/[^\/]+\/role$/.test(rawPath)) {
    return "/api/admin/users/:id/role";
  }
  if (/^\/api\/reports\/branch$/.test(rawPath)) {
    return "/api/reports/branch";
  }
  return rawPath;
}

// Middleware to record request metrics
function metricsMiddleware(req, res, next) {
  res.on("finish", () => {
    const route = getRoutePattern(req);
    httpRequestsTotal.inc({
      method: req.method,
      route,
      status_code: res.statusCode.toString(),
    });
  });
  next();
}

// Dedicated metrics HTTP server (isolated on separate port)
let metricsServer = null;

function startMetricsServer(port = 9090, host = "127.0.0.1") {
  if (metricsServer) return metricsServer;

  metricsServer = http.createServer(async (req, res) => {
    if (req.url === "/metrics" && req.method === "GET") {
      try {
        res.setHeader("Content-Type", register.contentType);
        const data = await register.metrics();
        res.writeHead(200);
        res.end(data);
      } catch (err) {
        res.writeHead(500);
        res.end(err.message);
      }
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    }
  });

  metricsServer.listen(port, host, () => {
    // Isolated metrics server running on host:port
  });

  return metricsServer;
}

function stopMetricsServer() {
  return new Promise((resolve) => {
    if (metricsServer) {
      metricsServer.close(() => {
        metricsServer = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

module.exports = {
  register,
  httpRequestsTotal,
  securityEventsCounter,
  metricsMiddleware,
  getRoutePattern,
  startMetricsServer,
  stopMetricsServer,
};
