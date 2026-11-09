const express = require("express");
const { requestIdMiddleware } = require("./middleware/requestId");
const { metricsMiddleware } = require("./metrics");
const { logSecurityEvent } = require("./events");
const authRoutes = require("./routes/auth");
const orderRoutes = require("./routes/orders");
const paymentRoutes = require("./routes/payments");
const reportRoutes = require("./routes/reports");
const adminRoutes = require("./routes/admin");

const app = express();

app.use(express.json());
app.use(requestIdMiddleware);
app.use(metricsMiddleware);

// Mount API routes
app.use("/api/auth", authRoutes);
app.use("/api/orders", orderRoutes);
app.use("/api/payments", paymentRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/admin", adminRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "DineDesk API" });
});

// Controlled error test endpoint for server error verification
app.get("/api/test/error", (req, res, next) => {
  const testError = new Error("Controlled test server failure");
  testError.name = "TestError";
  next(testError);
});

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Global 500 error handler
// Returns generic message and requestId to client - never a stack trace!
app.use((err, req, res, next) => {
  logSecurityEvent(req, "server_error", {
    errorName: err.name || "Error",
    errorMessage: err.message,
    stack: err.stack,
  });

  res.status(500).json({
    error: "Internal server error",
    requestId: req.id,
  });
});

module.exports = app;
