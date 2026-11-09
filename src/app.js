const express = require("express");
const authRoutes = require("./routes/auth");
const orderRoutes = require("./routes/orders");
const paymentRoutes = require("./routes/payments");
const reportRoutes = require("./routes/reports");
const adminRoutes = require("./routes/admin");

const app = express();

app.use(express.json());

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

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

module.exports = app;
