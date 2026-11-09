const config = require("./config");
const app = require("./app");
const logger = require("./logger");
const { startMetricsServer } = require("./metrics");

const PORT = config.PORT || 3000;
const METRICS_PORT = process.env.METRICS_PORT || 9090;

const server = app.listen(PORT, () => {
  logger.info({
    event: "service_started",
    port: PORT,
    environment: process.env.NODE_ENV || "development",
  });
  console.log(`DineDesk API server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});

// Start isolated metrics server on 127.0.0.1:9090
startMetricsServer(METRICS_PORT, "127.0.0.1");
console.log(`Prometheus metrics server listening on 127.0.0.1:${METRICS_PORT}/metrics`);

module.exports = server;
