const dotenv = require("dotenv");
dotenv.config();

function loadConfig() {
  const REQUIRED = ["JWT_SECRET"];
  const missing = REQUIRED.filter((key) => !process.env[key] || process.env[key].trim() === "");

  if (missing.length > 0) {
    throw new Error(`Configuration error: Missing required environment variable(s): ${missing.join(", ")}`);
  }

  if (process.env.JWT_SECRET.length < 32) {
    throw new Error("Configuration error: JWT_SECRET must be at least 32 characters long for security");
  }

  return {
    PORT: parseInt(process.env.PORT, 10) || 3000,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "15m",
    JWT_ISSUER: process.env.JWT_ISSUER || "dinedesk-api",
    JWT_AUDIENCE: process.env.JWT_AUDIENCE || "dinedesk-client",
  };
}

module.exports = loadConfig();
