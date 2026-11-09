const pino = require("pino");

const capturedLogs = [];
const rawCapturedChunks = [];
let isCapturing = false;

const customDestination = {
  write(msg) {
    if (isCapturing) {
      rawCapturedChunks.push(msg);
      try {
        capturedLogs.push(JSON.parse(msg));
      } catch (e) {
        capturedLogs.push({ raw: msg });
      }
    }
    // Only output to stdout when not in test or if DEBUG_LOGS is explicitly set
    if (process.env.NODE_ENV !== "test" || process.env.DEBUG_LOGS) {
      process.stdout.write(msg);
    }
  },
};

const logger = pino(
  {
    level: process.env.LOG_LEVEL || "info",
    base: { service: "dinedesk-api" },
    timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,
    formatters: {
      level: (label) => ({ level: label }),
    },
    redact: {
      paths: [
        "password",
        "*.password",
        "token",
        "*.token",
        "authorization",
        "*.authorization",
        "cookie",
        "*.cookie",
        "secret",
        "*.secret",
        "hash",
        "*.hash",
        "passwordHash",
        "*.passwordHash",
      ],
      censor: "[REDACTED]",
    },
  },
  customDestination
);

// Test helper methods to capture and inspect log lines in memory
logger.startCapture = () => {
  capturedLogs.length = 0;
  rawCapturedChunks.length = 0;
  isCapturing = true;
};

logger.stopCapture = () => {
  isCapturing = false;
};

logger.getCapturedLogs = () => [...capturedLogs];

logger.getRawCapturedOutput = () => rawCapturedChunks.join("");

logger.clearCapturedLogs = () => {
  capturedLogs.length = 0;
  rawCapturedChunks.length = 0;
};

module.exports = logger;
