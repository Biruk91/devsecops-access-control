const logger = require("./logger");
const { securityEventsCounter } = require("./metrics");

const EVENTS = {
  login_succeeded: "info",
  login_failed: "warn",
  authentication_failed: "warn",
  authorization_denied: "warn",
  branch_access_denied: "warn",
  user_role_changed: "info",
  server_error: "error",
};

/**
 * Emit a structured security log event and increment its Prometheus counter
 *
 * @param {Object} req - The Express request object (carries req.log and req.id)
 * @param {string} event - The security event name from the EVENTS catalog
 * @param {Object} details - Additional event-specific metadata
 */
function logSecurityEvent(req, event, details = {}) {
  let level = details.level || EVENTS[event];
  // Denied/rejected administrative audit events log at warn
  if (event === "user_role_changed" && details.outcome === "denied") {
    level = "warn";
  }

  if (!level) {
    throw new Error(`Unknown security event: ${event}`);
  }

  const logPayload = {
    event,
    ip: req.ip || req.socket?.remoteAddress || "127.0.0.1",
    path: (req.originalUrl || req.url || "").split("?")[0],
    method: req.method,
    ...details,
  };

  // Stamp requestId from req.log if available, or fallback to root logger
  if (req.log && typeof req.log[level] === "function") {
    req.log[level](logPayload);
  } else {
    logger[level]({ requestId: req.id || "no-request-id", ...logPayload });
  }

  // Increment Prometheus counter
  if (securityEventsCounter) {
    securityEventsCounter.inc({ event });
  }
}

module.exports = {
  EVENTS,
  logSecurityEvent,
};
