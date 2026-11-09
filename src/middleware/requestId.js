const crypto = require("crypto");
const logger = require("../logger");

// Strict UUIDv4 pattern regex
const UUIDV4_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

function requestIdMiddleware(req, res, next) {
  const incomingId = req.headers["x-request-id"];

  // Reuse only if valid strict UUIDv4; otherwise generate fresh UUIDv4
  const requestId =
    typeof incomingId === "string" && UUIDV4_REGEX.test(incomingId.trim())
      ? incomingId.trim()
      : crypto.randomUUID();

  req.id = requestId;
  res.setHeader("X-Request-Id", requestId);

  // Attach child logger so every log line for this request carries requestId
  req.log = logger.child({ requestId });

  next();
}

module.exports = {
  UUIDV4_REGEX,
  requestIdMiddleware,
};
