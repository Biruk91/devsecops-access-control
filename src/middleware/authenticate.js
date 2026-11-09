const jwt = require("jsonwebtoken");
const config = require("../config");
const { findUserById } = require("../data");

function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const parts = authHeader.trim().split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer" || !parts[1]) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Missing or malformed Bearer token" });
  }

  const token = parts[1];

  let payload;
  try {
    payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: ["HS256"], // Strictly reject "alg": "none" and algorithm confusion
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });
  } catch (err) {
    // Expired, forged, wrong key, or mismatched claims: all return 401
    return res
      .status(401)
      .json({ error: "Unauthorized: Invalid or expired token" });
  }

  // Re-verify against authoritative user records; never trust client headers or body
  const userRecord = findUserById(payload.sub);
  if (!userRecord) {
    return res
      .status(401)
      .json({ error: "Unauthorized: User account not found or inactive" });
  }

  // Attach verified user identity from our server records
  req.user = {
    id: userRecord.id,
    email: userRecord.email,
    role: userRecord.role,
    branchId: userRecord.branchId,
  };

  next();
}

module.exports = authenticate;
