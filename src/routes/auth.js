const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const config = require("../config");
const { findUserByEmail, DUMMY_HASH } = require("../data");

const router = express.Router();

router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  const user = findUserByEmail(email);

  // Timing-attack defense: compare against dummy hash even if user not found
  const hashToCompare = user ? user.passwordHash : DUMMY_HASH;
  const passwordMatch = await bcrypt.compare(password || "", hashToCompare);

  if (!user || !passwordMatch) {
    // Single generic error for unknown email or wrong password
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // Issue token with minimal claims (sub only), short expiry (15m), issuer, and audience
  // Completely ignores any role or branch sent in the request body
  const payload = {
    sub: user.id,
  };

  const token = jwt.sign(payload, config.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: config.JWT_EXPIRES_IN,
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
  });

  return res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      branchId: user.branchId,
    },
  });
});

module.exports = router;
