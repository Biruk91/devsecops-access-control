const express = require("express");
const authenticate = require("../middleware/authenticate");
const { requireRole } = require("../middleware/authorize");
const { getAllUsersSafe } = require("../data");

const router = express.Router();

// GET /api/admin/users - requireRole("admin")
// Strictly restricted to users with the admin role; never returns password hashes
router.get("/users", authenticate, requireRole("admin"), (req, res) => {
  const safeUsers = getAllUsersSafe();
  return res.json(safeUsers);
});

module.exports = router;
