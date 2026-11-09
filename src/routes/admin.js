const express = require("express");
const authenticate = require("../middleware/authenticate");
const { requireRole } = require("../middleware/authorize");
const { getAllUsersSafe, findUserById, updateUserRole } = require("../data");
const { logSecurityEvent } = require("../events");

const router = express.Router();

// GET /api/admin/users - requireRole("admin")
// Strictly restricted to users with the admin role; never returns password hashes
router.get("/users", authenticate, requireRole("admin"), (req, res) => {
  const safeUsers = getAllUsersSafe();
  return res.json(safeUsers);
});

// PUT /api/admin/users/:id/role - Audit trail administrative action
// Updates a staff member's role and logs an audit trail event for both success and denied attempts
router.put("/users/:id/role", authenticate, (req, res) => {
  const targetUser = findUserById(req.params.id);
  const newRole = req.body?.role;

  // Rejected attempt check: caller is not an administrator
  if (!req.user || req.user.role !== "admin") {
    logSecurityEvent(req, "user_role_changed", {
      audit: true,
      actor: req.user?.id || "anonymous",
      target: req.params.id,
      action: "role_change",
      from: targetUser?.role || "unknown",
      to: newRole || "none",
      outcome: "denied",
      reason: "forbidden",
    });
    return res
      .status(403)
      .json({ error: "Forbidden: Admin privileges required" });
  }

  // Target user must exist
  if (!targetUser) {
    return res.status(404).json({ error: "User not found" });
  }

  const validRoles = ["waiter", "cashier", "manager", "admin"];
  if (!newRole || !validRoles.includes(newRole)) {
    return res.status(400).json({ error: "Invalid role specified" });
  }

  // Update role and capture before/after values
  const result = updateUserRole(req.params.id, newRole);

  // Successful administrative action audit event
  logSecurityEvent(req, "user_role_changed", {
    audit: true,
    actor: req.user.id,
    target: targetUser.id,
    action: "role_change",
    from: result.previousRole,
    to: result.user.role,
    outcome: "success",
  });

  return res.json({
    message: "Role updated successfully",
    user: {
      id: result.user.id,
      name: result.user.name,
      email: result.user.email,
      role: result.user.role,
      branchId: result.user.branchId,
    },
  });
});

module.exports = router;
