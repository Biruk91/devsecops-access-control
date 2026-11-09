const express = require("express");
const authenticate = require("../middleware/authenticate");
const { requirePermission } = require("../middleware/authorize");
const { getOrders } = require("../data");

const router = express.Router();

// GET /api/reports/branch - reports:read
// Branch is strictly derived from req.user.branchId, NEVER from req.query.branchId
router.get("/branch", authenticate, requirePermission("reports:read"), (req, res) => {
  const branchId =
    req.user.branchId || (req.user.role === "admin" ? req.query.branchId || "all" : null);

  if (!branchId) {
    return res.status(400).json({ error: "No branch associated with this user" });
  }

  const allOrders = getOrders();
  const branchOrders =
    branchId === "all"
      ? allOrders
      : allOrders.filter((o) => o.branchId === branchId);

  const totalRevenue = branchOrders.reduce(
    (sum, order) => sum + (order.totalAmount || 0),
    0
  );

  return res.json({
    branch: branchId,
    totalOrders: branchOrders.length,
    totalRevenue,
    generatedAt: new Date().toISOString(),
  });
});

module.exports = router;
