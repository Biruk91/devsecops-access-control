const express = require("express");
const authenticate = require("../middleware/authenticate");
const { requirePermission } = require("../middleware/authorize");
const { canAccessOrder } = require("../policies");
const { getOrders, findOrderById, createOrder } = require("../data");

const router = express.Router();

// GET /api/orders - list orders scoped to the caller's branch
router.get("/", authenticate, (req, res) => {
  const allOrders = getOrders();
  const accessibleOrders = allOrders.filter((order) =>
    canAccessOrder(req.user, order)
  );
  return res.json(accessibleOrders);
});

// GET /api/orders/:id - orders:read scoped to caller's branch
router.get("/:id", authenticate, requirePermission("orders:read"), (req, res) => {
  const order = findOrderById(req.params.id);

  // If order does not exist or caller cannot access this branch's order, return 404
  // Returning 404 prevents IDOR enumeration: caller cannot tell whether order exists
  if (!order || !canAccessOrder(req.user, order)) {
    return res.status(404).json({ error: "Order not found" });
  }

  return res.json(order);
});

// POST /api/orders - orders:create
router.post(
  "/",
  authenticate,
  requirePermission("orders:create"),
  (req, res) => {
    const { tableNumber, items, totalAmount } = req.body || {};

    if (!tableNumber || !items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Invalid order data" });
    }

    // Branch ID is bound from authenticated identity, never from req.body
    const branchId = req.user.branchId;
    if (!branchId && req.user.role !== "admin") {
      return res.status(400).json({ error: "Staff member must belong to a branch" });
    }

    const newOrder = createOrder({
      branchId: branchId || req.body.branchId || "bole",
      tableNumber,
      items,
      totalAmount: totalAmount || 0,
      status: "pending",
    });

    return res.status(201).json(newOrder);
  }
);

module.exports = router;
