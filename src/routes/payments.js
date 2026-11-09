const express = require("express");
const authenticate = require("../middleware/authenticate");
const { requirePermission } = require("../middleware/authorize");
const { createPayment, findOrderById } = require("../data");

const router = express.Router();

// POST /api/payments - payments:create
router.post(
  "/",
  authenticate,
  requirePermission("payments:create"),
  (req, res) => {
    const { orderId, amount, paymentMethod } = req.body || {};

    if (!orderId || !amount) {
      return res.status(400).json({ error: "Missing required payment fields" });
    }

    const order = findOrderById(orderId);
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    const newPayment = createPayment({
      orderId,
      branchId: order.branchId,
      amount,
      paymentMethod: paymentMethod || "card",
      status: "successful",
    });

    return res.status(201).json(newPayment);
  }
);

module.exports = router;
