const bcrypt = require("bcryptjs");

// Pre-computed dummy hash for constant-time comparison when email is not found
const DUMMY_HASH = bcrypt.hashSync("dummy_password_timing_defense", 10);

const users = [
  {
    id: "u_waiter_bole",
    name: "Abebe Waiter",
    email: "waiter.bole@dinedesk.et",
    passwordHash: bcrypt.hashSync("WaiterBole123!", 10),
    role: "waiter",
    branchId: "bole",
  },
  {
    id: "u_waiter_piassa",
    name: "Chala Waiter",
    email: "waiter.piassa@dinedesk.et",
    passwordHash: bcrypt.hashSync("WaiterPiassa123!", 10),
    role: "waiter",
    branchId: "piassa",
  },
  {
    id: "u_cashier_bole",
    name: "Bethlehem Cashier",
    email: "cashier.bole@dinedesk.et",
    passwordHash: bcrypt.hashSync("CashierBole123!", 10),
    role: "cashier",
    branchId: "bole",
  },
  {
    id: "u_cashier_piassa",
    name: "Dawit Cashier",
    email: "cashier.piassa@dinedesk.et",
    passwordHash: bcrypt.hashSync("CashierPiassa123!", 10),
    role: "cashier",
    branchId: "piassa",
  },
  {
    id: "u_manager_bole",
    name: "Marta Manager",
    email: "manager.bole@dinedesk.et",
    passwordHash: bcrypt.hashSync("ManagerBole123!", 10),
    role: "manager",
    branchId: "bole",
  },
  {
    id: "u_manager_piassa",
    name: "Yonas Manager",
    email: "manager.piassa@dinedesk.et",
    passwordHash: bcrypt.hashSync("ManagerPiassa123!", 10),
    role: "manager",
    branchId: "piassa",
  },
  {
    id: "u_admin",
    name: "Sara Admin",
    email: "admin@dinedesk.et",
    passwordHash: bcrypt.hashSync("AdminSecret2026!", 10),
    role: "admin",
    branchId: null, // Admin oversees the entire chain
  },
];

let orders = [
  {
    id: "ord_bole_101",
    branchId: "bole",
    tableNumber: 4,
    items: [{ name: "Kitfo Special", price: 350, quantity: 2 }],
    totalAmount: 700,
    status: "completed",
    createdAt: "2026-11-09T10:15:00.000Z",
  },
  {
    id: "ord_bole_102",
    branchId: "bole",
    tableNumber: 7,
    items: [{ name: "Beef Tibs", price: 300, quantity: 1 }],
    totalAmount: 300,
    status: "pending",
    createdAt: "2026-11-09T11:30:00.000Z",
  },
  {
    id: "ord_piassa_201",
    branchId: "piassa",
    tableNumber: 2,
    items: [{ name: "Beyaynetu Fasting", price: 180, quantity: 2 }],
    totalAmount: 360,
    status: "completed",
    createdAt: "2026-11-09T09:45:00.000Z",
  },
  {
    id: "ord_piassa_202",
    branchId: "piassa",
    tableNumber: 5,
    items: [{ name: "Tegabino Shiro", price: 150, quantity: 1 }],
    totalAmount: 150,
    status: "pending",
    createdAt: "2026-11-09T12:00:00.000Z",
  },
];

let payments = [
  {
    id: "pay_001",
    orderId: "ord_bole_101",
    branchId: "bole",
    amount: 700,
    paymentMethod: "card",
    status: "successful",
    createdAt: "2026-11-09T10:45:00.000Z",
  },
  {
    id: "pay_002",
    orderId: "ord_piassa_201",
    branchId: "piassa",
    amount: 360,
    paymentMethod: "telebirr",
    status: "successful",
    createdAt: "2026-11-09T10:15:00.000Z",
  },
];

function findUserByEmail(email) {
  return users.find((u) => u.email.toLowerCase() === (email || "").toLowerCase());
}

function findUserById(id) {
  return users.find((u) => u.id === id);
}

function getAllUsersSafe() {
  // Never expose password hashes
  return users.map(({ passwordHash, ...safeUser }) => safeUser);
}

function findOrderById(id) {
  return orders.find((o) => o.id === id);
}

function getOrders() {
  return orders;
}

function createOrder(orderData) {
  const newOrder = {
    id: `ord_${orderData.branchId}_${Date.now()}`,
    ...orderData,
    createdAt: new Date().toISOString(),
  };
  orders.push(newOrder);
  return newOrder;
}

function createPayment(paymentData) {
  const newPayment = {
    id: `pay_${Date.now()}`,
    ...paymentData,
    createdAt: new Date().toISOString(),
  };
  payments.push(newPayment);
  return newPayment;
}

function getPayments() {
  return payments;
}

module.exports = {
  users,
  DUMMY_HASH,
  findUserByEmail,
  findUserById,
  getAllUsersSafe,
  findOrderById,
  getOrders,
  createOrder,
  createPayment,
  getPayments,
};
