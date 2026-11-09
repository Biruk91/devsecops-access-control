/**
 * Policy function: Object-level authorization for orders
 * Non-admin staff may access only their own branch's orders.
 * Administrators can access any branch's orders.
 * Deny by default.
 *
 * @param {Object} user - The authenticated user object (from req.user)
 * @param {Object} order - The target order record
 * @returns {boolean} - True if access is permitted, false otherwise
 */
function canAccessOrder(user, order) {
  if (!user || !order) {
    return false;
  }

  // Administrators oversee the whole chain and can inspect orders across all branches
  if (user.role === "admin") {
    return true;
  }

  // Non-admin staff are strictly confined to their own branch's orders
  if (user.branchId && order.branchId && user.branchId === order.branchId) {
    return true;
  }

  // Deny by default
  return false;
}

module.exports = {
  canAccessOrder,
};
