const ROLE_PERMISSIONS = {
  waiter: ["orders:create", "orders:read"],
  cashier: ["orders:read", "payments:create"],
  manager: ["orders:read", "reports:read"],
  admin: [
    "users:manage",
    "orders:read",
    "orders:create",
    "payments:create",
    "reports:read",
  ],
};

function hasPermission(role, permission) {
  if (!role || typeof role !== "string") return false;
  const permissions = ROLE_PERMISSIONS[role] || [];
  return permissions.includes(permission);
}

function getPermissionsForRole(role) {
  if (!role || typeof role !== "string") return [];
  return ROLE_PERMISSIONS[role] || [];
}

module.exports = {
  ROLE_PERMISSIONS,
  hasPermission,
  getPermissionsForRole,
};
