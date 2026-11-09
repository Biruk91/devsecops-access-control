const { hasPermission } = require("../permissions");

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "Forbidden: Insufficient role privileges" });
    }
    next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !hasPermission(req.user.role, permission)) {
      return res
        .status(403)
        .json({ error: `Forbidden: Missing required permission '${permission}'` });
    }
    next();
  };
}

module.exports = {
  requireRole,
  requirePermission,
};
