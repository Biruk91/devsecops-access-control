const { hasPermission } = require("../permissions");
const { logSecurityEvent } = require("../events");

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      logSecurityEvent(req, "authorization_denied", {
        userId: req.user?.id || "anonymous",
        role: req.user?.role || "none",
        required: `role:${allowedRoles.join(",")}`,
      });
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
      logSecurityEvent(req, "authorization_denied", {
        userId: req.user?.id || "anonymous",
        role: req.user?.role || "none",
        required: `permission:${permission}`,
      });
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
