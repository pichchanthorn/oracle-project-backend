// Requires req.user.role (set by requireAccessToken from the verified JWT
// claim — see middleware/auth.js) to exactly match one of allowedRoles.
// Must run after requireAccessToken: authentication failures (missing/
// invalid/wrong-type token) are requireAccessToken's responsibility and
// result in 401 before this middleware ever runs. This middleware only
// ever returns 403 — it is not a second authentication check.
//
// Role comes exclusively from req.user.role, never from req.body/query/
// params, so a client can never self-assign a different role by sending
// one alongside a valid token.
function requireRole(...allowedRoles) {
  return function roleMiddleware(req, res, next) {
    const role = req.user && req.user.role;

    if (typeof role !== 'string' || !allowedRoles.includes(role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  };
}

module.exports = { requireRole };
