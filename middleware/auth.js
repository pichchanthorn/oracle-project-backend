const jwtService = require('../services/jwtService');

function extractBearerToken(req) {
  const header = req.headers.authorization;
  if (!header || typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/.exec(header);
  return match ? match[1] : null;
}

function claimsToReqUser(claims) {
  // Only the fields the token itself carries — never anything from the
  // request body/query, so a caller cannot influence req.user by sending
  // extra fields alongside a valid Authorization header.
  return {
    id: claims.sub,
    username: claims.username,
    email: claims.email,
    role: claims.role,
  };
}

// Requires a valid, non-expired, correctly-signed JWT whose token_type is
// exactly "access". This is the sole enforcement point for the rule that a
// 2fa-challenge token must never authorize a normal business route — every
// router protected by this middleware is safe by construction, regardless
// of whether the future 2FA verification route also checks token type.
function requireAccessToken(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  let claims;
  try {
    claims = jwtService.verifyTokenOfType(token, jwtService.TOKEN_TYPE_ACCESS);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = claimsToReqUser(claims);
  next();
}

// Requires a valid, non-expired, correctly-signed JWT whose token_type is
// exactly "2fa-challenge". Intended for the future 2FA verify-login route
// only — never mount this on business routes.
function requireTwoFactorChallengeToken(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  let claims;
  try {
    claims = jwtService.verifyTokenOfType(token, jwtService.TOKEN_TYPE_TWO_FACTOR_CHALLENGE);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.pendingLogin = claimsToReqUser(claims);
  next();
}

module.exports = { requireAccessToken, requireTwoFactorChallengeToken };
