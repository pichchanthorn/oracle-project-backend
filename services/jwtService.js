const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const ALGORITHM = 'HS256';
const MIN_SECRET_BYTES = 32;
const CLOCK_TOLERANCE_SECONDS = 30;

const TOKEN_TYPE_ACCESS = 'access';
const TOKEN_TYPE_TWO_FACTOR_CHALLENGE = '2fa-challenge';

let cachedConfig = null;

// Reads and validates JWT configuration from process.env. Called once at
// startup (server.js) so a misconfigured deployment fails fast instead of
// signing tokens with a missing/weak secret. Throws — never logs or returns
// the secret value itself.
function loadConfig() {
  const secret = process.env.JWT_SECRET;
  if (!secret || typeof secret !== 'string' || secret.length === 0) {
    throw new Error('JWT_SECRET is missing. Set a strong random value (at least 32 bytes) in .env.');
  }
  if (Buffer.byteLength(secret, 'utf8') < MIN_SECRET_BYTES) {
    throw new Error(
      `JWT_SECRET does not meet the minimum length requirement (${MIN_SECRET_BYTES} bytes).`
    );
  }

  const issuer = process.env.JWT_ISSUER;
  if (!issuer) {
    throw new Error('JWT_ISSUER is missing.');
  }

  const audience = process.env.JWT_AUDIENCE;
  if (!audience) {
    throw new Error('JWT_AUDIENCE is missing.');
  }

  const accessTokenExpirationMinutes = Number(process.env.JWT_ACCESS_TOKEN_EXPIRATION_MINUTES);
  if (!Number.isFinite(accessTokenExpirationMinutes) || accessTokenExpirationMinutes <= 0) {
    throw new Error('JWT_ACCESS_TOKEN_EXPIRATION_MINUTES must be a positive number.');
  }

  const twoFactorChallengeExpirationMinutes = Number(
    process.env.JWT_TWO_FACTOR_CHALLENGE_EXPIRATION_MINUTES
  );
  if (!Number.isFinite(twoFactorChallengeExpirationMinutes) || twoFactorChallengeExpirationMinutes <= 0) {
    throw new Error('JWT_TWO_FACTOR_CHALLENGE_EXPIRATION_MINUTES must be a positive number.');
  }

  return {
    secret,
    issuer,
    audience,
    accessTokenExpirationSeconds: accessTokenExpirationMinutes * 60,
    twoFactorChallengeExpirationSeconds: twoFactorChallengeExpirationMinutes * 60,
  };
}

// Validates configuration and caches it. Call this at startup so the process
// exits immediately on misconfiguration rather than failing on first login.
function validateConfig() {
  cachedConfig = loadConfig();
  return cachedConfig;
}

function getConfig() {
  if (!cachedConfig) {
    cachedConfig = loadConfig();
  }
  return cachedConfig;
}

function baseClaims(user, amr = ['pwd']) {
  return {
    sub: String(user.id),
    username: user.username,
    email: user.email,
    role: user.role,
    jti: crypto.randomUUID(),
    amr,
  };
}

function signToken(claims, expiresInSeconds) {
  const config = getConfig();
  return jwt.sign(claims, config.secret, {
    algorithm: ALGORITHM,
    issuer: config.issuer,
    audience: config.audience,
    expiresIn: expiresInSeconds,
  });
}

// `amr` defaults to ['pwd'] (password-only login) for backward
// compatibility with existing callers (authService.js's password-only
// login path). Phase 5 passes { amr: ['pwd', 'mfa'] } after a successful
// TOTP verification — see routes/auth.js's /verify-login handler.
function signAccessToken(user, { amr } = {}) {
  const config = getConfig();
  return signToken(
    { ...baseClaims(user, amr), token_type: TOKEN_TYPE_ACCESS },
    config.accessTokenExpirationSeconds
  );
}

function signTwoFactorChallengeToken(user) {
  const config = getConfig();
  return signToken(
    { ...baseClaims(user), token_type: TOKEN_TYPE_TWO_FACTOR_CHALLENGE },
    config.twoFactorChallengeExpirationSeconds
  );
}

// Verifies signature, issuer, audience, expiration, and algorithm. Throws on
// any failure (malformed token, bad signature, expired, wrong iss/aud, wrong
// alg) — callers must catch, never assume success. Does not check
// token_type; callers that need a specific type must check the returned
// claims themselves (see verifyTokenOfType below).
function verifyToken(token) {
  const config = getConfig();
  return jwt.verify(token, config.secret, {
    algorithms: [ALGORITHM],
    issuer: config.issuer,
    audience: config.audience,
    clockTolerance: CLOCK_TOLERANCE_SECONDS,
  });
}

// Verifies the token and additionally requires claims.token_type to match
// expectedType. Throws the same way verifyToken does, plus throws if the
// token is otherwise valid but of the wrong type — this is the function
// middleware should use so a well-formed token of the wrong type is always
// rejected at the same layer as a malformed one.
function verifyTokenOfType(token, expectedType) {
  const claims = verifyToken(token);
  if (claims.token_type !== expectedType) {
    throw new Error(`Unexpected token_type: expected "${expectedType}"`);
  }
  return claims;
}

module.exports = {
  TOKEN_TYPE_ACCESS,
  TOKEN_TYPE_TWO_FACTOR_CHALLENGE,
  validateConfig,
  signAccessToken,
  signTwoFactorChallengeToken,
  verifyToken,
  verifyTokenOfType,
};
