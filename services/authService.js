const bcrypt = require('bcrypt');
const oracledb = require('oracledb');
const { TokenExpiredError } = require('jsonwebtoken');
const { getConnection } = require('../db');
const { findByUsername, findById } = require('./userService');
const jwtService = require('./jwtService');
const totpService = require('./totpService');

// A bcrypt hash of an arbitrary, unrelated string — not a real password or a
// secret. Used only so that an unknown-username login still runs a bcrypt
// comparison of comparable cost, to avoid an obvious timing difference
// between "username doesn't exist" and "username exists, password wrong".
const DUMMY_PASSWORD_HASH = '$2b$12$GaW1KPhFBEp2cjBcrMznM.R7cyBbTao2zgUB2u3Pp4YYCpvO8i50i';

const LOGIN_RESULT = {
  INVALID_CREDENTIALS: 'invalid_credentials',
  LOCKED: 'locked',
  SUCCESS_ACCESS: 'success_access',
  SUCCESS_CHALLENGE: 'success_challenge',
};

function getMaxFailedAttempts() {
  const value = Number(process.env.MAX_FAILED_LOGIN_ATTEMPTS);
  return Number.isFinite(value) && value > 0 ? value : 5;
}

function getLockoutDurationMinutes() {
  const value = Number(process.env.LOCKOUT_DURATION_MINUTES);
  return Number.isFinite(value) && value > 0 ? value : 15;
}

// Atomically increments FAILED_LOGIN_COUNT and, if the post-increment value
// reaches the threshold, sets LOCKOUT_END_AT in the same statement. This is
// a single UPDATE with no preceding SELECT, so Oracle's row lock on the
// UPDATE itself serializes concurrent attempts against the same account —
// two simultaneous wrong-password requests cannot both read the same "count
// before increment" and lose an update, because neither ever reads the
// count separately from incrementing it.
async function recordFailedAttempt(userId) {
  const maxAttempts = getMaxFailedAttempts();
  const lockoutMinutes = getLockoutDurationMinutes();

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE users
       SET failed_login_count = failed_login_count + 1,
           lockout_end_at = CASE
             WHEN failed_login_count + 1 >= :maxAttempts
               THEN SYSTIMESTAMP + NUMTODSINTERVAL(:lockoutMinutes, 'MINUTE')
             ELSE lockout_end_at
           END
       WHERE user_id = :userId
       RETURNING failed_login_count, lockout_end_at INTO :newCount, :newLockoutEnd`,
      {
        maxAttempts,
        lockoutMinutes,
        userId,
        newCount: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        newLockoutEnd: { dir: oracledb.BIND_OUT, type: oracledb.DATE },
      },
      { autoCommit: true }
    );

    return {
      failedLoginCount: result.outBinds.newCount[0],
      lockedOut: result.outBinds.newLockoutEnd[0] != null,
    };
  } finally {
    if (conn) await conn.close();
  }
}

async function resetFailedAttempts(userId) {
  let conn;
  try {
    conn = await getConnection();
    await conn.execute(
      `UPDATE users SET failed_login_count = 0, lockout_end_at = NULL WHERE user_id = :userId`,
      { userId },
      { autoCommit: true }
    );
  } finally {
    if (conn) await conn.close();
  }
}

function isCurrentlyLockedOut(user) {
  return Boolean(user.lockoutEndAt) && new Date(user.lockoutEndAt).getTime() > Date.now();
}

// Core login logic. Returns a discriminated result object; never throws for
// expected outcomes (unknown user, wrong password, locked account) — only
// for genuinely unexpected failures (e.g. DB unreachable), which the route
// layer maps to a generic 500. Callers are responsible for recording the
// audit event and shaping the HTTP response — this function focuses purely
// on the authentication decision.
async function login({ username, password }) {
  const user = await findByUsername(username);

  if (!user) {
    // Run a bcrypt comparison anyway so the response time for an unknown
    // username is comparable to a known username with a wrong password.
    await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
    return { outcome: LOGIN_RESULT.INVALID_CREDENTIALS };
  }

  if (!user.active) {
    await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
    return { outcome: LOGIN_RESULT.INVALID_CREDENTIALS };
  }

  if (isCurrentlyLockedOut(user)) {
    return { outcome: LOGIN_RESULT.LOCKED, user };
  }

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);

  if (!passwordMatches) {
    const { failedLoginCount, lockedOut } = await recordFailedAttempt(user.id);
    return {
      outcome: LOGIN_RESULT.INVALID_CREDENTIALS,
      user,
      failedLoginCount,
      lockedOut,
    };
  }

  await resetFailedAttempts(user.id);

  const safeUser = {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    email: user.email,
    role: user.role,
  };

  if (user.twoFactorEnabled) {
    return {
      outcome: LOGIN_RESULT.SUCCESS_CHALLENGE,
      user: safeUser,
      challengeToken: jwtService.signTwoFactorChallengeToken(safeUser),
    };
  }

  return {
    outcome: LOGIN_RESULT.SUCCESS_ACCESS,
    user: safeUser,
    accessToken: jwtService.signAccessToken(safeUser),
  };
}

const VERIFY_LOGIN_RESULT = {
  INVALID_CHALLENGE: 'invalid_challenge',
  EXPIRED_CHALLENGE: 'expired_challenge',
  INACTIVE_USER: 'inactive_user',
  LOCKED: 'locked',
  TWO_FACTOR_DISABLED: 'two_factor_disabled',
  MISSING_SECRET: 'missing_secret',
  INVALID_SECRET: 'invalid_secret',
  INVALID_CODE: 'invalid_code',
  SUCCESS: 'success',
};

// Completes a password+TOTP login: verifies the challenge token (signature,
// HS256, issuer, audience, expiration, clock tolerance, token_type), reloads
// the user fresh from Oracle (the challenge token's claims are a snapshot
// from password-verification time and must never be trusted as current
// security state — the account may have been deactivated, locked, or had
// 2FA disabled since the challenge was issued), then verifies the submitted
// TOTP code against the decrypted stored secret. Only on full success does
// it issue a normal access token with amr: ['pwd', 'mfa'].
//
// Never throws for expected failure outcomes (bad/expired challenge,
// inactive user, disabled 2FA, missing/corrupt secret, wrong code) — only
// for genuinely unexpected failures, which the route maps to a generic 500.
// Callers are responsible for recording the audit event and shaping the
// HTTP response.
async function verifyTwoFactorLogin({ challengeToken, twoFactorCode }) {
  let claims;
  try {
    claims = jwtService.verifyTokenOfType(challengeToken, jwtService.TOKEN_TYPE_TWO_FACTOR_CHALLENGE);
  } catch (err) {
    const outcome =
      err instanceof TokenExpiredError
        ? VERIFY_LOGIN_RESULT.EXPIRED_CHALLENGE
        : VERIFY_LOGIN_RESULT.INVALID_CHALLENGE;
    return { outcome };
  }

  // claims.sub is always a string (see jwtService.js's baseClaims) — never
  // pass it into an Oracle NUMBER bind or an audit call unconverted. This is
  // exactly the NJS-011 class of bug Phase 4 hit; convert once, here.
  const userId = Number(claims.sub);
  if (!Number.isInteger(userId)) {
    return { outcome: VERIFY_LOGIN_RESULT.INVALID_CHALLENGE };
  }

  const user = await findById(userId);
  if (!user) {
    return { outcome: VERIFY_LOGIN_RESULT.INVALID_CHALLENGE, userId };
  }

  if (!user.active) {
    return { outcome: VERIFY_LOGIN_RESULT.INACTIVE_USER, userId };
  }

  if (isCurrentlyLockedOut(user)) {
    return { outcome: VERIFY_LOGIN_RESULT.LOCKED, userId };
  }

  if (!user.twoFactorEnabled) {
    return { outcome: VERIFY_LOGIN_RESULT.TWO_FACTOR_DISABLED, userId };
  }

  if (!user.twoFactorSecret) {
    return { outcome: VERIFY_LOGIN_RESULT.MISSING_SECRET, userId };
  }

  let plaintextSecret;
  try {
    plaintextSecret = totpService.decryptSecret(user.twoFactorSecret);
  } catch {
    // Stored secret is unusable (corrupted/tampered, or encrypted under a
    // rotated key) — fail safely, never leak decryption detail.
    return { outcome: VERIFY_LOGIN_RESULT.INVALID_SECRET, userId };
  }

  const isValid = await totpService.verifyCode({ secret: plaintextSecret, code: twoFactorCode });
  if (!isValid) {
    return { outcome: VERIFY_LOGIN_RESULT.INVALID_CODE, userId };
  }

  const safeUser = {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    email: user.email,
    role: user.role,
  };

  return {
    outcome: VERIFY_LOGIN_RESULT.SUCCESS,
    userId,
    user: safeUser,
    accessToken: jwtService.signAccessToken(safeUser, { amr: ['pwd', 'mfa'] }),
  };
}

module.exports = {
  login,
  LOGIN_RESULT,
  getMaxFailedAttempts,
  verifyTwoFactorLogin,
  VERIFY_LOGIN_RESULT,
  isCurrentlyLockedOut,
};
