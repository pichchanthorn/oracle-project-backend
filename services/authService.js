const bcrypt = require('bcrypt');
const oracledb = require('oracledb');
const { getConnection } = require('../db');
const { findByUsername } = require('./userService');
const jwtService = require('./jwtService');

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

module.exports = { login, LOGIN_RESULT, getMaxFailedAttempts };
