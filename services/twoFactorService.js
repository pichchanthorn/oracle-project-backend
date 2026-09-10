const oracledb = require('oracledb');
const { getConnection } = require('../db');
// Called through the module object (not destructured) so tests can spy on
// userService.findById and have that reflected here — same pattern already
// used for authAuditService in routes/auth.js and routes/twoFactor.js.
const userService = require('./userService');
const totpService = require('./totpService');
const { isCurrentlyLockedOut } = require('./authService');

const SETUP_RESULT = {
  ALREADY_ENABLED: 'already_enabled',
  SUCCESS: 'success',
};

const ENABLE_RESULT = {
  NO_PENDING_SETUP: 'no_pending_setup',
  ALREADY_ENABLED: 'already_enabled',
  INVALID_CODE: 'invalid_code',
  SUCCESS: 'success',
};

const DISABLE_RESULT = {
  INACTIVE_USER: 'inactive_user',
  LOCKED: 'locked',
  ALREADY_DISABLED: 'already_disabled',
  MISSING_SECRET: 'missing_secret',
  INVALID_SECRET: 'invalid_secret',
  INVALID_CODE: 'invalid_code',
  SUCCESS: 'success',
};

async function persistPendingSecret(userId, encryptedSecret) {
  let conn;
  try {
    conn = await getConnection();
    await conn.execute(
      `UPDATE users
       SET two_factor_secret = :encryptedSecret,
           updated_at = SYSTIMESTAMP
       WHERE user_id = :userId`,
      { encryptedSecret, userId },
      { autoCommit: true }
    );
  } finally {
    if (conn) await conn.close();
  }
}

// Atomically flips TWO_FACTOR_ENABLED 0 -> 1 only if it is currently 0.
// rowsAffected === 0 means either the user no longer exists or a concurrent
// request already enabled it first — both are safe, detectable outcomes,
// never a silent double-enable. No preceding SELECT is used for the
// decision itself, so two concurrent requests cannot both read "disabled"
// and both attempt to flip it; Oracle's row lock on the UPDATE serializes
// them, and only one will see rowsAffected === 1.
async function enableAtomically(userId) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE users
       SET two_factor_enabled = 1,
           updated_at = SYSTIMESTAMP
       WHERE user_id = :userId
         AND two_factor_enabled = 0`,
      { userId },
      { autoCommit: true }
    );
    return result.rowsAffected === 1;
  } finally {
    if (conn) await conn.close();
  }
}

// Core /setup logic. Never throws for the expected "already enabled" case —
// only for genuinely unexpected failures, which the route maps to a generic
// 500. Returns a discriminated result; the route is responsible for shaping
// the HTTP response and recording the audit event.
async function setup(userId) {
  const user = await userService.findById(userId);
  if (!user) {
    // Should not happen for a request that passed requireAccessToken
    // against a still-existing user, but fail safely rather than assume.
    throw new Error('User not found for authenticated request');
  }

  if (user.twoFactorEnabled) {
    return { outcome: SETUP_RESULT.ALREADY_ENABLED };
  }

  const secret = totpService.generateSecret();
  const otpAuthUri = totpService.generateOtpAuthUri({ secret, accountName: user.username });
  const qrCodeDataUrl = await totpService.generateQrCodeDataUrl(otpAuthUri);
  const encryptedSecret = totpService.encryptSecret(secret);

  await persistPendingSecret(userId, encryptedSecret);

  return {
    outcome: SETUP_RESULT.SUCCESS,
    secret,
    otpAuthUri,
    qrCodeDataUrl,
  };
}

const CODE_PATTERN = /^[0-9]{6}$/;

function isWellFormedCode(code) {
  return typeof code === 'string' && CODE_PATTERN.test(code);
}

// Core /enable logic. Assumes the caller has already validated that `code`
// is a well-formed 6-digit string (routes/twoFactor.js rejects malformed
// input with 400 before any DB/crypto work is attempted here).
async function enable(userId, code) {
  const user = await userService.findById(userId);
  if (!user) {
    throw new Error('User not found for authenticated request');
  }

  if (user.twoFactorEnabled) {
    return { outcome: ENABLE_RESULT.ALREADY_ENABLED };
  }

  if (!user.twoFactorSecret) {
    return { outcome: ENABLE_RESULT.NO_PENDING_SETUP };
  }

  let plaintextSecret;
  try {
    plaintextSecret = totpService.decryptSecret(user.twoFactorSecret);
  } catch {
    // Stored secret is unusable (corrupted/tampered) — treat identically to
    // "no usable pending setup" rather than leaking decryption detail.
    return { outcome: ENABLE_RESULT.NO_PENDING_SETUP };
  }

  const isValid = await totpService.verifyCode({ secret: plaintextSecret, code });
  if (!isValid) {
    return { outcome: ENABLE_RESULT.INVALID_CODE };
  }

  const enabled = await enableAtomically(userId);
  if (!enabled) {
    // Lost the race to a concurrent enable, or the row disappeared — either
    // way, 2FA is (or will be) enabled without this request's help.
    return { outcome: ENABLE_RESULT.ALREADY_ENABLED };
  }

  return { outcome: ENABLE_RESULT.SUCCESS };
}

// Atomically flips TWO_FACTOR_ENABLED 1 -> 0 and clears the secret, only if
// currently enabled — the inverse of enableAtomically, same reasoning: a
// single UPDATE with no preceding SELECT means Oracle's row lock on the
// UPDATE itself serializes concurrent disable attempts. rowsAffected === 0
// means 2FA was already disabled (by a concurrent request, or already off)
// — a safe, detectable outcome, never a silent no-op that the caller can't
// distinguish from success. TWO_FACTOR_ENABLED, TWO_FACTOR_SECRET, and
// UPDATED_AT all change in this one statement — no partial state is ever
// observable between them.
async function disableAtomically(userId) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE users
       SET two_factor_enabled = 0,
           two_factor_secret = NULL,
           updated_at = SYSTIMESTAMP
       WHERE user_id = :userId
         AND two_factor_enabled = 1`,
      { userId },
      { autoCommit: true }
    );
    return result.rowsAffected === 1;
  } finally {
    if (conn) await conn.close();
  }
}

// Core /disable logic. Assumes the caller has already validated that `code`
// is a well-formed 6-digit string (routes/twoFactor.js rejects malformed
// input with 400 before any DB/crypto work is attempted here).
//
// The access token's claims are a snapshot from whenever it was issued —
// the user is reloaded fresh from Oracle here and re-checked (active, not
// locked, currently enabled, secret present/decryptable) rather than
// trusting anything beyond the token's identity claim. TOTP is verified
// BEFORE disableAtomically is ever called — an invalid code returns early
// and never reaches the database write, so the secret can never be cleared
// without a successful verification immediately preceding it.
async function disable(userId, code) {
  const user = await userService.findById(userId);
  if (!user) {
    throw new Error('User not found for authenticated request');
  }

  if (!user.active) {
    return { outcome: DISABLE_RESULT.INACTIVE_USER };
  }

  if (isCurrentlyLockedOut(user)) {
    return { outcome: DISABLE_RESULT.LOCKED };
  }

  if (!user.twoFactorEnabled) {
    return { outcome: DISABLE_RESULT.ALREADY_DISABLED };
  }

  if (!user.twoFactorSecret) {
    return { outcome: DISABLE_RESULT.MISSING_SECRET };
  }

  let plaintextSecret;
  try {
    plaintextSecret = totpService.decryptSecret(user.twoFactorSecret);
  } catch {
    // Stored secret is unusable (corrupted/tampered) — fail safely, never
    // leak decryption detail.
    return { outcome: DISABLE_RESULT.INVALID_SECRET };
  }

  const isValid = await totpService.verifyCode({ secret: plaintextSecret, code });
  if (!isValid) {
    return { outcome: DISABLE_RESULT.INVALID_CODE };
  }

  const disabled = await disableAtomically(userId);
  if (!disabled) {
    // Lost the race to a concurrent disable (or 2FA was already off by the
    // time this UPDATE ran) — either way, the end state the caller wanted
    // (2FA disabled) is already true, just not because of this request.
    return { outcome: DISABLE_RESULT.ALREADY_DISABLED };
  }

  return { outcome: DISABLE_RESULT.SUCCESS };
}

module.exports = {
  SETUP_RESULT,
  ENABLE_RESULT,
  DISABLE_RESULT,
  isWellFormedCode,
  setup,
  enable,
  disable,
};
