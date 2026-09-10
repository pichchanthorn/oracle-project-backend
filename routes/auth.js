const express = require('express');
const router = express.Router();
const { createUser, DuplicateFieldError } = require('../services/userService');
const authService = require('../services/authService');
const { isWellFormedCode } = require('../services/twoFactorService');
const authAuditService = require('../services/authAuditService');

// Called through the module object (not destructured) so tests can spy on
// authAuditService.recordAuthEvent and have that reflected here.
const recordAuthEvent = (...args) => authAuditService.recordAuthEvent(...args);

const USERNAME_MAX_LENGTH = 50;
const FULL_NAME_MAX_LENGTH = 100;
const EMAIL_MAX_LENGTH = 150;
const PASSWORD_MIN_LENGTH = 8;
const USERNAME_PATTERN = /^[A-Za-z0-9._-]+$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegistration({ username, password, fullName, email }) {
  if (typeof username !== 'string' || !username.trim()) {
    return 'username is required';
  }
  if (username.trim().length > USERNAME_MAX_LENGTH) {
    return `username must be ${USERNAME_MAX_LENGTH} characters or fewer`;
  }
  if (!USERNAME_PATTERN.test(username.trim())) {
    return 'username may only contain letters, numbers, ".", "_", and "-"';
  }

  if (typeof password !== 'string' || !password) {
    return 'password is required';
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  }

  if (typeof fullName !== 'string' || !fullName.trim()) {
    return 'fullName is required';
  }
  if (fullName.trim().length > FULL_NAME_MAX_LENGTH) {
    return `fullName must be ${FULL_NAME_MAX_LENGTH} characters or fewer`;
  }

  if (typeof email !== 'string' || !email.trim()) {
    return 'email is required';
  }
  if (email.trim().length > EMAIL_MAX_LENGTH) {
    return `email must be ${EMAIL_MAX_LENGTH} characters or fewer`;
  }
  if (!EMAIL_PATTERN.test(email.trim())) {
    return 'email must be a valid email address';
  }

  return null;
}

// POST /api/auth/register — self-registration. Always creates an ASSOCIATE,
// active account; role/isActive/etc. are never accepted from the client (see
// services/userService.js, which only ever binds the four fields below).
router.post('/register', async (req, res) => {
  const { username, password, fullName, email } = req.body || {};
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;

  const validationError = validateRegistration({ username, password, fullName, email });
  if (validationError) {
    await recordAuthEvent({
      usernameAttempted: typeof username === 'string' ? username.trim() : null,
      eventType: 'REGISTER_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'validation_error',
    });
    return res.status(400).json({ error: validationError });
  }

  const trimmedUsername = username.trim();
  const trimmedFullName = fullName.trim();
  const trimmedEmail = email.trim();

  let user;
  try {
    user = await createUser({
      username: trimmedUsername,
      password,
      fullName: trimmedFullName,
      email: trimmedEmail,
    });
  } catch (err) {
    if (err instanceof DuplicateFieldError) {
      const detail = err.field === 'email' ? 'duplicate_email' : 'duplicate_username';
      const message =
        err.field === 'email' ? 'Email is already registered' : 'Username is already taken';

      await recordAuthEvent({
        usernameAttempted: trimmedUsername,
        eventType: 'REGISTER_FAILURE',
        eventResult: 'FAILURE',
        ip,
        userAgent,
        detail,
      });

      return res.status(409).json({ error: message });
    }

    console.error(err);
    await recordAuthEvent({
      usernameAttempted: trimmedUsername,
      eventType: 'REGISTER_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: 'Registration failed' });
  }

  // The user row is already committed at this point. Audit logging is
  // best-effort and must never downgrade this into an error response —
  // recordAuthEvent() already swallows its own errors, but the response is
  // sent first regardless so that guarantee doesn't depend on that contract.
  res.status(201).json(user);
  recordAuthEvent({
    userId: user.id,
    usernameAttempted: trimmedUsername,
    eventType: 'REGISTER_SUCCESS',
    eventResult: 'SUCCESS',
    ip,
    userAgent,
  });
});

function validateLogin({ username, password }) {
  if (typeof username !== 'string' || !username.trim()) {
    return 'username is required';
  }
  if (typeof password !== 'string' || !password) {
    return 'password is required';
  }
  return null;
}

// POST /api/auth/login — public. Unknown username, inactive account, and
// wrong password all produce the identical 401 response below; only a
// currently-locked account differs (423), which is an explicit, approved
// exception to the no-enumeration rule (an attacker who already knows a
// locked username learns nothing they couldn't infer from repeated lockouts
// anyway). See services/authService.js for the lockout/timing logic itself.
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;

  const validationError = validateLogin({ username, password });
  if (validationError) {
    await recordAuthEvent({
      usernameAttempted: typeof username === 'string' ? username.trim() : null,
      eventType: 'LOGIN_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'validation_error',
    });
    return res.status(400).json({ error: validationError });
  }

  const trimmedUsername = username.trim();

  let result;
  try {
    result = await authService.login({ username: trimmedUsername, password });
  } catch (err) {
    console.error(err);
    await recordAuthEvent({
      usernameAttempted: trimmedUsername,
      eventType: 'LOGIN_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: 'Login failed' });
  }

  const { LOGIN_RESULT } = authService;

  if (result.outcome === LOGIN_RESULT.INVALID_CREDENTIALS) {
    const locked = result.lockedOut === true;
    await recordAuthEvent({
      userId: result.user ? result.user.id : null,
      usernameAttempted: trimmedUsername,
      eventType: locked ? 'ACCOUNT_LOCKOUT' : 'LOGIN_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: locked ? 'lockout_threshold_reached' : 'invalid_credentials',
    });

    if (locked) {
      return res.status(423).json({ error: 'Account is locked. Try again later.' });
    }
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  if (result.outcome === LOGIN_RESULT.LOCKED) {
    await recordAuthEvent({
      userId: result.user.id,
      usernameAttempted: trimmedUsername,
      eventType: 'LOGIN_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'account_locked',
    });
    return res.status(423).json({ error: 'Account is locked. Try again later.' });
  }

  if (result.outcome === LOGIN_RESULT.SUCCESS_CHALLENGE) {
    res.status(200).json({
      requiresTwoFactor: true,
      challengeToken: result.challengeToken,
      user: result.user,
    });
    recordAuthEvent({
      userId: result.user.id,
      usernameAttempted: trimmedUsername,
      eventType: 'PASSWORD_VERIFIED_2FA_REQUIRED',
      eventResult: 'SUCCESS',
      ip,
      userAgent,
    });
    return;
  }

  // LOGIN_RESULT.SUCCESS_ACCESS
  res.status(200).json({
    requiresTwoFactor: false,
    accessToken: result.accessToken,
    user: result.user,
  });
  recordAuthEvent({
    userId: result.user.id,
    usernameAttempted: trimmedUsername,
    eventType: 'LOGIN_SUCCESS',
    eventResult: 'SUCCESS',
    ip,
    userAgent,
  });
});

function isWellFormedChallengeToken(token) {
  return typeof token === 'string' && token.length > 0;
}

function validateVerifyLogin({ challengeToken, twoFactorCode }) {
  if (!isWellFormedChallengeToken(challengeToken)) {
    return 'challengeToken is required';
  }
  if (!isWellFormedCode(twoFactorCode)) {
    return 'twoFactorCode must be exactly 6 digits';
  }
  return null;
}

// POST /api/auth/verify-login — public. This is the second step of a 2FA
// login: the client holds a challengeToken from /login (not a normal access
// token) and submits it here alongside the 6-digit TOTP code. No
// Authorization header is used or required — the challenge token, supplied
// only in the request body, is the sole credential. User identity comes
// exclusively from the challenge token's verified claims (authService's
// verifyTwoFactorLogin) — the request body can never supply/override a
// user ID. Deliberately NOT mounted behind requireAccessToken or under
// routes/twoFactor.js (which app.js mounts behind requireAccessToken) —
// see services/authService.js for the full verification flow.
router.post('/verify-login', async (req, res) => {
  const { challengeToken, twoFactorCode } = req.body || {};
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;

  const validationError = validateVerifyLogin({ challengeToken, twoFactorCode });
  if (validationError) {
    // Malformed input is rejected before any JWT/DB/crypto work. No user
    // identity is known yet at this point, so the audit row carries no
    // userId — consistent with how routes/auth.js's /login handles an
    // unparseable request.
    await recordAuthEvent({
      eventType: '2FA_VERIFY_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'invalid_code',
    });
    return res.status(400).json({ error: validationError });
  }

  let result;
  try {
    result = await authService.verifyTwoFactorLogin({ challengeToken, twoFactorCode });
  } catch (err) {
    console.error(err);
    await recordAuthEvent({
      eventType: '2FA_VERIFY_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: 'Verification failed' });
  }

  const { VERIFY_LOGIN_RESULT } = authService;

  if (result.outcome === VERIFY_LOGIN_RESULT.SUCCESS) {
    // result.userId/result.user are already safe, non-sensitive fields.
    // Response sent before the fire-and-forget audit call, matching the
    // established pattern (routes/auth.js's /login, routes/twoFactor.js's
    // /setup and /enable) — a slow or failing audit write can never turn a
    // successful verification into an error response.
    res.status(200).json({
      accessToken: result.accessToken,
      user: result.user,
    });
    recordAuthEvent({
      userId: result.userId,
      usernameAttempted: result.user.username,
      eventType: '2FA_VERIFY_SUCCESS',
      eventResult: 'SUCCESS',
      ip,
      userAgent,
    });
    return;
  }

  // Every failure outcome below maps to one of two safe, generic client
  // responses (401 for anything identity/challenge/state related, 400 for
  // a TOTP code that was well-formed but wrong) — the HTTP response never
  // distinguishes "invalid challenge" from "inactive user" from "2FA
  // disabled" from "missing/corrupt secret", only the audit DETAIL does.
  //
  // LOCKED maps to 'invalid_challenge', not 'inactive_user': a currently
  // locked account is a transient, time-bound state tied to the lockout
  // mechanism (FAILED_LOGIN_COUNT/LOCKOUT_END_AT), not a permanent
  // administrative deactivation — conflating the two in the audit trail
  // would make it impossible to tell "account disabled by an admin" apart
  // from "account temporarily locked out from failed attempts" during
  // later review. 'invalid_challenge' is the correct existing category
  // here: from the verifier's perspective, a locked account's challenge
  // token cannot be honored right now, which is exactly what
  // 'invalid_challenge' already means for every other "this challenge
  // cannot be used to authenticate" case.
  const detailByOutcome = {
    [VERIFY_LOGIN_RESULT.INVALID_CHALLENGE]: 'invalid_challenge',
    [VERIFY_LOGIN_RESULT.EXPIRED_CHALLENGE]: 'expired_challenge',
    [VERIFY_LOGIN_RESULT.INACTIVE_USER]: 'inactive_user',
    [VERIFY_LOGIN_RESULT.LOCKED]: 'invalid_challenge',
    [VERIFY_LOGIN_RESULT.TWO_FACTOR_DISABLED]: 'two_factor_disabled',
    [VERIFY_LOGIN_RESULT.MISSING_SECRET]: 'missing_secret',
    [VERIFY_LOGIN_RESULT.INVALID_SECRET]: 'invalid_secret',
    [VERIFY_LOGIN_RESULT.INVALID_CODE]: 'invalid_code',
  };

  const detail = detailByOutcome[result.outcome] || 'internal_error';

  await recordAuthEvent({
    userId: result.userId || null,
    eventType: '2FA_VERIFY_FAILURE',
    eventResult: 'FAILURE',
    ip,
    userAgent,
    detail,
  });

  if (result.outcome === VERIFY_LOGIN_RESULT.INVALID_CODE) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  return res.status(401).json({ error: 'Invalid or expired challenge' });
});

module.exports = router;
