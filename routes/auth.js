const express = require('express');
const router = express.Router();
const { createUser, DuplicateFieldError } = require('../services/userService');
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

module.exports = router;
