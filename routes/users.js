const express = require('express');
const router = express.Router();
const userService = require('../services/userService');
const { DuplicateFieldError } = userService;
const { requireRole } = require('../middleware/roles');
const { parsePositiveIntegerId } = require('../utils/validateId');
const authAuditService = require('../services/authAuditService');

// Called through the module object (not destructured) so tests can spy on
// authAuditService.recordAuthEvent and have that reflected here — same
// pattern already used in routes/auth.js.
const recordAuthEvent = (...args) => authAuditService.recordAuthEvent(...args);

// Every route in this router requires a real access token (never a 2FA
// challenge token — see middleware/auth.js's requireAccessToken, mounted
// once for the whole /api prefix in app.js) and the ADMIN role. Applied
// once here rather than per-route so a future route added to this file can
// never accidentally ship without it.
router.use(requireRole('ADMIN'));

const ALLOWED_ROLES = ['ADMIN', 'MANAGER', 'ASSOCIATE'];

// req.user.id comes from the JWT `sub` claim, which jwtService.js's
// baseClaims always encodes as a string — never assume it is already a
// number. This is the same NJS-011-class conversion authService.js's
// verifyTwoFactorLogin already documents and performs for the same reason
// (an unconverted string sub passed into a NUMBER bind or compared with
// === against a real numeric id silently does the wrong thing rather than
// throwing). Returns null if the claim is somehow not a valid integer,
// so callers can fail closed instead of miscomparing/miscasting.
function actingAdminId(req) {
  const id = Number(req.user && req.user.id);
  return Number.isInteger(id) ? id : null;
}

// Same rules as routes/auth.js's validateRegistration — this project has
// exactly one password/username/fullName/email policy, reused here rather
// than reimplemented, per the existing registration conventions.
const USERNAME_MAX_LENGTH = 50;
const FULL_NAME_MAX_LENGTH = 100;
const EMAIL_MAX_LENGTH = 150;
const PASSWORD_MIN_LENGTH = 8;
const USERNAME_PATTERN = /^[A-Za-z0-9._-]+$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateFullName(fullName) {
  if (typeof fullName !== 'string' || !fullName.trim()) {
    return 'fullName is required';
  }
  if (fullName.trim().length > FULL_NAME_MAX_LENGTH) {
    return `fullName must be ${FULL_NAME_MAX_LENGTH} characters or fewer`;
  }
  return null;
}

// email is optional for admin-created users (spec: "Optional: email"), but
// when present must be well-formed — same shape check as registration.
function validateOptionalEmail(email) {
  if (email === undefined || email === null || email === '') {
    return null;
  }
  if (typeof email !== 'string') {
    return 'email must be a string';
  }
  if (email.trim().length > EMAIL_MAX_LENGTH) {
    return `email must be ${EMAIL_MAX_LENGTH} characters or fewer`;
  }
  if (!EMAIL_PATTERN.test(email.trim())) {
    return 'email must be a valid email address';
  }
  return null;
}

function validateRole(role) {
  if (typeof role !== 'string' || !ALLOWED_ROLES.includes(role)) {
    return `role must be one of ${ALLOWED_ROLES.join(', ')}`;
  }
  return null;
}

function validateCreateUser({ username, password, fullName, email, role }) {
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

  const fullNameError = validateFullName(fullName);
  if (fullNameError) return fullNameError;

  const emailError = validateOptionalEmail(email);
  if (emailError) return emailError;

  if (role === undefined || role === null || role === '') {
    return 'role is required';
  }
  const roleError = validateRole(role);
  if (roleError) return roleError;

  return null;
}

// GET /api/users — ADMIN only. Safe user list; never includes
// PASSWORD_HASH or TWO_FACTOR_SECRET (see userService.listUsers, which
// never even selects those columns).
router.get('/', async (req, res) => {
  try {
    const users = await userService.listUsers();
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /api/users/:id — ADMIN only.
router.get('/:id', async (req, res) => {
  const id = parsePositiveIntegerId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  try {
    const user = await userService.findByIdForAdmin(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// POST /api/users — ADMIN only. Creates a new POS user. Only username,
// password, fullName, role (required) and email (optional) are ever read
// from the body — role is bound explicitly (an admin is allowed to choose
// it, unlike self-registration), but isActive/twoFactorEnabled/
// twoFactorSecret/passwordHash are never accepted from the client; the new
// row always starts active with 2FA disabled via userService.createUserAsAdmin's
// DB-level defaults.
router.post('/', async (req, res) => {
  const { username, password, fullName, email, role } = req.body || {};
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;
  const adminId = actingAdminId(req);

  const validationError = validateCreateUser({ username, password, fullName, email, role });
  if (validationError) {
    await recordAuthEvent({
      userId: adminId,
      usernameAttempted: typeof username === 'string' ? username.trim() : null,
      eventType: 'USER_CREATE_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'validation_error',
    });
    return res.status(400).json({ error: validationError });
  }

  const trimmedUsername = username.trim();
  const trimmedFullName = fullName.trim();
  const trimmedEmail = typeof email === 'string' && email.trim() ? email.trim() : null;

  let user;
  try {
    user = await userService.createUserAsAdmin({
      username: trimmedUsername,
      password,
      fullName: trimmedFullName,
      email: trimmedEmail,
      role,
    });
  } catch (err) {
    if (err instanceof DuplicateFieldError) {
      const detail = err.field === 'email' ? 'duplicate_email' : 'duplicate_username';
      const message =
        err.field === 'email' ? 'Email is already registered' : 'Username is already taken';

      await recordAuthEvent({
        userId: adminId,
        usernameAttempted: trimmedUsername,
        eventType: 'USER_CREATE_FAILURE',
        eventResult: 'FAILURE',
        ip,
        userAgent,
        detail,
      });

      return res.status(409).json({ error: message });
    }

    console.error(err);
    await recordAuthEvent({
      userId: adminId,
      usernameAttempted: trimmedUsername,
      eventType: 'USER_CREATE_FAILURE',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: 'Failed to create user' });
  }

  // Row is already committed. Audit logging is best-effort and must never
  // downgrade this into an error response — matching routes/auth.js's
  // /register (response sent first, audit call fire-and-forget).
  res.status(201).json(user);
  recordAuthEvent({
    userId: adminId,
    usernameAttempted: trimmedUsername,
    eventType: 'USER_CREATE_SUCCESS',
    eventResult: 'SUCCESS',
    ip,
    userAgent,
    detail: `created_user_id=${user.userId};role=${role}`,
  });
});

// PATCH /api/users/:id — ADMIN only. Allows updating fullName/email/role
// only. userId/username/password/passwordHash/twoFactorSecret/createdAt are
// never read from the body at all — there is no code path here that could
// forward them even if a client sent them.
router.patch('/:id', async (req, res) => {
  const id = parsePositiveIntegerId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  const { fullName, email, role } = req.body || {};

  if (fullName === undefined && email === undefined && role === undefined) {
    return res.status(400).json({ error: 'At least one field is required' });
  }

  if (fullName !== undefined) {
    const fullNameError = validateFullName(fullName);
    if (fullNameError) {
      return res.status(400).json({ error: fullNameError });
    }
  }

  if (email !== undefined) {
    const emailError = validateOptionalEmail(email);
    if (emailError) {
      return res.status(400).json({ error: emailError });
    }
  }

  if (role !== undefined) {
    const roleError = validateRole(role);
    if (roleError) {
      return res.status(400).json({ error: roleError });
    }
  }

  const trimmedFullName = fullName !== undefined ? fullName.trim() : undefined;
  // userService.updateUser uses COALESCE(:email, email) like every other
  // PATCH in this codebase (see routes/products.js) — passing null here
  // (an omitted or empty-string email) leaves the stored value unchanged
  // rather than clearing it. Clearing email to NULL is out of scope for
  // this phase; validateOptionalEmail already accepts '' as a well-formed,
  // no-op value for consistency with that limitation.
  const trimmedEmail =
    email !== undefined ? (typeof email === 'string' && email.trim() ? email.trim() : null) : undefined;

  try {
    const user = await userService.updateUser(id, {
      fullName: trimmedFullName,
      email: trimmedEmail,
      role,
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    if (err instanceof DuplicateFieldError) {
      const message = err.field === 'email' ? 'Email is already registered' : 'Duplicate value';
      return res.status(409).json({ error: message });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

function validateStatusBody(body) {
  if (!body || typeof body !== 'object') {
    return 'isActive is required';
  }
  if (typeof body.isActive !== 'boolean') {
    return 'isActive must be a boolean';
  }
  return null;
}

// PATCH /api/users/:id/status — ADMIN only. Updates only IS_ACTIVE. An
// ADMIN can never deactivate the account they are currently authenticated
// as — the comparison uses actingAdminId(req), which derives from the
// verified JWT `sub` claim (see middleware/auth.js), never from the request
// body/params, so this check cannot be bypassed by anything the client
// sends.
router.patch('/:id/status', async (req, res) => {
  const id = parsePositiveIntegerId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  const validationError = validateStatusBody(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { isActive } = req.body;
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;
  const adminId = actingAdminId(req);

  if (!isActive && id === adminId) {
    return res.status(409).json({ error: 'You cannot deactivate your own account' });
  }

  try {
    const updated = await userService.updateUserStatus(id, isActive);
    if (!updated) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ userId: id, isActive });
    recordAuthEvent({
      userId: adminId,
      eventType: 'USER_STATUS_CHANGE',
      eventResult: 'SUCCESS',
      ip,
      userAgent,
      detail: `target_user_id=${id};is_active=${isActive}`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

module.exports = router;
