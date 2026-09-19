const oracledb = require('oracledb');
const bcrypt = require('bcrypt');
const { getConnection } = require('../db');

const BCRYPT_COST_FACTOR = 12;
const ORA_UNIQUE_VIOLATION = 1;

// Oracle auto-generated these names for the USERS unique constraints in
// Phase 1 (db/migrations/001_auth_foundation.sql ran ALTER TABLE on a
// pre-existing table, so the underlying UNIQUE constraints predate that
// migration and were never explicitly named). Verified live against the
// dev DB at the time of writing. If these constraints are ever renamed
// (e.g. to UQ_USERS_USERNAME / UQ_USERS_EMAIL), update this map only —
// callers of classifyUniqueViolation() do not need to change.
const UNIQUE_CONSTRAINT_FIELD_MAP = {
  SYS_C008595: 'username',
  SYS_C008596: 'email',
};

function extractConstraintName(message) {
  const match = /\(([A-Z0-9_]+\.[A-Z0-9_]+)\)/.exec(message || '');
  if (!match) return null;
  const parts = match[1].split('.');
  return parts[parts.length - 1];
}

// Given an Oracle error with errorNum === 1 (unique constraint violated),
// determine whether USERNAME or EMAIL was the duplicated field.
// Falls back to inspecting the error message for the column name if the
// constraint name isn't recognized, so a constraint rename doesn't silently
// turn into an unclassified 500.
function classifyUniqueViolation(err) {
  const constraintName = extractConstraintName(err.message);
  if (constraintName && UNIQUE_CONSTRAINT_FIELD_MAP[constraintName]) {
    return UNIQUE_CONSTRAINT_FIELD_MAP[constraintName];
  }

  const message = (err.message || '').toUpperCase();
  if (message.includes('USERNAME')) return 'username';
  if (message.includes('EMAIL')) return 'email';

  return null;
}

class DuplicateFieldError extends Error {
  constructor(field) {
    super(`Duplicate ${field}`);
    this.field = field; // 'username' | 'email'
  }
}

// Creates a new USERS row. Only ever binds the four registration fields —
// role/isActive/etc. are left to their DB-level defaults (ASSOCIATE / 1) so
// a caller can never mass-assign privileged fields through this function.
async function createUser({ username, password, fullName, email }) {
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO users (username, password_hash, full_name, email)
       VALUES (:username, :passwordHash, :fullName, :email)
       RETURNING user_id, role, is_active INTO :id, :role, :active`,
      {
        username,
        passwordHash,
        fullName,
        email,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        role: { dir: oracledb.BIND_OUT, type: oracledb.STRING },
        active: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
      },
      { autoCommit: true }
    );

    return {
      id: result.outBinds.id[0],
      username,
      fullName,
      email,
      role: result.outBinds.role[0],
      active: result.outBinds.active[0] === 1,
    };
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      const field = classifyUniqueViolation(err);
      throw new DuplicateFieldError(field || 'unknown');
    }
    throw err;
  } finally {
    if (conn) await conn.close();
  }
}

// Case-insensitive username lookup for login. Returns only the fields the
// auth service needs (including password_hash, required for bcrypt
// verification) — callers outside the auth flow should not need this
// function, and nothing here is ever sent back in an HTTP response as-is.
async function findByUsername(username) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id, username, password_hash, full_name, email, role,
              is_active, failed_login_count, lockout_end_at, two_factor_enabled
       FROM users
       WHERE UPPER(username) = UPPER(:username)`,
      { username }
    );

    const row = result.rows[0];
    if (!row) return null;

    return {
      id: row.USER_ID,
      username: row.USERNAME,
      passwordHash: row.PASSWORD_HASH,
      fullName: row.FULL_NAME,
      email: row.EMAIL,
      role: row.ROLE,
      active: row.IS_ACTIVE === 1,
      failedLoginCount: row.FAILED_LOGIN_COUNT,
      lockoutEndAt: row.LOCKOUT_END_AT,
      twoFactorEnabled: row.TWO_FACTOR_ENABLED === 1,
    };
  } finally {
    if (conn) await conn.close();
  }
}

// Lookup by USER_ID (the only identity source for an authenticated request —
// see middleware/auth.js, which derives req.user.id from the verified JWT
// `sub` claim, never from the request body). Returns the same shape as
// findByUsername so callers can treat both lookups interchangeably.
async function findById(userId) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id, username, password_hash, full_name, email, role,
              is_active, failed_login_count, lockout_end_at, two_factor_enabled,
              two_factor_secret
       FROM users
       WHERE user_id = :userId`,
      { userId }
    );

    const row = result.rows[0];
    if (!row) return null;

    return {
      id: row.USER_ID,
      username: row.USERNAME,
      passwordHash: row.PASSWORD_HASH,
      fullName: row.FULL_NAME,
      email: row.EMAIL,
      role: row.ROLE,
      active: row.IS_ACTIVE === 1,
      failedLoginCount: row.FAILED_LOGIN_COUNT,
      lockoutEndAt: row.LOCKOUT_END_AT,
      twoFactorEnabled: row.TWO_FACTOR_ENABLED === 1,
      twoFactorSecret: row.TWO_FACTOR_SECRET,
    };
  } finally {
    if (conn) await conn.close();
  }
}

// Shapes one USERS row for an ADMIN-facing API response. Deliberately a
// fixed allow-list of fields — PASSWORD_HASH and TWO_FACTOR_SECRET are never
// read by any of the SELECTs below, so there is nothing here to accidentally
// leak even if this function is ever called with a wider row in the future.
function serializeUserForAdmin(row) {
  return {
    userId: row.USER_ID,
    username: row.USERNAME,
    fullName: row.FULL_NAME,
    email: row.EMAIL,
    role: row.ROLE,
    isActive: row.IS_ACTIVE === 1,
    twoFactorEnabled: row.TWO_FACTOR_ENABLED === 1,
    createdAt: row.CREATED_AT,
    updatedAt: row.UPDATED_AT,
  };
}

// GET /api/users — full safe user list for ADMIN. Selects only the columns
// serializeUserForAdmin needs; PASSWORD_HASH/TWO_FACTOR_SECRET are never
// fetched by this query at all.
async function listUsers() {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id, username, full_name, email, role, is_active,
              two_factor_enabled, created_at, updated_at
       FROM users
       ORDER BY user_id`
    );
    return result.rows.map(serializeUserForAdmin);
  } finally {
    if (conn) await conn.close();
  }
}

// GET /api/users/:id — single safe user for ADMIN. Returns null if the id
// does not exist; callers map that to 404.
async function findByIdForAdmin(userId) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id, username, full_name, email, role, is_active,
              two_factor_enabled, created_at, updated_at
       FROM users
       WHERE user_id = :userId`,
      { userId }
    );
    const row = result.rows[0];
    return row ? serializeUserForAdmin(row) : null;
  } finally {
    if (conn) await conn.close();
  }
}

// POST /api/users — ADMIN-initiated user creation. Unlike createUser()
// (self-registration, always ASSOCIATE/active/2FA-off by omission), this
// binds an explicit :role because an admin is allowed to choose it — but
// still only ever binds the five columns named here. IS_ACTIVE,
// TWO_FACTOR_ENABLED, and TWO_FACTOR_SECRET are left to their DB-level
// defaults (1, 0, NULL), so a newly admin-created user starts active with
// 2FA disabled and no stored secret, exactly like self-registration, and a
// caller of this function has no way to pass those fields even if it wanted
// to.
async function createUserAsAdmin({ username, password, fullName, email, role }) {
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO users (username, password_hash, full_name, email, role)
       VALUES (:username, :passwordHash, :fullName, :email, :role)
       RETURNING user_id, is_active, two_factor_enabled, created_at, updated_at
         INTO :id, :active, :twoFactorEnabled, :createdAt, :updatedAt`,
      {
        username,
        passwordHash,
        fullName,
        email: email || null,
        role,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        active: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        twoFactorEnabled: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        createdAt: { dir: oracledb.BIND_OUT, type: oracledb.DATE },
        updatedAt: { dir: oracledb.BIND_OUT, type: oracledb.DATE },
      },
      { autoCommit: true }
    );

    return {
      userId: result.outBinds.id[0],
      username,
      fullName,
      email: email || null,
      role,
      isActive: result.outBinds.active[0] === 1,
      twoFactorEnabled: result.outBinds.twoFactorEnabled[0] === 1,
      createdAt: result.outBinds.createdAt[0],
      updatedAt: result.outBinds.updatedAt[0],
    };
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      const field = classifyUniqueViolation(err);
      throw new DuplicateFieldError(field || 'unknown');
    }
    throw err;
  } finally {
    if (conn) await conn.close();
  }
}

// PATCH /api/users/:id — ADMIN-only profile update. Only ever binds
// fullName/email/role; the caller (routes/users.js) is responsible for never
// passing anything else through, but this function's SQL text is itself a
// second, independent guarantee — there is no column here a caller could
// reach for userId/username/password/passwordHash/twoFactorSecret/createdAt
// even by mistake. COALESCE lets each field be updated independently: pass
// null for a field to leave it unchanged. Returns null if the user does not
// exist (rowsAffected === 0); callers map that to 404.
async function updateUser(userId, { fullName, email, role }) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE users
       SET full_name = COALESCE(:fullName, full_name),
           email = COALESCE(:email, email),
           role = COALESCE(:role, role),
           updated_at = SYSTIMESTAMP
       WHERE user_id = :userId`,
      {
        fullName: fullName !== undefined ? fullName : null,
        email: email !== undefined ? email : null,
        role: role !== undefined ? role : null,
        userId,
      },
      { autoCommit: true }
    );

    if (result.rowsAffected === 0) {
      return null;
    }

    return findByIdForAdmin(userId);
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      const field = classifyUniqueViolation(err);
      throw new DuplicateFieldError(field || 'unknown');
    }
    throw err;
  } finally {
    if (conn) await conn.close();
  }
}

// PATCH /api/users/:id/status — ADMIN-only active/inactive toggle. Updates
// exactly one column. Returns false if the user does not exist
// (rowsAffected === 0); callers map that to 404.
async function updateUserStatus(userId, isActive) {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE users
       SET is_active = :isActive,
           updated_at = SYSTIMESTAMP
       WHERE user_id = :userId`,
      { isActive: isActive ? 1 : 0, userId },
      { autoCommit: true }
    );
    return result.rowsAffected > 0;
  } finally {
    if (conn) await conn.close();
  }
}

module.exports = {
  createUser,
  DuplicateFieldError,
  findByUsername,
  findById,
  listUsers,
  findByIdForAdmin,
  createUserAsAdmin,
  updateUser,
  updateUserStatus,
};
