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

module.exports = { createUser, DuplicateFieldError };
