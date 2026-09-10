// Read-only validation for db/migrations/001_auth_foundation.sql.
//
// Checks schema state only — runs no DDL, no DML, inserts no rows.
// Usage: node db/validate_auth_foundation.js  (run from the project root,
// with .env configured per .env.example)

require('dotenv').config();
const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

const EXPECTED_USERS_COLUMNS = [
  'FAILED_LOGIN_COUNT',
  'LOCKOUT_END_AT',
  'TWO_FACTOR_ENABLED',
  'TWO_FACTOR_SECRET',
  'UPDATED_AT',
];

let failures = 0;

function check(label, condition, detail) {
  const status = condition ? 'PASS' : 'FAIL';
  if (!condition) failures += 1;
  console.log(`[${status}] ${label}${detail ? ' — ' + detail : ''}`);
}

async function main() {
  const conn = await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectString: process.env.DB_CONNECT_STRING,
  });

  try {
    // 1. USERS has the new columns
    const cols = await conn.execute(
      `SELECT column_name, nullable, data_default FROM user_tab_columns WHERE table_name = 'USERS'`
    );
    const colNames = cols.rows.map((r) => r.COLUMN_NAME);
    for (const name of EXPECTED_USERS_COLUMNS) {
      check(`USERS has column ${name}`, colNames.includes(name));
    }

    // 2. Existing USERS PK/unique constraints remain
    const userConstraints = await conn.execute(
      `SELECT constraint_name, constraint_type, status FROM user_constraints
       WHERE table_name = 'USERS' AND constraint_type IN ('P','U')`
    );
    check(
      'USERS retains a PRIMARY KEY constraint',
      userConstraints.rows.some((r) => r.CONSTRAINT_TYPE === 'P' && r.STATUS === 'ENABLED'),
      JSON.stringify(userConstraints.rows)
    );

    // 3. New CHECK constraints exist
    const checks = await conn.execute(
      `SELECT constraint_name, status FROM user_constraints
       WHERE table_name = 'USERS' AND constraint_name IN
       ('CK_USERS_FAILED_LOGIN_COUNT','CK_USERS_TWO_FACTOR_ENABLED')`
    );
    check(
      'CK_USERS_FAILED_LOGIN_COUNT and CK_USERS_TWO_FACTOR_ENABLED exist and are enabled',
      checks.rows.length === 2 && checks.rows.every((r) => r.STATUS === 'ENABLED'),
      JSON.stringify(checks.rows)
    );

    // 4. FK_INVENTORY_USER and FK_SALES_CASHIER remain valid
    const fks = await conn.execute(
      `SELECT constraint_name, table_name, status FROM user_constraints
       WHERE constraint_name IN ('FK_INVENTORY_USER','FK_SALES_CASHIER')`
    );
    check(
      'FK_INVENTORY_USER exists and is ENABLED',
      fks.rows.some((r) => r.CONSTRAINT_NAME === 'FK_INVENTORY_USER' && r.STATUS === 'ENABLED'),
      JSON.stringify(fks.rows.filter((r) => r.CONSTRAINT_NAME === 'FK_INVENTORY_USER'))
    );
    check(
      'FK_SALES_CASHIER exists and is ENABLED',
      fks.rows.some((r) => r.CONSTRAINT_NAME === 'FK_SALES_CASHIER' && r.STATUS === 'ENABLED'),
      JSON.stringify(fks.rows.filter((r) => r.CONSTRAINT_NAME === 'FK_SALES_CASHIER'))
    );

    // 5. AUTH_AUDIT_LOG exists
    const authLogTable = await conn.execute(
      `SELECT table_name FROM user_tables WHERE table_name = 'AUTH_AUDIT_LOG'`
    );
    check('AUTH_AUDIT_LOG table exists', authLogTable.rows.length === 1);

    if (authLogTable.rows.length === 1) {
      // 5a. Columns
      const authCols = await conn.execute(
        `SELECT column_name, data_type, nullable FROM user_tab_columns WHERE table_name = 'AUTH_AUDIT_LOG'`
      );
      const expectedAuthCols = [
        'AUTH_LOG_ID', 'USER_ID', 'USERNAME_ATTEMPTED', 'EVENT_TYPE', 'EVENT_RESULT',
        'IP_ADDRESS', 'USER_AGENT', 'DETAIL', 'CREATED_AT',
      ];
      const authColNames = authCols.rows.map((r) => r.COLUMN_NAME);
      check(
        'AUTH_AUDIT_LOG has all expected columns',
        expectedAuthCols.every((c) => authColNames.includes(c)),
        authColNames.join(', ')
      );

      // 5b. PK
      const authPk = await conn.execute(
        `SELECT constraint_name, status FROM user_constraints
         WHERE table_name = 'AUTH_AUDIT_LOG' AND constraint_type = 'P'`
      );
      check('AUTH_AUDIT_LOG has a PRIMARY KEY', authPk.rows.length === 1 && authPk.rows[0].STATUS === 'ENABLED');

      // 5c. FK to USERS
      const authFk = await conn.execute(
        `SELECT constraint_name, status FROM user_constraints
         WHERE constraint_name = 'FK_AUTH_AUDIT_LOG_USER'`
      );
      check(
        'FK_AUTH_AUDIT_LOG_USER exists and is ENABLED',
        authFk.rows.length === 1 && authFk.rows[0].STATUS === 'ENABLED'
      );

      // 5d. CHECK constraints
      const authChecks = await conn.execute(
        `SELECT constraint_name, status FROM user_constraints
         WHERE table_name = 'AUTH_AUDIT_LOG' AND constraint_name IN
         ('CK_AUTH_AUDIT_LOG_EVENT_TYPE','CK_AUTH_AUDIT_LOG_EVENT_RESULT')`
      );
      check(
        'AUTH_AUDIT_LOG EVENT_TYPE/EVENT_RESULT check constraints exist and are enabled',
        authChecks.rows.length === 2 && authChecks.rows.every((r) => r.STATUS === 'ENABLED'),
        JSON.stringify(authChecks.rows)
      );

      // 5e. Indexes
      const authIdx = await conn.execute(
        `SELECT index_name FROM user_indexes WHERE table_name = 'AUTH_AUDIT_LOG'`
      );
      const idxNames = authIdx.rows.map((r) => r.INDEX_NAME);
      check(
        'IX_AUTH_AUDIT_LOG_USER_ID exists',
        idxNames.includes('IX_AUTH_AUDIT_LOG_USER_ID'),
        idxNames.join(', ')
      );
      check(
        'IX_AUTH_AUDIT_LOG_CREATED_AT exists',
        idxNames.includes('IX_AUTH_AUDIT_LOG_CREATED_AT'),
        idxNames.join(', ')
      );
    }

    // 6. Generic AUDIT_LOG table untouched — just confirm it still exists if it did before
    const genericAuditLog = await conn.execute(
      `SELECT table_name FROM user_tables WHERE table_name = 'AUDIT_LOG'`
    );
    console.log(
      `[INFO] Generic AUDIT_LOG table present: ${genericAuditLog.rows.length === 1} (not modified by this migration)`
    );

    // 7. Business tables untouched — report row counts only (read-only, no writes)
    for (const t of ['PRODUCTS', 'SALES', 'INVENTORY', 'CATEGORIES', 'UNITS']) {
      try {
        const r = await conn.execute(`SELECT COUNT(*) AS CNT FROM ${t}`);
        console.log(`[INFO] ${t} row count: ${r.rows[0].CNT}`);
      } catch (e) {
        console.log(`[INFO] ${t} not present or not queryable: ${e.message}`);
      }
    }

    console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    await conn.close();
  }
}

main().catch((e) => {
  console.error('VALIDATION ERROR:', e.message);
  process.exit(1);
});
