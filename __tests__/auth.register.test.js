require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

// Unique per test run so repeated runs never collide with leftover rows,
// and so this suite can never touch the pre-existing legitimate user.
const RUN_ID = Date.now();
const testUsernames = [];

function uniqueUsername(label) {
  const username = `test_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_${RUN_ID}_${label}@example.com`;
}

async function queryUserByUsername(username) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT user_id, username, email, role, is_active, password_hash,
              failed_login_count, two_factor_enabled
       FROM users WHERE username = :username`,
      { username }
    );
    return result.rows[0] || null;
  } finally {
    await conn.close();
  }
}

async function countUsersByUsername(username) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(`SELECT COUNT(*) AS CNT FROM users WHERE username = :username`, {
      username,
    });
    return result.rows[0].CNT;
  } finally {
    await conn.close();
  }
}

async function latestAuditEventForUsername(username) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT * FROM auth_audit_log
       WHERE username_attempted = :username
       ORDER BY auth_log_id DESC
       FETCH FIRST 1 ROWS ONLY`,
      { username }
    );
    return result.rows[0] || null;
  } finally {
    await conn.close();
  }
}

async function deleteTestUsers() {
  if (testUsernames.length === 0) return;
  const conn = await getConnection();
  try {
    for (const username of testUsernames) {
      await conn.execute(`DELETE FROM auth_audit_log WHERE username_attempted = :username`, {
        username,
      });
      await conn.execute(`DELETE FROM users WHERE username = :username`, { username });
    }
    await conn.commit();
  } finally {
    await conn.close();
  }
}

beforeAll(async () => {
  await initPool();
});

afterAll(async () => {
  // Clean up only the rows this suite created — never touches the
  // pre-existing legitimate user or any business data.
  await deleteTestUsers();
  await closePool();
});

describe('POST /api/auth/register', () => {
  test('1. successful registration returns 201, persists a hashed password, and omits secrets', async () => {
    const username = uniqueUsername('success');
    const email = uniqueEmail('success');

    const res = await request(app).post('/api/auth/register').send({
      username,
      password: 'CorrectHorse123',
      fullName: 'Test Success',
      email,
    });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      username,
      fullName: 'Test Success',
      email,
      role: 'ASSOCIATE',
      active: true,
    });
    expect(res.body.password).toBeUndefined();
    expect(res.body.passwordHash).toBeUndefined();
    expect(res.body.password_hash).toBeUndefined();

    const row = await queryUserByUsername(username);
    expect(row).not.toBeNull();
    expect(row.PASSWORD_HASH).toMatch(/^\$2[aby]\$12\$/);
    expect(row.PASSWORD_HASH).not.toBe('CorrectHorse123');
  });

  test('2. duplicate username returns 409, does not create a second row, and audits REGISTER_FAILURE', async () => {
    const username = uniqueUsername('dupuser');
    const firstEmail = uniqueEmail('dupuser-1');
    const secondEmail = uniqueEmail('dupuser-2');

    const first = await request(app).post('/api/auth/register').send({
      username,
      password: 'CorrectHorse123',
      fullName: 'First',
      email: firstEmail,
    });
    expect(first.status).toBe(201);

    const second = await request(app).post('/api/auth/register').send({
      username,
      password: 'CorrectHorse123',
      fullName: 'Second',
      email: secondEmail,
    });

    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/username/i);

    const count = await countUsersByUsername(username);
    expect(count).toBe(1);

    const auditEvent = await latestAuditEventForUsername(username);
    expect(auditEvent.EVENT_TYPE).toBe('REGISTER_FAILURE');
    expect(auditEvent.EVENT_RESULT).toBe('FAILURE');
    expect(auditEvent.DETAIL).toBe('duplicate_username');
  });

  test('3. duplicate email returns 409, does not create a second row, and audits REGISTER_FAILURE', async () => {
    const firstUsername = uniqueUsername('dupemail-1');
    const secondUsername = uniqueUsername('dupemail-2');
    const email = uniqueEmail('dupemail');

    const first = await request(app).post('/api/auth/register').send({
      username: firstUsername,
      password: 'CorrectHorse123',
      fullName: 'First',
      email,
    });
    expect(first.status).toBe(201);

    const second = await request(app).post('/api/auth/register').send({
      username: secondUsername,
      password: 'CorrectHorse123',
      fullName: 'Second',
      email,
    });

    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/email/i);

    const count = await countUsersByUsername(secondUsername);
    expect(count).toBe(0);

    const auditEvent = await latestAuditEventForUsername(secondUsername);
    expect(auditEvent.EVENT_TYPE).toBe('REGISTER_FAILURE');
    expect(auditEvent.EVENT_RESULT).toBe('FAILURE');
    expect(auditEvent.DETAIL).toBe('duplicate_email');
  });

  test('4. validation failure returns 400 and inserts no user', async () => {
    const username = uniqueUsername('badinput');

    const res = await request(app).post('/api/auth/register').send({
      username,
      password: 'short',
      fullName: 'Bad Input',
      email: uniqueEmail('badinput'),
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeTruthy();

    const count = await countUsersByUsername(username);
    expect(count).toBe(0);
  });

  test('5. mass-assignment attempts are ignored', async () => {
    const username = uniqueUsername('massassign');
    const email = uniqueEmail('massassign');

    const res = await request(app).post('/api/auth/register').send({
      username,
      password: 'CorrectHorse123',
      fullName: 'Mass Assign',
      email,
      role: 'ADMIN',
      isActive: true,
      twoFactorEnabled: true,
      failedLoginCount: 999,
    });

    expect(res.status).toBe(201);
    expect(res.body.role).toBe('ASSOCIATE');
    expect(res.body.active).toBe(true);

    const row = await queryUserByUsername(username);
    expect(row.ROLE).toBe('ASSOCIATE');
    expect(row.IS_ACTIVE).toBe(1);
    expect(row.TWO_FACTOR_ENABLED).toBe(0);
    expect(row.FAILED_LOGIN_COUNT).toBe(0);
  });

  test('6. concurrent duplicate registration: exactly one 201, one 409, one row', async () => {
    const username = uniqueUsername('race');
    const email = uniqueEmail('race');

    const payload = {
      username,
      password: 'CorrectHorse123',
      fullName: 'Race Condition',
      email,
    };

    const [resA, resB] = await Promise.all([
      request(app).post('/api/auth/register').send(payload),
      request(app).post('/api/auth/register').send(payload),
    ]);

    const statuses = [resA.status, resB.status].sort();
    expect(statuses).toEqual([201, 409]);

    const count = await countUsersByUsername(username);
    expect(count).toBe(1);
  });

  test('7a. recordAuthEvent() itself never throws, even when the audit insert fails', async () => {
    const { recordAuthEvent } = require('../services/authAuditService');

    // Force a real DB-level failure for this one insert (invalid event_type
    // value — violates CK_AUTH_AUDIT_LOG_EVENT_TYPE) to prove the function
    // swallows the error internally rather than merely "usually" not throwing.
    await expect(
      recordAuthEvent({
        usernameAttempted: uniqueUsername('auditfail-direct'),
        eventType: 'NOT_A_REAL_EVENT_TYPE',
        eventResult: 'FAILURE',
        detail: 'validation_error',
      })
    ).resolves.toBeUndefined();
  });

  test('7b. registration responds 201 without waiting on the audit write (fire-and-forget)', async () => {
    const username = uniqueUsername('auditasync');
    const email = uniqueEmail('auditasync');
    const authAuditService = require('../services/authAuditService');

    let auditResolved = false;
    const spy = jest.spyOn(authAuditService, 'recordAuthEvent').mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            auditResolved = true;
            resolve();
          }, 200);
        })
    );

    try {
      const res = await request(app).post('/api/auth/register').send({
        username,
        password: 'CorrectHorse123',
        fullName: 'Audit Async',
        email,
      });

      // The response must come back before the (intentionally slow) audit
      // write resolves — proving the route does not await it on success.
      expect(res.status).toBe(201);
      expect(auditResolved).toBe(false);

      const count = await countUsersByUsername(username);
      expect(count).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });
});
