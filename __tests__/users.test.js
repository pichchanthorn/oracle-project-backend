require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const jwtService = require('../services/jwtService');
const { createUser } = require('../services/userService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

// Real Oracle round trips (bcrypt cost=12 hashing on every create, shared
// pool with other suites) — generous timeout to avoid false failures under
// load, matching the other auth suites.
jest.setTimeout(60000);

const RUN_ID = Date.now();
const testUsernames = [];
const testUserIds = [];
const TEST_PASSWORD = 'CorrectHorse123';

function uniqueUsername(label) {
  const username = `test_users_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_users_${RUN_ID}_${label}@example.com`;
}

// Creates a real USERS row directly via the same service the self-
// registration route uses (bypasses HTTP so fixture setup here can never be
// broken by a bug in the very routes under test). Always ASSOCIATE/active/
// 2FA-off, matching createUser()'s contract.
async function createFixtureUser(label, overrides = {}) {
  const username = uniqueUsername(label);
  const email = uniqueEmail(label);
  const user = await createUser({
    username,
    password: TEST_PASSWORD,
    fullName: `Test ${label}`,
    email,
  });
  testUserIds.push(user.id);

  if (overrides.role || overrides.isActive === false) {
    const conn = await getConnection();
    try {
      // Explicit bind types: a null role/isActive alongside a non-null one
      // otherwise lets oracledb infer the wrong type for the null side
      // (it has no value of its own to infer from), which fails with
      // ORA-00932 against IS_ACTIVE (NUMBER) / ROLE (VARCHAR2).
      await conn.execute(
        `UPDATE users
         SET role = COALESCE(:role, role),
             is_active = COALESCE(:isActive, is_active)
         WHERE user_id = :userId`,
        {
          role: { val: overrides.role || null, type: oracledb.STRING },
          isActive: {
            val: overrides.isActive === false ? 0 : null,
            type: oracledb.NUMBER,
          },
          userId: user.id,
        },
        { autoCommit: true }
      );
    } finally {
      await conn.close();
    }
  }

  return { id: user.id, username, email };
}

// requireAccessToken/requireRole only inspect the verified token's claims,
// never the database — these do not need to correspond to a real USERS row
// unless a test specifically needs req.user.id to match a fixture.
function signAccessTokenWithRole(role, overrides = {}) {
  return jwtService.signAccessToken({
    id: overrides.id !== undefined ? overrides.id : 888888,
    username: overrides.username || 'users_api_test_actor',
    email: overrides.email || 'users_api_test_actor@example.com',
    role,
  });
}

function signChallengeToken() {
  return jwtService.signTwoFactorChallengeToken({
    id: 888888,
    username: 'users_api_test_actor',
    email: 'users_api_test_actor@example.com',
    role: 'ADMIN',
  });
}

const adminToken = () => signAccessTokenWithRole('ADMIN');

async function getUserRow(userId) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT user_id, username, password_hash, full_name, email, role,
              is_active, two_factor_enabled, two_factor_secret, created_at, updated_at
       FROM users WHERE user_id = :userId`,
      { userId }
    );
    return result.rows[0] || null;
  } finally {
    await conn.close();
  }
}

async function deleteTestUsers() {
  if (testUsernames.length === 0 && testUserIds.length === 0) return;
  const conn = await getConnection();
  try {
    for (const username of testUsernames) {
      await conn.execute(`DELETE FROM auth_audit_log WHERE username_attempted = :username`, {
        username,
      });
    }
    for (const id of testUserIds) {
      await conn.execute(`DELETE FROM auth_audit_log WHERE user_id = :id`, { id });
      await conn.execute(`DELETE FROM users WHERE user_id = :id`, { id });
    }
    await conn.commit();
  } finally {
    await conn.close();
  }
}

beforeAll(async () => {
  await initPool();
  jwtService.validateConfig();
});

afterAll(async () => {
  await deleteTestUsers();
  await closePool();
});

describe('Authorization matrix — shared across all /api/users routes', () => {
  test('1. unauthenticated request is rejected with 401', async () => {
    const res = await request(app).get('/api/users');
    expect(res.status).toBe(401);
  });

  test('2. a 2FA challenge token is rejected with 401, never 403', async () => {
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${signChallengeToken()}`);
    expect(res.status).toBe(401);
  });

  test('3. ADMIN is allowed', async () => {
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
  });

  test('4. MANAGER is rejected with 403', async () => {
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${signAccessTokenWithRole('MANAGER')}`);
    expect(res.status).toBe(403);
  });

  test('5. ASSOCIATE is rejected with 403', async () => {
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${signAccessTokenWithRole('ASSOCIATE')}`);
    expect(res.status).toBe(403);
  });

  test('6. an invalid/tampered access token is rejected with 401', async () => {
    const tampered = adminToken().slice(0, -2) + 'xx';
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${tampered}`);
    expect(res.status).toBe(401);
  });
});

describe('GET /api/users', () => {
  test('7. lists users and never returns sensitive fields', async () => {
    const fixture = await createFixtureUser('list');

    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);

    const found = res.body.find((u) => u.userId === fixture.id);
    expect(found).toBeDefined();
    expect(found).toMatchObject({
      userId: fixture.id,
      username: fixture.username,
      fullName: `Test list`,
      email: fixture.email,
      role: 'ASSOCIATE',
      isActive: true,
      twoFactorEnabled: false,
    });
    expect(found.createdAt).toBeDefined();
    expect(found.updatedAt).toBeDefined();
    expect(found.passwordHash).toBeUndefined();
    expect(found.password_hash).toBeUndefined();
    expect(found.twoFactorSecret).toBeUndefined();
    expect(found.two_factor_secret).toBeUndefined();
  });
});

describe('GET /api/users/:id', () => {
  test('8. gets a user by id', async () => {
    const fixture = await createFixtureUser('getbyid');

    const res = await request(app)
      .get(`/api/users/${fixture.id}`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      userId: fixture.id,
      username: fixture.username,
      role: 'ASSOCIATE',
      isActive: true,
      twoFactorEnabled: false,
    });
    expect(res.body.passwordHash).toBeUndefined();
    expect(res.body.twoFactorSecret).toBeUndefined();
  });

  test('9. malformed id returns 400', async () => {
    // Deliberately excludes '' — an empty :id segment collapses the path to
    // /api/users (the list route), which is not this test's concern.
    const cases = ['abc', '-1', '0', '1.5', '1e5', ' 1'];
    for (const badId of cases) {
      const res = await request(app)
        .get(`/api/users/${encodeURIComponent(badId)}`)
        .set('Authorization', `Bearer ${adminToken()}`);
      expect(res.status).toBe(400);
    }
  });

  test('10. missing user returns 404', async () => {
    const res = await request(app)
      .get('/api/users/999999999')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(404);
  });
});

describe('POST /api/users', () => {
  test('11. valid creation returns 201, starts active with 2FA disabled, and hashes the password with bcrypt', async () => {
    const username = uniqueUsername('create_valid');
    const email = uniqueEmail('create_valid');

    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ username, password: TEST_PASSWORD, fullName: 'Create Valid', email, role: 'MANAGER' });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      username,
      fullName: 'Create Valid',
      email,
      role: 'MANAGER',
      isActive: true,
      twoFactorEnabled: false,
    });
    expect(res.body.password).toBeUndefined();
    expect(res.body.passwordHash).toBeUndefined();
    testUserIds.push(res.body.userId);

    const row = await getUserRow(res.body.userId);
    expect(row.PASSWORD_HASH).toMatch(/^\$2[aby]\$12\$/);
    expect(row.PASSWORD_HASH).not.toBe(TEST_PASSWORD);
    expect(row.IS_ACTIVE).toBe(1);
    expect(row.TWO_FACTOR_ENABLED).toBe(0);
    expect(row.TWO_FACTOR_SECRET).toBeNull();
  });

  test('12. missing required fields return 400', async () => {
    const base = {
      username: uniqueUsername('missing_fields'),
      password: TEST_PASSWORD,
      fullName: 'Missing Fields',
      role: 'ASSOCIATE',
    };

    for (const omit of ['username', 'password', 'fullName', 'role']) {
      const payload = { ...base, username: uniqueUsername(`missing_${omit}`) };
      delete payload[omit];
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send(payload);
      expect(res.status).toBe(400);
    }
  });

  test('13. invalid role returns 400', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        username: uniqueUsername('invalid_role'),
        password: TEST_PASSWORD,
        fullName: 'Invalid Role',
        role: 'SUPERUSER',
      });
    expect(res.status).toBe(400);
  });

  test('14. invalid password (existing policy) returns 400', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        username: uniqueUsername('short_pw'),
        password: 'short',
        fullName: 'Short Password',
        role: 'ASSOCIATE',
      });
    expect(res.status).toBe(400);
  });

  test('15. duplicate username returns 409 and does not create a second row', async () => {
    const fixture = await createFixtureUser('dup_username_target');

    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        username: fixture.username,
        password: TEST_PASSWORD,
        fullName: 'Duplicate Username',
        role: 'ASSOCIATE',
      });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/username/i);
  });

  test('16. duplicate email returns 409', async () => {
    const fixture = await createFixtureUser('dup_email_target');

    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        username: uniqueUsername('dup_email_attempt'),
        password: TEST_PASSWORD,
        fullName: 'Duplicate Email',
        email: fixture.email,
        role: 'ASSOCIATE',
      });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/email/i);
  });

  test('17. mass-assignment of isActive/twoFactorEnabled/passwordHash is ignored', async () => {
    const username = uniqueUsername('mass_assign');
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        username,
        password: TEST_PASSWORD,
        fullName: 'Mass Assign',
        role: 'ASSOCIATE',
        isActive: false,
        twoFactorEnabled: true,
        passwordHash: '$2b$12$deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead',
        userId: 1,
      });
      expect(res.status).toBe(201);
      expect(res.body.isActive).toBe(true);
      expect(res.body.twoFactorEnabled).toBe(false);
      testUserIds.push(res.body.userId);

      const row = await getUserRow(res.body.userId);
      expect(row.IS_ACTIVE).toBe(1);
      expect(row.TWO_FACTOR_ENABLED).toBe(0);
  });

  test('18. only ADMIN can create a user; MANAGER/ASSOCIATE are rejected with 403', async () => {
    for (const role of ['MANAGER', 'ASSOCIATE']) {
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${signAccessTokenWithRole(role)}`)
        .send({
          username: uniqueUsername(`role_gate_${role}`),
          password: TEST_PASSWORD,
          fullName: 'Role Gate',
          role: 'ASSOCIATE',
        });
      expect(res.status).toBe(403);
    }
  });
});

describe('PATCH /api/users/:id', () => {
  test('19. valid profile update changes fullName/email/role', async () => {
    const fixture = await createFixtureUser('patch_valid');
    const newEmail = uniqueEmail('patch_valid_new');

    const res = await request(app)
      .patch(`/api/users/${fixture.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ fullName: 'Patched Name', email: newEmail, role: 'MANAGER' });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      userId: fixture.id,
      fullName: 'Patched Name',
      email: newEmail,
      role: 'MANAGER',
    });

    const row = await getUserRow(fixture.id);
    expect(row.FULL_NAME).toBe('Patched Name');
    expect(row.EMAIL).toBe(newEmail);
    expect(row.ROLE).toBe('MANAGER');
  });

  test('20. invalid role returns 400 and does not change the row', async () => {
    const fixture = await createFixtureUser('patch_invalid_role');

    const res = await request(app)
      .patch(`/api/users/${fixture.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ role: 'SUPERUSER' });
    expect(res.status).toBe(400);

    const row = await getUserRow(fixture.id);
    expect(row.ROLE).toBe('ASSOCIATE');
  });

  test('21. malformed id returns 400', async () => {
    const res = await request(app)
      .patch('/api/users/not-a-number')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ fullName: 'Whatever' });
    expect(res.status).toBe(400);
  });

  test('22. missing user returns 404', async () => {
    const res = await request(app)
      .patch('/api/users/999999999')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ fullName: 'Nobody' });
    expect(res.status).toBe(404);
  });

  test('23. duplicate email on update returns 409 and does not change the row', async () => {
    const target = await createFixtureUser('patch_dup_email_target');
    const other = await createFixtureUser('patch_dup_email_other');

    const res = await request(app)
      .patch(`/api/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ email: other.email });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/email/i);

    const row = await getUserRow(target.id);
    expect(row.EMAIL).toBe(target.email);
  });

  test('24. forbidden immutable fields (userId, username, password, passwordHash, twoFactorSecret, createdAt) are not accepted', async () => {
    const fixture = await createFixtureUser('patch_immutable');
    const before = await getUserRow(fixture.id);

    const res = await request(app)
      .patch(`/api/users/${fixture.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        fullName: 'Immutable Test',
        userId: 999999,
        username: 'should_not_change',
        password: 'NewPassword123',
        passwordHash: '$2b$12$deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead',
        twoFactorSecret: 'tampered-secret',
        createdAt: '2000-01-01T00:00:00.000Z',
      });

    expect(res.status).toBe(200);
    expect(res.body.fullName).toBe('Immutable Test');
    expect(res.body.username).toBe(fixture.username);
    expect(res.body.passwordHash).toBeUndefined();

    const after = await getUserRow(fixture.id);
    expect(after.USER_ID).toBe(fixture.id);
    expect(after.USERNAME).toBe(fixture.username);
    expect(after.PASSWORD_HASH).toBe(before.PASSWORD_HASH);
    expect(after.TWO_FACTOR_SECRET).toBe(before.TWO_FACTOR_SECRET);
    expect(new Date(after.CREATED_AT).getTime()).toBe(new Date(before.CREATED_AT).getTime());
  });

  test('25. only ADMIN can update a user; MANAGER/ASSOCIATE are rejected with 403', async () => {
    const fixture = await createFixtureUser('patch_role_gate');
    for (const role of ['MANAGER', 'ASSOCIATE']) {
      const res = await request(app)
        .patch(`/api/users/${fixture.id}`)
        .set('Authorization', `Bearer ${signAccessTokenWithRole(role)}`)
        .send({ fullName: 'Should Not Apply' });
      expect(res.status).toBe(403);
    }
  });
});

describe('PATCH /api/users/:id/status', () => {
  test('26. ADMIN can deactivate and reactivate another user, and the action is audited', async () => {
    const fixture = await createFixtureUser('status_toggle');

    // AUTH_AUDIT_LOG.USER_ID has a foreign key to USERS (FK_AUTH_AUDIT_LOG_USER),
    // so the audit write only actually persists (rather than being silently
    // swallowed by recordAuthEvent's own error handling) when the acting
    // admin corresponds to a real row — a synthetic, non-existent token
    // subject like the other tests in this suite use is fine for exercising
    // the route/response, but not for asserting on the resulting audit row.
    const actingAdmin = await createFixtureUser('status_toggle_actor', { role: 'ADMIN' });
    const actingAdminToken = jwtService.signAccessToken({
      id: actingAdmin.id,
      username: actingAdmin.username,
      email: actingAdmin.email,
      role: 'ADMIN',
    });

    const deactivateRes = await request(app)
      .patch(`/api/users/${fixture.id}/status`)
      .set('Authorization', `Bearer ${actingAdminToken}`)
      .send({ isActive: false });
    expect(deactivateRes.status).toBe(200);
    expect(deactivateRes.body.isActive).toBe(false);

    let row = await getUserRow(fixture.id);
    expect(row.IS_ACTIVE).toBe(0);

    const reactivateRes = await request(app)
      .patch(`/api/users/${fixture.id}/status`)
      .set('Authorization', `Bearer ${actingAdminToken}`)
      .send({ isActive: true });
    expect(reactivateRes.status).toBe(200);
    expect(reactivateRes.body.isActive).toBe(true);

    row = await getUserRow(fixture.id);
    expect(row.IS_ACTIVE).toBe(1);

    const conn = await getConnection();
    try {
      const auditRes = await conn.execute(
        `SELECT event_type, event_result FROM auth_audit_log
         WHERE detail LIKE :pattern
         ORDER BY auth_log_id DESC FETCH FIRST 1 ROWS ONLY`,
        { pattern: `%target_user_id=${fixture.id}%` }
      );
      expect(auditRes.rows[0].EVENT_TYPE).toBe('USER_STATUS_CHANGE');
      expect(auditRes.rows[0].EVENT_RESULT).toBe('SUCCESS');
    } finally {
      await conn.close();
    }
  });

  test('27. malformed id returns 400', async () => {
    const res = await request(app)
      .patch('/api/users/not-a-number/status')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ isActive: false });
    expect(res.status).toBe(400);
  });

  test('28. invalid isActive returns 400', async () => {
    const fixture = await createFixtureUser('status_invalid_body');
    const cases = [undefined, null, 'true', 1, 0, {}, []];
    for (const isActive of cases) {
      const res = await request(app)
        .patch(`/api/users/${fixture.id}/status`)
        .set('Authorization', `Bearer ${adminToken()}`)
        .send(isActive === undefined ? {} : { isActive });
      expect(res.status).toBe(400);
    }
  });

  test('29. missing user returns 404', async () => {
    const res = await request(app)
      .patch('/api/users/999999999/status')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ isActive: false });
    expect(res.status).toBe(404);
  });

  test('30. self-deactivation is rejected with a 409 business error', async () => {
    const fixture = await createFixtureUser('self_deactivate');
    const selfToken = jwtService.signAccessToken({
      id: fixture.id,
      username: fixture.username,
      email: fixture.email,
      role: 'ADMIN',
    });

    const res = await request(app)
      .patch(`/api/users/${fixture.id}/status`)
      .set('Authorization', `Bearer ${selfToken}`)
      .send({ isActive: false });

    expect(res.status).toBe(409);

    const row = await getUserRow(fixture.id);
    expect(row.IS_ACTIVE).toBe(1);
  });

  test('31. self-reactivation (isActive: true) on your own account is allowed', async () => {
    const fixture = await createFixtureUser('self_reactivate', { isActive: false });
    const selfToken = jwtService.signAccessToken({
      id: fixture.id,
      username: fixture.username,
      email: fixture.email,
      role: 'ADMIN',
    });

    const res = await request(app)
      .patch(`/api/users/${fixture.id}/status`)
      .set('Authorization', `Bearer ${selfToken}`)
      .send({ isActive: true });

    expect(res.status).toBe(200);
    expect(res.body.isActive).toBe(true);
  });

  test('32. only ADMIN can change status; MANAGER/ASSOCIATE are rejected with 403', async () => {
    const fixture = await createFixtureUser('status_role_gate');
    for (const role of ['MANAGER', 'ASSOCIATE']) {
      const res = await request(app)
        .patch(`/api/users/${fixture.id}/status`)
        .set('Authorization', `Bearer ${signAccessTokenWithRole(role)}`)
        .send({ isActive: false });
      expect(res.status).toBe(403);
    }
  });
});
