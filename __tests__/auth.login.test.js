require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const jwt = require('jsonwebtoken');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const { createUser } = require('../services/userService');
const jwtService = require('../services/jwtService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

const RUN_ID = Date.now();
const testUsernames = [];
const TEST_PASSWORD = 'CorrectHorse123';

function uniqueUsername(label) {
  const username = `test_login_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_login_${RUN_ID}_${label}@example.com`;
}

async function createTestUser(label, overrides = {}) {
  const username = uniqueUsername(label);
  const email = uniqueEmail(label);
  const user = await createUser({
    username,
    password: TEST_PASSWORD,
    fullName: `Test ${label}`,
    email,
  });

  if (Object.keys(overrides).length > 0) {
    const sets = [];
    const binds = { id: user.id };
    if ('isActive' in overrides) {
      sets.push('is_active = :isActive');
      binds.isActive = overrides.isActive ? 1 : 0;
    }
    if ('twoFactorEnabled' in overrides) {
      sets.push('two_factor_enabled = :twoFactorEnabled');
      binds.twoFactorEnabled = overrides.twoFactorEnabled ? 1 : 0;
    }
    if ('failedLoginCount' in overrides) {
      sets.push('failed_login_count = :failedLoginCount');
      binds.failedLoginCount = overrides.failedLoginCount;
    }
    if ('lockoutEndAt' in overrides) {
      sets.push('lockout_end_at = :lockoutEndAt');
      binds.lockoutEndAt = overrides.lockoutEndAt;
    }

    const conn = await getConnection();
    try {
      await conn.execute(`UPDATE users SET ${sets.join(', ')} WHERE user_id = :id`, binds, {
        autoCommit: true,
      });
    } finally {
      await conn.close();
    }
  }

  return { username, email, id: user.id };
}

async function getUserRow(username) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT user_id, username, failed_login_count, lockout_end_at, is_active
       FROM users WHERE username = :username`,
      { username }
    );
    return result.rows[0] || null;
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
  jwtService.validateConfig();
});

afterAll(async () => {
  await deleteTestUsers();
  await closePool();
});

describe('POST /api/auth/login', () => {
  test('1. valid credentials + 2FA disabled → 200 + access token', async () => {
    const { username } = await createTestUser('valid');

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    expect(res.status).toBe(200);
    expect(res.body.requiresTwoFactor).toBe(false);
    expect(typeof res.body.accessToken).toBe('string');
    expect(res.body.user.username).toBe(username);
    expect(res.body.user.password).toBeUndefined();
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  test('2. wrong password → 401 generic message', async () => {
    const { username } = await createTestUser('wrongpw');

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: 'TotallyWrongPassword1',
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBeTruthy();
    expect(res.body.accessToken).toBeUndefined();
  });

  test('3. unknown username → identical generic 401', async () => {
    // Never actually created, but still registered for cleanup since the
    // route records a LOGIN_FAILURE audit row for it regardless.
    const username = uniqueUsername('does_not_exist');

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: 'Whatever123',
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBeTruthy();
    expect(res.body.accessToken).toBeUndefined();
  });

  test('4. inactive user → identical generic 401', async () => {
    const { username } = await createTestUser('inactive', { isActive: false });

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBeTruthy();
  });

  test('5. failed attempt counter increments', async () => {
    const { username } = await createTestUser('increment');

    await request(app).post('/api/auth/login').send({ username, password: 'wrong' });

    const row = await getUserRow(username);
    expect(row.FAILED_LOGIN_COUNT).toBe(1);
  });

  test('6. fifth failed attempt triggers lockout', async () => {
    const { username } = await createTestUser('fifthfail');

    for (let i = 0; i < 4; i++) {
      await request(app).post('/api/auth/login').send({ username, password: 'wrong' });
    }

    const res = await request(app).post('/api/auth/login').send({ username, password: 'wrong' });

    expect(res.status).toBe(423);

    const row = await getUserRow(username);
    expect(row.FAILED_LOGIN_COUNT).toBe(5);
    expect(row.LOCKOUT_END_AT).not.toBeNull();

    const auditEvent = await latestAuditEventForUsername(username);
    expect(auditEvent.EVENT_TYPE).toBe('ACCOUNT_LOCKOUT');
  });

  test('7. locked account → 423, even with the correct password', async () => {
    const lockoutEndAt = new Date(Date.now() + 15 * 60 * 1000);
    const { username } = await createTestUser('locked', {
      failedLoginCount: 5,
      lockoutEndAt,
    });

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    expect(res.status).toBe(423);
    expect(res.body.accessToken).toBeUndefined();
  });

  test('8. successful login resets failed count and lockout', async () => {
    const { username } = await createTestUser('resetcheck', { failedLoginCount: 3 });

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    expect(res.status).toBe(200);

    const row = await getUserRow(username);
    expect(row.FAILED_LOGIN_COUNT).toBe(0);
    expect(row.LOCKOUT_END_AT).toBeNull();
  });

  test('9. access JWT contains required claims', async () => {
    const { username } = await createTestUser('claims');

    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    const decoded = jwt.decode(res.body.accessToken);
    expect(decoded.sub).toBeDefined();
    expect(decoded.username).toBe(username);
    expect(decoded.email).toBeDefined();
    expect(decoded.role).toBe('ASSOCIATE');
    expect(decoded.jti).toBeDefined();
    expect(decoded.token_type).toBe('access');
    expect(decoded.amr).toEqual(['pwd']);
    expect(decoded.iss).toBe(process.env.JWT_ISSUER);
    expect(decoded.aud).toBe(process.env.JWT_AUDIENCE);
  });

  test('10. expired access token rejected', async () => {
    const { username } = await createTestUser('expired');
    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });
    const decoded = jwt.decode(res.body.accessToken);
    const { iat, exp, iss, aud, ...claimsToResign } = decoded;

    // Sign a token identical in shape but already expired, using the same
    // secret/issuer/audience — avoids waiting out a real 15-minute expiry.
    const expiredToken = jwt.sign(claimsToResign, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
      expiresIn: -120, // well past the 30s clock tolerance in jwtService
    });

    expect(() => jwtService.verifyToken(expiredToken)).toThrow();

    const apiRes = await request(app)
      .get('/api/products')
      .set('Authorization', `Bearer ${expiredToken}`);
    expect(apiRes.status).toBe(401);
  });

  test('11. malformed/tampered token rejected', async () => {
    const { username } = await createTestUser('tampered');
    const res = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });
    const tampered = res.body.accessToken.slice(0, -2) + 'xx';

    expect(() => jwtService.verifyToken(tampered)).toThrow();

    const apiRes = await request(app)
      .get('/api/products')
      .set('Authorization', `Bearer ${tampered}`);
    expect(apiRes.status).toBe(401);

    const malformedRes = await request(app)
      .get('/api/products')
      .set('Authorization', 'Bearer not-a-jwt-at-all');
    expect(malformedRes.status).toBe(401);
  });

  test('12. wrong issuer rejected', async () => {
    const token = jwt.sign(
      { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: 'access', amr: ['pwd'] },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', issuer: 'someone-else', audience: process.env.JWT_AUDIENCE, expiresIn: '15m' }
    );

    expect(() => jwtService.verifyToken(token)).toThrow();

    const apiRes = await request(app).get('/api/products').set('Authorization', `Bearer ${token}`);
    expect(apiRes.status).toBe(401);
  });

  test('13. wrong audience rejected', async () => {
    const token = jwt.sign(
      { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: 'access', amr: ['pwd'] },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', issuer: process.env.JWT_ISSUER, audience: 'someone-else', expiresIn: '15m' }
    );

    expect(() => jwtService.verifyToken(token)).toThrow();

    const apiRes = await request(app).get('/api/products').set('Authorization', `Bearer ${token}`);
    expect(apiRes.status).toBe(401);
  });

  test('14. missing/invalid Authorization header → 401', async () => {
    const noHeader = await request(app).get('/api/products');
    expect(noHeader.status).toBe(401);

    const badScheme = await request(app).get('/api/products').set('Authorization', 'Basic abc123');
    expect(badScheme.status).toBe(401);
  });

  test('15. access token accepted by protected business route', async () => {
    const { username } = await createTestUser('accessok');
    const loginRes = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    const apiRes = await request(app)
      .get('/api/products')
      .set('Authorization', `Bearer ${loginRes.body.accessToken}`);
    expect(apiRes.status).toBe(200);
    expect(Array.isArray(apiRes.body)).toBe(true);
  });

  test('16. 2FA challenge token rejected by protected business route', async () => {
    const { username } = await createTestUser('challengereject', { twoFactorEnabled: true });
    const loginRes = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    expect(loginRes.body.requiresTwoFactor).toBe(true);
    expect(typeof loginRes.body.challengeToken).toBe('string');

    const apiRes = await request(app)
      .get('/api/products')
      .set('Authorization', `Bearer ${loginRes.body.challengeToken}`);
    expect(apiRes.status).toBe(401);
  });

  test('17. challenge middleware accepts only challenge-type tokens', async () => {
    const express = require('express');
    const { requireTwoFactorChallengeToken } = require('../middleware/auth');
    const probeApp = express();
    probeApp.get('/probe', requireTwoFactorChallengeToken, (req, res) =>
      res.status(200).json({ pendingLogin: req.pendingLogin })
    );

    const { username } = await createTestUser('challengetype', { twoFactorEnabled: true });
    const challengeLoginRes = await request(app).post('/api/auth/login').send({
      username,
      password: TEST_PASSWORD,
    });

    const { username: username2 } = await createTestUser('challengetype2');
    const accessLoginRes = await request(app).post('/api/auth/login').send({
      username: username2,
      password: TEST_PASSWORD,
    });

    const withChallengeToken = await request(probeApp)
      .get('/probe')
      .set('Authorization', `Bearer ${challengeLoginRes.body.challengeToken}`);
    expect(withChallengeToken.status).toBe(200);
    expect(withChallengeToken.body.pendingLogin.username).toBe(username);

    const withAccessToken = await request(probeApp)
      .get('/probe')
      .set('Authorization', `Bearer ${accessLoginRes.body.accessToken}`);
    expect(withAccessToken.status).toBe(401);
  });

  test('18. login audit events are recorded', async () => {
    const { username } = await createTestUser('auditrecorded');

    await request(app).post('/api/auth/login').send({ username, password: TEST_PASSWORD });

    const auditEvent = await latestAuditEventForUsername(username);
    expect(auditEvent.EVENT_TYPE).toBe('LOGIN_SUCCESS');
    expect(auditEvent.EVENT_RESULT).toBe('SUCCESS');
  });

  test('19. audit failure does not break a successful login', async () => {
    const { username } = await createTestUser('auditfailsafe');
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
      const res = await request(app).post('/api/auth/login').send({
        username,
        password: TEST_PASSWORD,
      });

      expect(res.status).toBe(200);
      expect(auditResolved).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });

  test('20. concurrent failed logins preserve the correct failed-login count', async () => {
    const { username } = await createTestUser('concurrentfail');

    const attempts = Array.from({ length: 4 }, () =>
      request(app).post('/api/auth/login').send({ username, password: 'wrong' })
    );
    await Promise.all(attempts);

    const row = await getUserRow(username);
    expect(row.FAILED_LOGIN_COUNT).toBe(4);
    expect(row.LOCKOUT_END_AT).toBeNull();
  });
});
