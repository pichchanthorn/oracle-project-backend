require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const { createUser } = require('../services/userService');
const jwtService = require('../services/jwtService');
const cryptoService = require('../services/cryptoService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

// Same rationale as the other Phase 4/5 auth test files: several
// bcrypt(cost=12) hashes plus multiple DB round trips per test, against a
// shared, small Oracle pool (db.js: poolMax=5) that gets contended when the
// full suite runs together.
jest.setTimeout(60000);

const RUN_ID = Date.now();
const testUsernames = [];
const testUserIds = [];
const TEST_PASSWORD = 'CorrectHorse123';
const PERIOD_SECONDS = 30;

// A fresh clone per call — never mutate the shared `authenticator`
// singleton (see services/totpService.js) — so tests can generate a code
// for an arbitrary epoch without leaking that override into any other
// concurrent test or into production code's own instance.
function generateSecret() {
  return authenticator.clone({ step: PERIOD_SECONDS, digits: 6, algorithm: 'sha1' }).generateSecret(20);
}

function generateCodeForSecret(secret, epochMs) {
  const instance = authenticator.clone({ step: PERIOD_SECONDS, digits: 6, algorithm: 'sha1' });
  if (epochMs !== undefined) {
    instance.options = { epoch: epochMs };
  }
  return instance.generate(secret);
}

function uniqueUsername(label) {
  const username = `test_disable_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_disable_${RUN_ID}_${label}@example.com`;
}

// Creates a user with 2FA already enabled (bypassing /setup and /enable —
// Phase 4's concern, not Phase 6's) by writing a known plaintext secret,
// encrypted via the real cryptoService, directly into the DB.
async function createTwoFactorUser(label) {
  const username = uniqueUsername(label);
  const email = uniqueEmail(label);
  const user = await createUser({
    username,
    password: TEST_PASSWORD,
    fullName: `Test ${label}`,
    email,
  });
  testUserIds.push(user.id);

  const secret = generateSecret();
  const conn = await getConnection();
  try {
    await conn.execute(
      `UPDATE users SET two_factor_enabled = 1, two_factor_secret = :secret WHERE user_id = :id`,
      { secret: cryptoService.encrypt(secret), id: user.id },
      { autoCommit: true }
    );
  } finally {
    await conn.close();
  }

  return { username, email, id: user.id, secret };
}

async function getAccessTokenViaLogin(username) {
  const res = await request(app).post('/api/auth/login').send({
    username,
    password: TEST_PASSWORD,
  });
  return res.body.accessToken;
}

// 2FA-enabled users get a challenge token from /login, not an access token
// directly — sign one via jwtService for tests that need a genuine access
// token for a 2FA-enabled user without going through the full
// login -> verify-login cycle.
function signAccessTokenFor(user) {
  return jwtService.signAccessToken({
    id: user.id,
    username: user.username,
    email: user.email,
    role: 'ASSOCIATE',
  });
}

async function updateUserRow(userId, sets, binds) {
  const conn = await getConnection();
  try {
    await conn.execute(`UPDATE users SET ${sets} WHERE user_id = :id`, { ...binds, id: userId }, {
      autoCommit: true,
    });
  } finally {
    await conn.close();
  }
}

async function getUserRow(userId) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT user_id, username, two_factor_enabled, two_factor_secret, updated_at, failed_login_count
       FROM users WHERE user_id = :id`,
      { id: userId }
    );
    return result.rows[0] || null;
  } finally {
    await conn.close();
  }
}

async function getAuditEventsForUserId(userId) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT * FROM auth_audit_log WHERE user_id = :userId ORDER BY auth_log_id`,
      { userId }
    );
    return result.rows;
  } finally {
    await conn.close();
  }
}

async function deleteTestUsers() {
  const conn = await getConnection();
  try {
    for (const userId of testUserIds) {
      await conn.execute(`DELETE FROM auth_audit_log WHERE user_id = :userId`, { userId });
    }
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
  cryptoService.validateConfig();
});

afterAll(async () => {
  await deleteTestUsers();
  await closePool();
});

describe('POST /api/auth/2fa/disable', () => {
  describe('authorization', () => {
    test('1. missing Authorization rejected', async () => {
      const res = await request(app).post('/api/auth/2fa/disable').send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);
    });

    test('2. malformed Authorization rejected', async () => {
      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', 'Basic abc123')
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);
    });

    test('3. valid access token accepted', async () => {
      const user = await createTwoFactorUser('validaccess');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(200);
    });

    test('4. challenge token rejected', async () => {
      const user = await createTwoFactorUser('challengerejected');
      const loginRes = await request(app).post('/api/auth/login').send({
        username: user.username,
        password: TEST_PASSWORD,
      });
      expect(typeof loginRes.body.challengeToken).toBe('string');

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${loginRes.body.challengeToken}`)
        .send({ twoFactorCode: generateCodeForSecret(user.secret) });
      expect(res.status).toBe(401);
    });

    test('5. expired access token rejected', async () => {
      const user = await createTwoFactorUser('expiredaccess');
      const accessToken = signAccessTokenFor(user);
      const decoded = jwt.decode(accessToken);
      const { iat, exp, iss, aud, ...claimsToResign } = decoded;

      const expiredToken = jwt.sign(claimsToResign, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        expiresIn: -120,
      });

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ twoFactorCode: generateCodeForSecret(user.secret) });
      expect(res.status).toBe(401);
    });

    test('6. tampered access token rejected', async () => {
      const user = await createTwoFactorUser('tamperedaccess');
      const accessToken = signAccessTokenFor(user);
      const tampered = accessToken.slice(0, -2) + 'xx';

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${tampered}`)
        .send({ twoFactorCode: generateCodeForSecret(user.secret) });
      expect(res.status).toBe(401);
    });

    test('7. wrong issuer rejected', async () => {
      const token = jwt.sign(
        { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: 'access', amr: ['pwd'] },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'someone-else', audience: process.env.JWT_AUDIENCE, expiresIn: '15m' }
      );
      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${token}`)
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);
    });

    test('8. wrong audience rejected', async () => {
      const token = jwt.sign(
        { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: 'access', amr: ['pwd'] },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: process.env.JWT_ISSUER, audience: 'someone-else', expiresIn: '15m' }
      );
      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${token}`)
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);
    });
  });

  describe('request validation', () => {
    test('9. missing code rejected', async () => {
      const user = await createTwoFactorUser('missingcode');
      const accessToken = signAccessTokenFor(user);
      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({});
      expect(res.status).toBe(400);
    });

    test('10. non-string code rejected', async () => {
      const user = await createTwoFactorUser('nonstringcode');
      const accessToken = signAccessTokenFor(user);
      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: 123456 });
      expect(res.status).toBe(400);
    });

    test('11-17. malformed codes rejected (empty, 5/7 digits, letters, whitespace, Unicode, extra chars)', async () => {
      const user = await createTwoFactorUser('malformedcodes');
      const accessToken = signAccessTokenFor(user);
      const cases = [
        '', // 11
        '12345', // 12
        '1234567', // 13
        'abcdef', // 14
        '123 56', // 15
        '１２３４５６', // 16 - fullwidth Unicode digits, must not be normalized
        '123456!', // 17
      ];
      for (const twoFactorCode of cases) {
        const res = await request(app)
          .post('/api/auth/2fa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ twoFactorCode });
        expect(res.status).toBe(400);
      }
    });
  });

  describe('user state', () => {
    test('18. inactive user rejected', async () => {
      const user = await createTwoFactorUser('inactiveuser');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'is_active = :isActive', { isActive: 0 });
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('inactive_user');
    });

    test('19. locked user rejected', async () => {
      const user = await createTwoFactorUser('lockeduser');
      const accessToken = signAccessTokenFor(user);
      const lockoutEndAt = new Date(Date.now() + 15 * 60 * 1000);
      await updateUserRow(user.id, 'lockout_end_at = :lockoutEndAt', { lockoutEndAt });
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('account_unavailable');
      expect(failure.DETAIL).not.toBe('inactive_user');
    });

    test('20. already disabled returns 409', async () => {
      const user = await createTwoFactorUser('alreadydisabled');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_enabled = 0, two_factor_secret = NULL', {});

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(409);
      expect(res.body.error).toBe('2FA is already disabled');

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('already_disabled');
    });

    test('21. missing secret rejected', async () => {
      const user = await createTwoFactorUser('missingsecret');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_secret = NULL', {});

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('missing_secret');
    });

    test('22. corrupted secret rejected safely', async () => {
      const user = await createTwoFactorUser('corruptedsecret');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_secret = :secret', { secret: 'not-a-valid-ciphertext' });

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });
      expect(res.status).toBe(401);
      expect(res.body.error).not.toMatch(/crypto|cipher|auth.?tag|decrypt/i);

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('invalid_secret');
    });

    test('23. current DB state is rechecked after token issuance (2FA disabled between token issuance and request)', async () => {
      const user = await createTwoFactorUser('statechanged');
      const accessToken = signAccessTokenFor(user);
      // Token was issued while 2FA was enabled; flip state afterward.
      await updateUserRow(user.id, 'two_factor_enabled = 0, two_factor_secret = NULL', {});
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      // The token's claims never asserted 2FA state in the first place —
      // the fresh findById() reload is what catches this, proving the
      // route does not trust any stale assumption.
      expect(res.status).toBe(409);
    });
  });

  describe('totp', () => {
    test('24. current-step valid code accepted', async () => {
      const user = await createTwoFactorUser('currentstep');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(200);
    });

    test('25. previous-step valid code accepted', async () => {
      const user = await createTwoFactorUser('previousstep');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret, Date.now() - PERIOD_SECONDS * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(200);
    });

    test('26. next-step valid code accepted', async () => {
      const user = await createTwoFactorUser('nextstep');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret, Date.now() + PERIOD_SECONDS * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(200);
    });

    test('27. two steps outside window rejected', async () => {
      const user = await createTwoFactorUser('outsidewindow');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret, Date.now() + PERIOD_SECONDS * 2 * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(res.status).toBe(400);
    });

    test('28-29. wrong code rejected and does not change DB state', async () => {
      const user = await createTwoFactorUser('wrongcode');
      const accessToken = signAccessTokenFor(user);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '000000' });
      expect(res.status).toBe(400); // 28
      expect(res.body.error).toBe('Invalid verification code');

      const row = await getUserRow(user.id); // 29
      expect(row.TWO_FACTOR_ENABLED).toBe(1);
      expect(row.TWO_FACTOR_SECRET).not.toBeNull();
    });
  });

  describe('ordering', () => {
    test('30-32. invalid TOTP leaves secret and enabled flag unchanged; successful TOTP is required before disable', async () => {
      const user = await createTwoFactorUser('orderingcheck');
      const accessToken = signAccessTokenFor(user);
      const rowBefore = await getUserRow(user.id);

      const wrong = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '000000' });
      expect(wrong.status).toBe(400);

      const rowAfterWrong = await getUserRow(user.id);
      expect(rowAfterWrong.TWO_FACTOR_ENABLED).toBe(rowBefore.TWO_FACTOR_ENABLED); // 30
      expect(rowAfterWrong.TWO_FACTOR_SECRET).toBe(rowBefore.TWO_FACTOR_SECRET); // 31

      const code = generateCodeForSecret(user.secret);
      const correct = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });
      expect(correct.status).toBe(200); // 32: only succeeds with a valid code

      const rowAfterCorrect = await getUserRow(user.id);
      expect(rowAfterCorrect.TWO_FACTOR_ENABLED).toBe(0);
      expect(rowAfterCorrect.TWO_FACTOR_SECRET).toBeNull();
    });
  });

  describe('success', () => {
    test('33-38. successful disable returns 200, flips state, and returns no sensitive values', async () => {
      const user = await createTwoFactorUser('successshape');
      const accessToken = signAccessTokenFor(user);
      const rowBefore = await getUserRow(user.id);
      const code = generateCodeForSecret(user.secret);

      const res = await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });

      expect(res.status).toBe(200); // 33
      expect(res.body).toEqual({ success: true }); // 34
      expect(res.body.secret).toBeUndefined(); // 38
      expect(res.body.otpAuthUri).toBeUndefined();
      expect(res.body.qrCodeDataUrl).toBeUndefined();
      expect(res.body.accessToken).toBeUndefined();
      expect(res.body.challengeToken).toBeUndefined();

      const row = await getUserRow(user.id);
      expect(row.TWO_FACTOR_ENABLED).toBe(0); // 35
      expect(row.TWO_FACTOR_SECRET).toBeNull(); // 36
      expect(new Date(row.UPDATED_AT).getTime()).toBeGreaterThan(new Date(rowBefore.UPDATED_AT).getTime()); // 37
    });
  });

  describe('audit', () => {
    test('39. success records 2FA_DISABLED/SUCCESS with no detail', async () => {
      const user = await createTwoFactorUser('auditsuccess');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret);
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });

      const events = await getAuditEventsForUserId(user.id);
      const success = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED' && e.EVENT_RESULT === 'SUCCESS');
      expect(success).toBeDefined();
      expect(success.DETAIL).toBeNull();
    });

    test('40. invalid TOTP records 2FA_DISABLED/FAILURE/invalid_code', async () => {
      const user = await createTwoFactorUser('auditinvalidtotp');
      const accessToken = signAccessTokenFor(user);
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '000000' });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED' && e.EVENT_RESULT === 'FAILURE');
      expect(failure.DETAIL).toBe('invalid_code');
    });

    test('41. malformed code records a failure audit with detail=invalid_code', async () => {
      const user = await createTwoFactorUser('auditmalformed');
      const accessToken = signAccessTokenFor(user);
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '12345' });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED' && e.EVENT_RESULT === 'FAILURE');
      expect(failure.DETAIL).toBe('invalid_code');
    });

    test('42. inactive user audited as inactive_user (covered above in test 18, re-asserted here for audit-section completeness)', async () => {
      const user = await createTwoFactorUser('auditinactive');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'is_active = 0', {});
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: generateCodeForSecret(user.secret) });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('inactive_user');
    });

    test('43. locked user audited as account_unavailable (re-asserted for audit-section completeness)', async () => {
      const user = await createTwoFactorUser('auditlocked');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'lockout_end_at = :lockoutEndAt', {
        lockoutEndAt: new Date(Date.now() + 15 * 60 * 1000),
      });
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: generateCodeForSecret(user.secret) });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('account_unavailable');
    });

    test('44. already disabled audited as already_disabled (re-asserted for audit-section completeness)', async () => {
      const user = await createTwoFactorUser('auditalreadydisabled');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_enabled = 0, two_factor_secret = NULL', {});
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('already_disabled');
    });

    test('45. missing secret audited as missing_secret (re-asserted for audit-section completeness)', async () => {
      const user = await createTwoFactorUser('auditmissingsecret');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_secret = NULL', {});
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('missing_secret');
    });

    test('46. corrupted secret audited as invalid_secret (re-asserted for audit-section completeness)', async () => {
      const user = await createTwoFactorUser('auditcorruptedsecret');
      const accessToken = signAccessTokenFor(user);
      await updateUserRow(user.id, 'two_factor_secret = :secret', { secret: 'not-a-valid-ciphertext' });
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '123456' });

      const events = await getAuditEventsForUserId(user.id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
      expect(failure.DETAIL).toBe('invalid_secret');
    });

    test('47. internal error audited as internal_error', async () => {
      const user = await createTwoFactorUser('auditinternalerror');
      const accessToken = signAccessTokenFor(user);

      const userServiceModule = require('../services/userService');
      const spy = jest.spyOn(userServiceModule, 'findById').mockRejectedValueOnce(new Error('simulated DB failure'));

      try {
        const res = await request(app)
          .post('/api/auth/2fa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ twoFactorCode: generateCodeForSecret(user.secret) });
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('2FA disable failed');

        const events = await getAuditEventsForUserId(user.id);
        const failure = events.find((e) => e.EVENT_TYPE === '2FA_DISABLED');
        expect(failure.DETAIL).toBe('internal_error');
      } finally {
        spy.mockRestore();
      }
    });

    test('48. audit DETAIL never contains secrets/tokens/codes', async () => {
      const user = await createTwoFactorUser('auditnoleak');
      const accessToken = signAccessTokenFor(user);

      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: '000000' });
      const code = generateCodeForSecret(user.secret);
      await request(app)
        .post('/api/auth/2fa/disable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ twoFactorCode: code });

      const events = await getAuditEventsForUserId(user.id);
      const allowedDetails = [
        'inactive_user',
        'account_unavailable',
        'already_disabled',
        'missing_secret',
        'invalid_secret',
        'invalid_code',
        'internal_error',
      ];
      for (const event of events) {
        if (event.DETAIL) {
          expect(event.DETAIL).not.toContain(user.secret);
          expect(event.DETAIL).not.toContain(code);
          expect(event.DETAIL).not.toContain(accessToken);
          expect(allowedDetails).toContain(event.DETAIL);
        }
      }
    });

    test('49. audit failure does not break a successful disable', async () => {
      const user = await createTwoFactorUser('auditfailsafe');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret);

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
        const res = await request(app)
          .post('/api/auth/2fa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ twoFactorCode: code });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(auditResolved).toBe(false);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('concurrency', () => {
    test('50-53. concurrent disable requests result in an atomic, consistent final state with no lost update', async () => {
      const user = await createTwoFactorUser('concurrentdisable');
      const accessToken = signAccessTokenFor(user);
      const code = generateCodeForSecret(user.secret);

      const [resA, resB] = await Promise.all([
        request(app)
          .post('/api/auth/2fa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ twoFactorCode: code }),
        request(app)
          .post('/api/auth/2fa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ twoFactorCode: code }),
      ]);

      // Both requests independently verify the same valid TOTP code (a
      // read-only check against an immutable decrypted secret — no race
      // there). Exactly one of them wins the atomic UPDATE; the other sees
      // rowsAffected === 0 and reports "already disabled".
      const statuses = [resA.status, resB.status].sort();
      expect(statuses).toEqual([200, 409]); // 50

      const row = await getUserRow(user.id); // 51, 52, 53
      expect(row.TWO_FACTOR_ENABLED).toBe(0);
      expect(row.TWO_FACTOR_SECRET).toBeNull();
      // Never observable: enabled=0 with a non-null secret, or enabled=1
      // with a null secret — the atomic UPDATE sets both together.
      const inconsistent =
        (row.TWO_FACTOR_ENABLED === 0 && row.TWO_FACTOR_SECRET !== null) ||
        (row.TWO_FACTOR_ENABLED === 1 && row.TWO_FACTOR_SECRET === null);
      expect(inconsistent).toBe(false);
    });
  });
});
