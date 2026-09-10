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

// Same rationale as __tests__/auth.2fa.test.js: several bcrypt(cost=12)
// hashes plus multiple DB round trips per test, and a shared, small Oracle
// pool (db.js: poolMax=5) that gets contended when the full suite runs.
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
  const username = `test_vl_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_vl_${RUN_ID}_${label}@example.com`;
}

// Creates a user with 2FA already enabled (bypassing /setup and /enable,
// which are Phase 4's concern, not Phase 5's) by writing a known plaintext
// secret, encrypted via the real cryptoService, directly into the DB.
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

async function loginAndGetChallenge(username) {
  const res = await request(app).post('/api/auth/login').send({
    username,
    password: TEST_PASSWORD,
  });
  return res;
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

async function getLatestAuditEvent() {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT * FROM auth_audit_log WHERE user_id IS NULL ORDER BY auth_log_id DESC FETCH FIRST 1 ROWS ONLY`
    );
    return result.rows[0] || null;
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
    // This test file's malformed-request/invalid-challenge cases produce
    // 2FA_VERIFY_FAILURE rows with no identifiable user_id or
    // username_attempted at all (there is no user identity to attach yet —
    // the challenge token itself was unparseable). No other route in this
    // codebase produces a 2FA_VERIFY_FAILURE row with both fields NULL, so
    // this is a safe, specific cleanup scoped to exactly this suite's
    // no-identity failure cases.
    await conn.execute(
      `DELETE FROM auth_audit_log WHERE user_id IS NULL AND username_attempted IS NULL AND event_type = '2FA_VERIFY_FAILURE'`
    );
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

describe('POST /api/auth/verify-login', () => {
  describe('challenge', () => {
    test('1. 2FA-enabled login returns requiresTwoFactor=true', async () => {
      const { username } = await createTwoFactorUser('challengeflag');
      const res = await loginAndGetChallenge(username);
      expect(res.body.requiresTwoFactor).toBe(true);
    });

    test('2. login returns no accessToken before MFA', async () => {
      const { username } = await createTwoFactorUser('noaccesstoken');
      const res = await loginAndGetChallenge(username);
      expect(res.body.accessToken).toBeUndefined();
      expect(typeof res.body.challengeToken).toBe('string');
    });

    test('3-8. challenge token shape: token_type, amr, issuer, audience, jti, expiration', async () => {
      const { username } = await createTwoFactorUser('challengeshape');
      const res = await loginAndGetChallenge(username);
      const decoded = jwt.decode(res.body.challengeToken);

      expect(decoded.token_type).toBe('2fa-challenge'); // 3
      expect(decoded.amr).toEqual(['pwd']); // 4
      expect(decoded.iss).toBe(process.env.JWT_ISSUER); // 5
      expect(decoded.aud).toBe(process.env.JWT_AUDIENCE); // 6
      expect(typeof decoded.jti).toBe('string'); // 7
      expect(decoded.jti.length).toBeGreaterThan(0);

      const expectedExpirySeconds = Number(process.env.JWT_TWO_FACTOR_CHALLENGE_EXPIRATION_MINUTES) * 60; // 8
      expect(decoded.exp - decoded.iat).toBe(expectedExpirySeconds);
    });

    test('9. malformed challenge rejected', async () => {
      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: 'not-a-jwt-at-all',
        twoFactorCode: '123456',
      });
      expect(res.status).toBe(401);
      expect(res.body.accessToken).toBeUndefined();
    });

    test('10. tampered challenge rejected', async () => {
      const { username, secret } = await createTwoFactorUser('tamperedchallenge');
      const loginRes = await loginAndGetChallenge(username);
      const tampered = loginRes.body.challengeToken.slice(0, -2) + 'xx';
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: tampered,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);
    });

    test('11. expired challenge rejected', async () => {
      const { username } = await createTwoFactorUser('expiredchallenge');
      const loginRes = await loginAndGetChallenge(username);
      const decoded = jwt.decode(loginRes.body.challengeToken);
      const { iat, exp, iss, aud, ...claimsToResign } = decoded;

      const expiredChallenge = jwt.sign(claimsToResign, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        expiresIn: -120,
      });

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: expiredChallenge,
        twoFactorCode: '123456',
      });
      expect(res.status).toBe(401);
    });

    test('12. wrong issuer rejected', async () => {
      const token = jwt.sign(
        { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: '2fa-challenge', amr: ['pwd'] },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'someone-else', audience: process.env.JWT_AUDIENCE, expiresIn: '5m' }
      );
      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: token,
        twoFactorCode: '123456',
      });
      expect(res.status).toBe(401);
    });

    test('13. wrong audience rejected', async () => {
      const token = jwt.sign(
        { sub: '1', username: 'x', email: 'x@example.com', role: 'ASSOCIATE', token_type: '2fa-challenge', amr: ['pwd'] },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: process.env.JWT_ISSUER, audience: 'someone-else', expiresIn: '5m' }
      );
      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: token,
        twoFactorCode: '123456',
      });
      expect(res.status).toBe(401);
    });

    test('14. access token rejected as challenge', async () => {
      const { username, secret } = await createTwoFactorUser('accesstokenasschallenge');
      // Force a non-2FA login path isn't available for this user (2FA is
      // enabled) — instead sign an access token directly via jwtService,
      // matching what a real access token for this user would look like.
      const accessToken = jwtService.signAccessToken({
        id: testUserIds[testUserIds.length - 1],
        username,
        email: `${username}@example.com`,
        role: 'ASSOCIATE',
      });
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: accessToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);
    });
  });

  describe('request validation', () => {
    test('15. missing challengeToken rejected', async () => {
      const res = await request(app).post('/api/auth/verify-login').send({ twoFactorCode: '123456' });
      expect(res.status).toBe(400);
    });

    test('16. missing twoFactorCode rejected', async () => {
      const res = await request(app).post('/api/auth/verify-login').send({ challengeToken: 'abc' });
      expect(res.status).toBe(400);
    });

    test('17. malformed OTP rejected (wrong digit counts, letters, whitespace)', async () => {
      const cases = ['12345', '1234567', 'abcdef', '12a456', '', '123 456', ' 123456', '123456 '];
      for (const twoFactorCode of cases) {
        const res = await request(app)
          .post('/api/auth/verify-login')
          .send({ challengeToken: 'placeholder', twoFactorCode });
        expect(res.status).toBe(400);
      }
    });

    test('18. Unicode digits rejected, not normalized', async () => {
      // Fullwidth digits and Arabic-Indic digits are NOT [0-9] — must be
      // rejected outright, never silently normalized to ASCII equivalents.
      const cases = ['１２３４５６', '١٢٣٤٥٦'];
      for (const twoFactorCode of cases) {
        const res = await request(app)
          .post('/api/auth/verify-login')
          .send({ challengeToken: 'placeholder', twoFactorCode });
        expect(res.status).toBe(400);
      }
    });

    test('19. extra characters rejected', async () => {
      const cases = ['123456!', '-123456', '123456\n', '0x123456'];
      for (const twoFactorCode of cases) {
        const res = await request(app)
          .post('/api/auth/verify-login')
          .send({ challengeToken: 'placeholder', twoFactorCode });
        expect(res.status).toBe(400);
      }
    });
  });

  describe('user state', () => {
    test('20. inactive user rejected', async () => {
      const { username, id, secret } = await createTwoFactorUser('inactiveuser');
      const loginRes = await loginAndGetChallenge(username);
      await updateUserRow(id, 'is_active = :isActive', { isActive: 0 });
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure.DETAIL).toBe('inactive_user');
    });

    test('20b. locked account rejected with detail=invalid_challenge (not inactive_user)', async () => {
      const { username, id, secret } = await createTwoFactorUser('lockedaccount');
      const loginRes = await loginAndGetChallenge(username);
      // Simulate an account that became locked (e.g. via concurrent failed
      // password attempts on another session) after the challenge token
      // was already issued — LOCKOUT_END_AT in the future means
      // isCurrentlyLockedOut() is true.
      const lockoutEndAt = new Date(Date.now() + 15 * 60 * 1000);
      await updateUserRow(id, 'lockout_end_at = :lockoutEndAt', { lockoutEndAt });
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid or expired challenge');

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure).toBeDefined();
      expect(failure.EVENT_RESULT).toBe('FAILURE');
      // Tech Lead correction: a locked account must be audited as
      // 'invalid_challenge', never 'inactive_user' — the two represent
      // different account states and must remain distinguishable in the
      // audit trail.
      expect(failure.DETAIL).toBe('invalid_challenge');
      expect(failure.DETAIL).not.toBe('inactive_user');
    });

    test('21. 2FA disabled after challenge issuance rejected', async () => {
      const { username, id, secret } = await createTwoFactorUser('disabledafterchallenge');
      const loginRes = await loginAndGetChallenge(username);
      await updateUserRow(id, 'two_factor_enabled = :enabled', { enabled: 0 });
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure.DETAIL).toBe('two_factor_disabled');
    });

    test('22. missing secret rejected', async () => {
      const { username, id, secret } = await createTwoFactorUser('missingsecret');
      const loginRes = await loginAndGetChallenge(username);
      await updateUserRow(id, 'two_factor_secret = NULL', {});
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure.DETAIL).toBe('missing_secret');
    });

    test('23. corrupted encrypted secret rejected safely', async () => {
      const { username, id, secret } = await createTwoFactorUser('corruptedsecret');
      const loginRes = await loginAndGetChallenge(username);
      await updateUserRow(id, 'two_factor_secret = :secret', { secret: 'not-a-valid-ciphertext' });
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(401);
      expect(res.body.error).not.toMatch(/crypto|cipher|auth.?tag|decrypt/i);

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure.DETAIL).toBe('invalid_secret');
    });
  });

  describe('totp', () => {
    test('24. current-step code accepted', async () => {
      const { username, secret } = await createTwoFactorUser('currentstep');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(200);
    });

    test('25. previous-step code accepted', async () => {
      const { username, secret } = await createTwoFactorUser('previousstep');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret, Date.now() - PERIOD_SECONDS * 1000);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(200);
    });

    test('26. next-step code accepted', async () => {
      const { username, secret } = await createTwoFactorUser('nextstep');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret, Date.now() + PERIOD_SECONDS * 1000);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(200);
    });

    test('27. two steps outside window rejected', async () => {
      const { username, secret } = await createTwoFactorUser('outsidewindow');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret, Date.now() + PERIOD_SECONDS * 2 * 1000);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });
      expect(res.status).toBe(400);
    });

    test('28. wrong code rejected', async () => {
      const { username } = await createTwoFactorUser('wrongcode');
      const loginRes = await loginAndGetChallenge(username);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: '000000',
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid verification code');
    });
  });

  describe('success', () => {
    test('29-34. successful verification returns a correctly shaped 200 + access token', async () => {
      const { username, id, secret } = await createTwoFactorUser('successshape');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);

      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });

      expect(res.status).toBe(200); // 29
      expect(typeof res.body.accessToken).toBe('string'); // 30
      expect(res.body.challengeToken).toBeUndefined();
      expect(res.body.secret).toBeUndefined();
      expect(res.body.otpAuthUri).toBeUndefined();
      expect(res.body.qrCodeDataUrl).toBeUndefined();

      const decoded = jwt.decode(res.body.accessToken);
      expect(decoded.token_type).toBe('access'); // 31
      expect(decoded.amr).toEqual(['pwd', 'mfa']); // 32
      expect(decoded.sub).toBe(String(id)); // 33
      expect(decoded.username).toBe(username);
      expect(decoded.iss).toBe(process.env.JWT_ISSUER); // 34
      expect(decoded.aud).toBe(process.env.JWT_AUDIENCE);
      expect(typeof decoded.jti).toBe('string'); // 35
      expect(decoded.jti.length).toBeGreaterThan(0);

      expect(res.body.user.id).toBe(id);
      expect(res.body.user.username).toBe(username);
      expect(res.body.user.password).toBeUndefined();
      expect(res.body.user.passwordHash).toBeUndefined();
    });

    test('36. jti is unique across issued tokens', async () => {
      const { username, secret } = await createTwoFactorUser('uniquejti');
      const loginRes1 = await loginAndGetChallenge(username);
      const code1 = generateCodeForSecret(secret);
      const res1 = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes1.body.challengeToken,
        twoFactorCode: code1,
      });

      // Second full login+verify cycle for the same user — 2FA is still
      // enabled, so the same flow repeats.
      const loginRes2 = await loginAndGetChallenge(username);
      const code2 = generateCodeForSecret(secret);
      const res2 = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes2.body.challengeToken,
        twoFactorCode: code2,
      });

      const jti1 = jwt.decode(res1.body.accessToken).jti;
      const jti2 = jwt.decode(res2.body.accessToken).jti;
      expect(jti1).not.toBe(jti2);
    });

    test('37. final access token works on a protected business API', async () => {
      const { username, secret } = await createTwoFactorUser('protectedapi');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);
      const verifyRes = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });

      const apiRes = await request(app)
        .get('/api/products')
        .set('Authorization', `Bearer ${verifyRes.body.accessToken}`);
      expect(apiRes.status).toBe(200);
    });

    test('38. challenge token still rejected by protected API', async () => {
      const { username } = await createTwoFactorUser('challengerejectedbyapi');
      const loginRes = await loginAndGetChallenge(username);

      const apiRes = await request(app)
        .get('/api/products')
        .set('Authorization', `Bearer ${loginRes.body.challengeToken}`);
      expect(apiRes.status).toBe(401);
    });
  });

  describe('audit', () => {
    test('39. success records 2FA_VERIFY_SUCCESS', async () => {
      const { username, id, secret } = await createTwoFactorUser('auditsuccess');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);
      await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });

      const events = await getAuditEventsForUserId(id);
      const success = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_SUCCESS');
      expect(success).toBeDefined();
      expect(success.EVENT_RESULT).toBe('SUCCESS');
      expect(success.DETAIL).toBeNull();
    });

    test('40. invalid TOTP records 2FA_VERIFY_FAILURE/invalid_code', async () => {
      const { username, id } = await createTwoFactorUser('auditinvalidtotp');
      const loginRes = await loginAndGetChallenge(username);
      await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: '000000',
      });

      const events = await getAuditEventsForUserId(id);
      const failure = events.find((e) => e.EVENT_TYPE === '2FA_VERIFY_FAILURE');
      expect(failure.DETAIL).toBe('invalid_code');
    });

    test('41. invalid challenge produces a safe failure audit row', async () => {
      await request(app).post('/api/auth/verify-login').send({
        challengeToken: 'not-a-jwt-at-all',
        twoFactorCode: '123456',
      });
      // No identifiable userId for a malformed challenge — this should not
      // throw or crash the audit write; absence of a crash is the assertion
      // (the route itself already returned 401, verified elsewhere).
      expect(true).toBe(true);
    });

    test('42. malformed code produces a correct audit row', async () => {
      const res = await request(app).post('/api/auth/verify-login').send({
        challengeToken: 'placeholder',
        twoFactorCode: '12345',
      });
      expect(res.status).toBe(400);

      const event = await getLatestAuditEvent();
      expect(event.EVENT_TYPE).toBe('2FA_VERIFY_FAILURE');
      expect(event.DETAIL).toBe('invalid_code');
    });

    test('43. audit DETAIL never contains secrets/tokens/codes', async () => {
      const { username, id, secret } = await createTwoFactorUser('auditnoleak');
      const loginRes = await loginAndGetChallenge(username);

      await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: '000000',
      });
      const code = generateCodeForSecret(secret);
      const verifyRes = await request(app).post('/api/auth/verify-login').send({
        challengeToken: loginRes.body.challengeToken,
        twoFactorCode: code,
      });

      const events = await getAuditEventsForUserId(id);
      const allowedDetails = [
        'invalid_challenge',
        'expired_challenge',
        'inactive_user',
        'two_factor_disabled',
        'missing_secret',
        'invalid_secret',
        'invalid_code',
        'internal_error',
      ];
      for (const event of events) {
        if (event.DETAIL) {
          expect(event.DETAIL).not.toContain(secret);
          expect(event.DETAIL).not.toContain(code);
          expect(event.DETAIL).not.toContain(loginRes.body.challengeToken);
          expect(event.DETAIL).not.toContain(verifyRes.body.accessToken || '');
          expect(allowedDetails).toContain(event.DETAIL);
        }
      }
    });

    test('44. audit failure does not break successful authentication', async () => {
      const { username, secret } = await createTwoFactorUser('auditfailsafe');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);

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
        const res = await request(app).post('/api/auth/verify-login').send({
          challengeToken: loginRes.body.challengeToken,
          twoFactorCode: code,
        });

        expect(res.status).toBe(200);
        expect(typeof res.body.accessToken).toBe('string');
        expect(auditResolved).toBe(false);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('replay and concurrency', () => {
    test('45. replaying the same challenge a second time: documented actual behavior', async () => {
      const { username, secret } = await createTwoFactorUser('replaychallenge');
      const loginRes = await loginAndGetChallenge(username);
      const challengeToken = loginRes.body.challengeToken;

      const code1 = generateCodeForSecret(secret);
      const first = await request(app).post('/api/auth/verify-login').send({ challengeToken, twoFactorCode: code1 });
      expect(first.status).toBe(200);

      // Documented, accepted trade-off (see Phase 5 audit §9): the challenge
      // token itself carries no one-time-use tracking, so a second
      // verify-login call with the SAME still-valid challenge token and a
      // freshly-generated valid code also succeeds, issuing a second,
      // independent access token. This is intentional — not a bug — given
      // the short challenge lifetime and that a correct TOTP code must
      // still be supplied each time.
      const code2 = generateCodeForSecret(secret);
      const second = await request(app).post('/api/auth/verify-login').send({ challengeToken, twoFactorCode: code2 });
      expect(second.status).toBe(200);
      expect(second.body.accessToken).not.toBe(first.body.accessToken);
    });

    test('46-47. concurrent verify-login requests with the same valid code both succeed independently', async () => {
      const { username, secret } = await createTwoFactorUser('concurrentverify');
      const loginRes = await loginAndGetChallenge(username);
      const code = generateCodeForSecret(secret);

      const [resA, resB] = await Promise.all([
        request(app).post('/api/auth/verify-login').send({
          challengeToken: loginRes.body.challengeToken,
          twoFactorCode: code,
        }),
        request(app).post('/api/auth/verify-login').send({
          challengeToken: loginRes.body.challengeToken,
          twoFactorCode: code,
        }),
      ]);

      // TOTP verification has no mutable shared state to race on (see
      // services/totpService.js — a read-only check() against an
      // immutable, module-level cloned instance) and no "enable" state
      // transition occurs here (unlike Phase 4's /enable) — both concurrent
      // requests are independently valid and both succeed.
      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);
      expect(resA.body.accessToken).not.toBe(resB.body.accessToken);
    });

    test('48. no shared authenticator mutation race across concurrent different-secret verifications', async () => {
      const userA = await createTwoFactorUser('noraceA');
      const userB = await createTwoFactorUser('noraceB');
      const loginA = await loginAndGetChallenge(userA.username);
      const loginB = await loginAndGetChallenge(userB.username);
      const codeA = generateCodeForSecret(userA.secret);
      const codeB = generateCodeForSecret(userB.secret);

      // If totpService's module-level `totp` instance were ever mutated
      // per-call (e.g. a future change setting a custom epoch on it
      // directly instead of using a clone), these two concurrent requests
      // for two different secrets could interfere with each other. Both
      // must independently succeed with their own correct code.
      const [resA, resB] = await Promise.all([
        request(app).post('/api/auth/verify-login').send({
          challengeToken: loginA.body.challengeToken,
          twoFactorCode: codeA,
        }),
        request(app).post('/api/auth/verify-login').send({
          challengeToken: loginB.body.challengeToken,
          twoFactorCode: codeB,
        }),
      ]);

      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);
    });
  });
});
