require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const { authenticator } = require('otplib');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const { createUser } = require('../services/userService');
const jwtService = require('../services/jwtService');
const cryptoService = require('../services/cryptoService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

// Each test typically does several bcrypt(cost=12) hashes (register, login)
// plus multiple DB round trips — comfortably under 5s alone, but the Oracle
// pool (db.js: poolMax=5) is shared and can be heavily contended when the
// full suite runs across all three auth test files at once, slowing every
// query. A generous timeout avoids false failures under that load rather
// than changing unrelated Phase 1 pool configuration.
jest.setTimeout(60000);

const RUN_ID = Date.now();
const testUsernames = [];
const testUserIds = [];
const TEST_PASSWORD = 'CorrectHorse123';
const PERIOD_SECONDS = 30;

// A fresh clone per call (never mutate the shared `authenticator` singleton
// — see services/totpService.js for why) so tests can generate a code for
// an arbitrary epoch without any risk of leaking that override into other
// concurrent test assertions.
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
  const username = `test_2fa_${RUN_ID}_${label}`;
  testUsernames.push(username);
  return username;
}

function uniqueEmail(label) {
  return `test_2fa_${RUN_ID}_${label}@example.com`;
}

async function createTestUser(label) {
  const username = uniqueUsername(label);
  const email = uniqueEmail(label);
  const user = await createUser({
    username,
    password: TEST_PASSWORD,
    fullName: `Test ${label}`,
    email,
  });
  testUserIds.push(user.id);
  return { username, email, id: user.id };
}

async function loginAndGetAccessToken(username) {
  const res = await request(app).post('/api/auth/login').send({
    username,
    password: TEST_PASSWORD,
  });
  return res.body.accessToken;
}

async function getChallengeToken(username) {
  // Flip the user to 2FA-enabled directly in the DB (bypassing /setup and
  // /enable, which are exactly what this suite is testing) purely to force
  // login into issuing a challenge token instead of an access token.
  const conn = await getConnection();
  try {
    await conn.execute(
      `UPDATE users SET two_factor_enabled = 1, two_factor_secret = :secret WHERE username = :username`,
      { secret: cryptoService.encrypt(generateSecret()), username },
      { autoCommit: true }
    );
  } finally {
    await conn.close();
  }
  const res = await request(app).post('/api/auth/login').send({ username, password: TEST_PASSWORD });
  return res.body.challengeToken;
}

async function getUserRow(username) {
  const conn = await getConnection();
  try {
    const result = await conn.execute(
      `SELECT user_id, username, two_factor_enabled, two_factor_secret, updated_at
       FROM users WHERE username = :username`,
      { username }
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

async function base32DecodedByteLength(base32) {
  // Minimal RFC4648 base32 decode (no padding), used only to verify the
  // secret's true byte length independent of otplib's own claims.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32.toUpperCase()) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  return Math.floor(bits.length / 8);
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

describe('POST /api/auth/2fa/setup and /api/auth/2fa/enable', () => {
  describe('authorization', () => {
    test('1. setup without token → 401', async () => {
      const res = await request(app).post('/api/auth/2fa/setup');
      expect(res.status).toBe(401);
    });

    test('2. enable without token → 401', async () => {
      const res = await request(app).post('/api/auth/2fa/enable').send({ code: '123456' });
      expect(res.status).toBe(401);
    });

    test('3. setup with challenge token → 401', async () => {
      const { username } = await createTestUser('challenge_setup');
      const challengeToken = await getChallengeToken(username);

      const res = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${challengeToken}`);
      expect(res.status).toBe(401);
    });

    test('4. enable with challenge token → 401', async () => {
      const { username } = await createTestUser('challenge_enable');
      const challengeToken = await getChallengeToken(username);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${challengeToken}`)
        .send({ code: '123456' });
      expect(res.status).toBe(401);
    });
  });

  describe('setup', () => {
    test('5-10. valid setup → 200, with correctly shaped secret/otpAuthUri/qrCodeDataUrl', async () => {
      const { username, id } = await createTestUser('validsetup');
      const accessToken = await loginAndGetAccessToken(username);

      const res = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(res.status).toBe(200); // 5
      expect(res.body.secret).toMatch(/^[A-Z2-7]+$/); // 6: Base32 alphabet only
      expect(await base32DecodedByteLength(res.body.secret)).toBe(20); // 7: exactly 20 bytes
      expect(res.body.otpAuthUri.startsWith('otpauth://totp/')).toBe(true); // 8
      expect(res.body.otpAuthUri).toContain(encodeURIComponent('lumina-diamond-pos'));
      expect(decodeURIComponent(res.body.otpAuthUri)).toContain(username); // 9: account present
      expect(res.body.qrCodeDataUrl.startsWith('data:image/png;base64,')).toBe(true); // 10

      const row = await getUserRow(username);
      expect(row.TWO_FACTOR_SECRET).not.toBe(res.body.secret); // 11: encrypted, not plaintext
      expect(row.TWO_FACTOR_SECRET.split(':').length).toBe(3); // 11: iv:tag:ciphertext shape
      expect(row.TWO_FACTOR_ENABLED).toBe(0); // 12: still disabled after setup alone
      void id;
    });

    test('13. setup when already enabled is rejected', async () => {
      const { username } = await createTestUser('setupalreadyenabled');
      const accessToken = await loginAndGetAccessToken(username);

      const first = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      const code = generateCodeForSecret(first.body.secret);
      await request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code });

      const second = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(second.status).toBe(409);
      expect(second.body.secret).toBeUndefined();
    });

    test('14. setup success/failure audit events are recorded with no secret material', async () => {
      const { username, id } = await createTestUser('setupaudit');
      const accessToken = await loginAndGetAccessToken(username);

      const res = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const events = await getAuditEventsForUserId(id);
      const setupEvent = events.find((e) => e.EVENT_TYPE === '2FA_SETUP');
      expect(setupEvent).toBeDefined();
      expect(setupEvent.EVENT_RESULT).toBe('SUCCESS');
      expect(setupEvent.DETAIL).toBeNull();

      // Try again while enabled to also capture a failure audit event.
      const code = generateCodeForSecret(res.body.secret);
      await request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code });
      await request(app).post('/api/auth/2fa/setup').set('Authorization', `Bearer ${accessToken}`);

      const eventsAfter = await getAuditEventsForUserId(id);
      const failureEvent = eventsAfter.find(
        (e) => e.EVENT_TYPE === '2FA_SETUP' && e.EVENT_RESULT === 'FAILURE'
      );
      expect(failureEvent.DETAIL).toBe('already_enabled');
    });
  });

  describe('enable', () => {
    test('15. valid current TOTP code → 200', async () => {
      const { username } = await createTestUser('enablevalid');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const code = generateCodeForSecret(setupRes.body.secret);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });

      expect(res.status).toBe(200);
      expect(res.body.secret).toBeUndefined();
      expect(res.body.otpAuthUri).toBeUndefined();
      expect(res.body.qrCodeDataUrl).toBeUndefined();
    });

    test('16. previous-step code → accepted', async () => {
      const { username } = await createTestUser('enableprevstep');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const code = generateCodeForSecret(setupRes.body.secret, Date.now() - PERIOD_SECONDS * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });

      expect(res.status).toBe(200);
    });

    test('17. next-step code → accepted', async () => {
      const { username } = await createTestUser('enablenextstep');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const code = generateCodeForSecret(setupRes.body.secret, Date.now() + PERIOD_SECONDS * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });

      expect(res.status).toBe(200);
    });

    test('18. code two steps outside window → rejected', async () => {
      const { username } = await createTestUser('enableoutsidewindow');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const code = generateCodeForSecret(setupRes.body.secret, Date.now() + PERIOD_SECONDS * 2 * 1000);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });

      expect(res.status).toBe(400);
    });

    test('19. malformed codes → 400, without a pending-secret requirement', async () => {
      const { username } = await createTestUser('malformedcode');
      const accessToken = await loginAndGetAccessToken(username);

      const cases = ['12345', '1234567', 'abcdef', '12a456', '', '123 456'];
      for (const code of cases) {
        const res = await request(app)
          .post('/api/auth/2fa/enable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code });
        expect(res.status).toBe(400);
      }

      const missing = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({});
      expect(missing.status).toBe(400);
    });

    test('20. no pending secret → rejected', async () => {
      const { username } = await createTestUser('nopendingsecret');
      const accessToken = await loginAndGetAccessToken(username);

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: '123456' });

      expect(res.status).toBe(409);
    });

    test('21. already enabled → rejected', async () => {
      const { username } = await createTestUser('enablealreadyenabled');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      const code = generateCodeForSecret(setupRes.body.secret);
      await request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code });

      const res = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });

      expect(res.status).toBe(409);
    });

    test('22-23. invalid code does not enable; successful enable sets TWO_FACTOR_ENABLED=1', async () => {
      const { username } = await createTestUser('invalidthenvalid');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      const wrong = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: '000000' });
      expect(wrong.status).toBe(400);

      let row = await getUserRow(username);
      expect(row.TWO_FACTOR_ENABLED).toBe(0); // 22

      const code = generateCodeForSecret(setupRes.body.secret);
      const ok = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code });
      expect(ok.status).toBe(200);

      row = await getUserRow(username);
      expect(row.TWO_FACTOR_ENABLED).toBe(1); // 23
    });

    test('24. UPDATED_AT changes after enable', async () => {
      const { username } = await createTestUser('updatedatcheck');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      const rowAfterSetup = await getUserRow(username);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const code = generateCodeForSecret(setupRes.body.secret);
      await request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code });

      const rowAfterEnable = await getUserRow(username);
      expect(new Date(rowAfterEnable.UPDATED_AT).getTime()).toBeGreaterThan(
        new Date(rowAfterSetup.UPDATED_AT).getTime()
      );
    });
  });

  describe('encryption', () => {
    test('25. encrypt/decrypt round trip', () => {
      const plaintext = generateSecret();
      const encrypted = cryptoService.encrypt(plaintext);
      expect(encrypted.split(':').length).toBe(3);
      expect(cryptoService.decrypt(encrypted)).toBe(plaintext);
    });

    test('26. tampered ciphertext/auth tag fails safely', () => {
      const plaintext = generateSecret();
      const encrypted = cryptoService.encrypt(plaintext);
      const [iv, tag, ciphertext] = encrypted.split(':');

      const tamperedCiphertext = [iv, tag, Buffer.from('tampered-data-here').toString('base64')].join(':');
      expect(() => cryptoService.decrypt(tamperedCiphertext)).toThrow();

      const tamperedTag = [iv, Buffer.from(tag, 'base64').map((b) => b ^ 0xff).toString('base64'), ciphertext].join(':');
      expect(() => cryptoService.decrypt(tamperedTag)).toThrow();

      expect(() => cryptoService.decrypt('not:valid')).toThrow();
      expect(() => cryptoService.decrypt('')).toThrow();
    });
  });

  describe('audit', () => {
    test('27. setup audit failure does not break a successful setup', async () => {
      const { username } = await createTestUser('setupauditfail');
      const accessToken = await loginAndGetAccessToken(username);
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
          .post('/api/auth/2fa/setup')
          .set('Authorization', `Bearer ${accessToken}`);

        expect(res.status).toBe(200);
        expect(auditResolved).toBe(false);
      } finally {
        spy.mockRestore();
      }
    });

    test('28. enable audit failure does not break a successful enable', async () => {
      const { username } = await createTestUser('enableauditfail');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      const code = generateCodeForSecret(setupRes.body.secret);

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
          .post('/api/auth/2fa/enable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code });

        expect(res.status).toBe(200);
        expect(auditResolved).toBe(false);
      } finally {
        spy.mockRestore();
      }
    });

    test('29. no secret/code/URI/QR data is ever stored in audit DETAIL', async () => {
      const { username, id } = await createTestUser('auditnoleak');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);

      await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: '000000' }); // wrong, to also generate a failure row

      const code = generateCodeForSecret(setupRes.body.secret);
      await request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code });

      const events = await getAuditEventsForUserId(id);
      expect(events.length).toBeGreaterThan(0);
      for (const event of events) {
        if (event.DETAIL) {
          expect(event.DETAIL).not.toContain(setupRes.body.secret);
          expect(event.DETAIL).not.toContain(setupRes.body.otpAuthUri);
          expect(event.DETAIL).not.toContain('data:image/png');
          expect(event.DETAIL).not.toContain(code);
          expect(event.DETAIL).not.toContain(accessToken);
          // Only the small fixed vocabulary of detail strings is allowed.
          expect(['already_enabled', 'no_pending_setup', 'invalid_code', 'internal_error']).toContain(
            event.DETAIL
          );
        }
      }
    });
  });

  describe('concurrency', () => {
    test('30. concurrent setup requests do not corrupt DB state', async () => {
      const { username } = await createTestUser('concurrentsetup');
      const accessToken = await loginAndGetAccessToken(username);

      const [resA, resB] = await Promise.all([
        request(app).post('/api/auth/2fa/setup').set('Authorization', `Bearer ${accessToken}`),
        request(app).post('/api/auth/2fa/setup').set('Authorization', `Bearer ${accessToken}`),
      ]);

      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);

      const row = await getUserRow(username);
      expect(row.TWO_FACTOR_ENABLED).toBe(0);
      expect(row.TWO_FACTOR_SECRET.split(':').length).toBe(3);

      // The persisted secret must be decryptable and must correspond to
      // whichever of the two setup calls' secrets landed last — not a
      // mangled hybrid of both.
      const decrypted = cryptoService.decrypt(row.TWO_FACTOR_SECRET);
      expect([resA.body.secret, resB.body.secret]).toContain(decrypted);
    });

    test('31. concurrent enable requests with the same valid code result in exactly one success', async () => {
      const { username } = await createTestUser('concurrentenable');
      const accessToken = await loginAndGetAccessToken(username);
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      const code = generateCodeForSecret(setupRes.body.secret);

      const [resA, resB] = await Promise.all([
        request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code }),
        request(app).post('/api/auth/2fa/enable').set('Authorization', `Bearer ${accessToken}`).send({ code }),
      ]);

      const statuses = [resA.status, resB.status].sort();
      expect(statuses).toEqual([200, 409]);

      const row = await getUserRow(username);
      expect(row.TWO_FACTOR_ENABLED).toBe(1);
    });
  });
});
