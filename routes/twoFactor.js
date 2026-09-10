const express = require('express');
const router = express.Router();
const twoFactorService = require('../services/twoFactorService');
const authAuditService = require('../services/authAuditService');

// Called through the module object (not destructured) so tests can spy on
// authAuditService.recordAuthEvent and have that reflected here — same
// pattern as routes/auth.js.
const recordAuthEvent = (...args) => authAuditService.recordAuthEvent(...args);

// POST /api/auth/2fa/setup — requires a valid access token (enforced by the
// requireAccessToken middleware this router is mounted behind in app.js,
// not by anything in this file). User identity comes exclusively from
// req.user.id (the verified JWT `sub` claim) — the request body is never
// consulted for identity, so a caller can never configure another user's 2FA.
router.post('/setup', async (req, res) => {
  // req.user.id comes from the JWT `sub` claim, which is always a string
  // (see services/jwtService.js) — convert once to a number here so every
  // downstream DB bind (USER_ID is NUMBER) and audit call gets a proper
  // JS number, not a numeric string.
  const userId = Number(req.user.id);
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;

  let result;
  try {
    result = await twoFactorService.setup(userId);
  } catch (err) {
    console.error(err);
    await recordAuthEvent({
      userId,
      eventType: '2FA_SETUP',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: '2FA setup failed' });
  }

  const { SETUP_RESULT } = twoFactorService;

  if (result.outcome === SETUP_RESULT.ALREADY_ENABLED) {
    await recordAuthEvent({
      userId,
      eventType: '2FA_SETUP',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'already_enabled',
    });
    return res.status(409).json({ error: 'Two-factor authentication is already enabled' });
  }

  // result.outcome === SETUP_RESULT.SUCCESS. The user row is already
  // updated at this point. These three response values are sensitive setup
  // material (the otpAuthUri embeds the plaintext secret) — they are
  // returned once, here, and never logged or placed in audit detail. The
  // response is sent before the (fire-and-forget) audit call so a slow or
  // failing audit write can never turn a successful setup into an error.
  res.status(200).json({
    secret: result.secret,
    otpAuthUri: result.otpAuthUri,
    qrCodeDataUrl: result.qrCodeDataUrl,
  });
  recordAuthEvent({
    userId,
    eventType: '2FA_SETUP',
    eventResult: 'SUCCESS',
    ip,
    userAgent,
  });
});

// POST /api/auth/2fa/enable — same access-token/identity rules as /setup.
router.post('/enable', async (req, res) => {
  // See the /setup handler above for why this conversion is needed.
  const userId = Number(req.user.id);
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || null;
  const { code } = req.body || {};

  const { isWellFormedCode, ENABLE_RESULT } = twoFactorService;

  if (!isWellFormedCode(code)) {
    // Malformed input is rejected before any DB/crypto work.
    await recordAuthEvent({
      userId,
      eventType: '2FA_ENABLED',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'invalid_code',
    });
    return res.status(400).json({ error: 'code must be exactly 6 digits' });
  }

  let result;
  try {
    result = await twoFactorService.enable(userId, code);
  } catch (err) {
    console.error(err);
    await recordAuthEvent({
      userId,
      eventType: '2FA_ENABLED',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'internal_error',
    });
    return res.status(500).json({ error: '2FA enable failed' });
  }

  if (result.outcome === ENABLE_RESULT.NO_PENDING_SETUP) {
    await recordAuthEvent({
      userId,
      eventType: '2FA_ENABLED',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'no_pending_setup',
    });
    return res.status(409).json({ error: 'No pending two-factor setup found' });
  }

  if (result.outcome === ENABLE_RESULT.ALREADY_ENABLED) {
    await recordAuthEvent({
      userId,
      eventType: '2FA_ENABLED',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'already_enabled',
    });
    return res.status(409).json({ error: 'Two-factor authentication is already enabled' });
  }

  if (result.outcome === ENABLE_RESULT.INVALID_CODE) {
    await recordAuthEvent({
      userId,
      eventType: '2FA_ENABLED',
      eventResult: 'FAILURE',
      ip,
      userAgent,
      detail: 'invalid_code',
    });
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // result.outcome === ENABLE_RESULT.SUCCESS. Response sent before the
  // fire-and-forget audit call, for the same reason as /setup above.
  res.status(200).json({ success: true });
  recordAuthEvent({
    userId,
    eventType: '2FA_ENABLED',
    eventResult: 'SUCCESS',
    ip,
    userAgent,
  });
});

module.exports = router;
