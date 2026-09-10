const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const cryptoService = require('./cryptoService');

const SECRET_LENGTH_BYTES = 20;
// authenticator.generateSecret() defaults to 10 bytes if not given an
// explicit length (verified against the installed otplib@12 source,
// @otplib/core's Authenticator#generateSecret(numberOfBytes = 10)) — the
// 20-byte argument below must never be omitted.
const ALGORITHM = 'sha1';
const DIGITS = 6;
const PERIOD_SECONDS = 30;
// "previous/current/next step" = exactly one step of tolerance in each
// direction. otplib@12's `window` option is expressed in steps (not
// seconds), so window: 1 is exactly ±1 step — verified empirically: tokens
// generated one step in the past/future both check() as valid, a token two
// steps away does not.
const WINDOW_STEPS = 1;

// A single configured clone of the shared `authenticator` singleton,
// created once at module load. otplib's `authenticator` export is a shared,
// mutable-by-assignment singleton (`authenticator.options = {...}` mutates
// it for every other concurrent caller in the process) — clone() instead
// produces an independent instance that still carries the preset's
// Node-crypto-backed digest/random-bytes/Base32 plugins, so concurrent
// requests on this server can never race on shared option state. Verified
// directly: after cloning, the original `authenticator.options` remains
// untouched.
const totp = authenticator.clone({
  step: PERIOD_SECONDS,
  digits: DIGITS,
  algorithm: ALGORITHM,
  window: WINDOW_STEPS,
});

function getIssuer() {
  return process.env.TOTP_ISSUER || 'lumina-diamond-pos';
}

// Generates a new Base32-encoded secret representing exactly 20
// cryptographically random bytes. Verified against the installed
// otplib@12 source: @otplib/plugin-crypto's createRandomBytes() calls
// Node's crypto.randomBytes() directly — never Math.random().
function generateSecret() {
  return totp.generateSecret(SECRET_LENGTH_BYTES);
}

function generateOtpAuthUri({ secret, accountName }) {
  return totp.keyuri(accountName, getIssuer(), secret);
}

async function generateQrCodeDataUrl(otpAuthUri) {
  return QRCode.toDataURL(otpAuthUri);
}

// Verifies a 6-digit TOTP code against a plaintext Base32 secret, with a
// ±1 time-step tolerance (configured on the module-level `totp` instance
// above). Returns a boolean — safe for malformed/invalid tokens (verified:
// otplib's check() returns false rather than throwing for a non-numeric or
// wrong-length token), never throws for an invalid code.
function verifyCode({ secret, code }) {
  return totp.check(code, secret);
}

// Encrypts a plaintext Base32 TOTP secret for storage in USERS.TWO_FACTOR_SECRET.
function encryptSecret(plaintextSecret) {
  return cryptoService.encrypt(plaintextSecret);
}

// Decrypts a stored USERS.TWO_FACTOR_SECRET value back to its plaintext
// Base32 form. Throws if the stored value is tampered/malformed — callers
// must treat that as "secret unusable", never log the thrown error's detail.
function decryptSecret(encryptedSecret) {
  return cryptoService.decrypt(encryptedSecret);
}

module.exports = {
  SECRET_LENGTH_BYTES,
  generateSecret,
  generateOtpAuthUri,
  generateQrCodeDataUrl,
  verifyCode,
  encryptSecret,
  decryptSecret,
};
