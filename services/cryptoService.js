const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

let cachedKey = null;

// Reads and validates TOTP_ENCRYPTION_KEY from process.env. Called once at
// startup (server.js) so a misconfigured deployment fails fast instead of
// failing on first 2FA setup. Throws — never logs or returns the key value
// itself. Accepts the key as base64; it must decode to exactly 32 bytes.
function loadKey() {
  const raw = process.env.TOTP_ENCRYPTION_KEY;
  if (!raw || typeof raw !== 'string' || raw.length === 0) {
    throw new Error('TOTP_ENCRYPTION_KEY is missing. Set a base64-encoded 32-byte key in .env.');
  }

  let key;
  try {
    key = Buffer.from(raw, 'base64');
  } catch {
    throw new Error('TOTP_ENCRYPTION_KEY is not valid base64.');
  }

  if (key.length !== KEY_BYTES) {
    throw new Error(`TOTP_ENCRYPTION_KEY must decode to exactly ${KEY_BYTES} bytes.`);
  }

  if (process.env.JWT_SECRET && raw === process.env.JWT_SECRET) {
    throw new Error('TOTP_ENCRYPTION_KEY must be distinct from JWT_SECRET.');
  }

  return key;
}

// Validates configuration and caches the decoded key. Call at startup so the
// process exits immediately on misconfiguration.
function validateConfig() {
  cachedKey = loadKey();
}

function getKey() {
  if (!cachedKey) {
    cachedKey = loadKey();
  }
  return cachedKey;
}

// Encrypts plaintext with AES-256-GCM using a fresh random 12-byte IV for
// every call. Returns a single self-contained string:
// base64(iv):base64(authTag):base64(ciphertext)
function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [iv.toString('base64'), authTag.toString('base64'), ciphertext.toString('base64')].join(':');
}

// Decrypts a value produced by encrypt(). Throws on any tampering (bad auth
// tag), malformed input, or key mismatch — never returns a partial/garbage
// result. Callers must catch and treat failure as "stored secret unusable",
// never log the thrown error's context beyond a generic message.
function decrypt(encoded) {
  const key = getKey();

  if (typeof encoded !== 'string') {
    throw new Error('Invalid encrypted value.');
  }

  const parts = encoded.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted value format.');
  }

  const [ivPart, authTagPart, ciphertextPart] = parts;
  const iv = Buffer.from(ivPart, 'base64');
  const authTag = Buffer.from(authTagPart, 'base64');
  const ciphertext = Buffer.from(ciphertextPart, 'base64');

  if (iv.length !== IV_BYTES || authTag.length !== AUTH_TAG_BYTES) {
    throw new Error('Invalid encrypted value format.');
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  // Throws if the auth tag does not match (tampered ciphertext/tag, or
  // wrong key) — this is the intended, safe failure mode.
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

module.exports = { validateConfig, encrypt, decrypt };
