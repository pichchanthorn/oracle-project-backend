// Reads and validates CORS configuration from process.env. Called once at
// startup (server.js) so a misconfigured deployment fails fast instead of
// starting with an unintentionally permissive (or broken) CORS policy.
// Mirrors the existing jwtService.js/cryptoService.js validate-at-startup
// pattern. Throws on missing/invalid config — never logs the value itself
// beyond what the operator already put in their own .env.
let cachedOrigin = null;

function loadOrigin() {
  const origin = process.env.CORS_ORIGIN;
  if (!origin || typeof origin !== 'string' || origin.trim().length === 0) {
    throw new Error('CORS_ORIGIN is missing. Set it to the exact allowed frontend origin in .env.');
  }
  return origin.trim();
}

// Validates configuration and caches it. Call this at startup so the
// process exits immediately on misconfiguration rather than serving
// requests under an unvalidated CORS policy.
function validateConfig() {
  cachedOrigin = loadOrigin();
  return cachedOrigin;
}

function getOrigin() {
  if (!cachedOrigin) {
    cachedOrigin = loadOrigin();
  }
  return cachedOrigin;
}

module.exports = { validateConfig, getOrigin };
