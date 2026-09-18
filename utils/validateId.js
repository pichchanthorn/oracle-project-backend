// Shared path-parameter validation for routes that take a numeric :id.
// Returns a positive integer Number if valid, or null if not — callers
// respond 400 on null before running any DB query, so a malformed ID
// (non-numeric, negative, zero, decimal) never reaches Oracle and never
// produces an unhandled ORA-01722-style error.
function parsePositiveIntegerId(rawId) {
  if (typeof rawId !== 'string' || !/^[1-9][0-9]*$/.test(rawId)) {
    return null;
  }
  return Number(rawId);
}

module.exports = { parsePositiveIntegerId };
