const oracledb = require('oracledb');
const { getConnection } = require('../db');

// Inserts one AUTH_AUDIT_LOG row. Never throws to the caller — a failure to
// record an audit event must not change the outcome of the registration (or
// any future auth action) that triggered it. Callers should still decide
// whether to await this before responding (to keep audit writes attempted
// even if the process exits right after), but must not let its rejection
// propagate into their own error handling.
async function recordAuthEvent({
  userId = null,
  usernameAttempted = null,
  eventType,
  eventResult,
  ip = null,
  userAgent = null,
  detail = null,
}) {
  let conn;
  try {
    conn = await getConnection();
    await conn.execute(
      `INSERT INTO auth_audit_log
         (user_id, username_attempted, event_type, event_result, ip_address, user_agent, detail)
       VALUES (:userId, :usernameAttempted, :eventType, :eventResult, :ip, :userAgent, :detail)`,
      {
        userId: { val: userId, type: oracledb.NUMBER },
        usernameAttempted,
        eventType,
        eventResult,
        ip,
        userAgent,
        detail,
      },
      { autoCommit: true }
    );
  } catch (err) {
    console.error('Failed to record auth audit event:', err.message);
  } finally {
    if (conn) await conn.close();
  }
}

module.exports = { recordAuthEvent };
