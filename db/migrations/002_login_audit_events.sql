-- =============================================================================
-- Migration: 002_login_audit_events.sql
-- Phase:     3 - JWT Authentication + Login + Access-Token Middleware
-- Purpose:   Allow AUTH_AUDIT_LOG to record the PASSWORD_VERIFIED_2FA_REQUIRED
--            event (password correct, but a 2FA challenge is now required)
--            by widening the existing CK_AUTH_AUDIT_LOG_EVENT_TYPE constraint.
--
-- SAFETY NOTES (read before running):
--   - This migration only replaces one CHECK constraint on AUTH_AUDIT_LOG. It
--     does NOT touch USERS, any business table, or any existing row.
--   - Dropping and recreating a CHECK constraint does not affect existing
--     rows (all existing EVENT_TYPE values are a subset of the new list), so
--     no data is at risk. It is not possible to ADD a value to an IN (...)
--     list via ALTER TABLE ... MODIFY CONSTRAINT — it must be dropped and
--     recreated.
--   - Run inside a tool that stops on the first error
--     (WHENEVER SQLERROR EXIT).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- PRE-FLIGHT (run manually and review before applying anything below):
--
--   -- Confirm the current constraint definition (expect the 10-value list
--   -- from db/migrations/001_auth_foundation.sql, NOT including
--   -- PASSWORD_VERIFIED_2FA_REQUIRED):
--   SELECT dbms_metadata.get_ddl('TABLE','AUTH_AUDIT_LOG') FROM dual;
--
--   -- Confirm this migration has not already been applied — attempt an
--   -- insert/rollback style check is unnecessary; instead just check the
--   -- constraint text above. If PASSWORD_VERIFIED_2FA_REQUIRED is already
--   -- present, STOP — do not run this file again.
-- -----------------------------------------------------------------------------

WHENEVER SQLERROR EXIT SQL.SQLCODE;

ALTER TABLE AUTH_AUDIT_LOG DROP CONSTRAINT CK_AUTH_AUDIT_LOG_EVENT_TYPE;

ALTER TABLE AUTH_AUDIT_LOG ADD CONSTRAINT CK_AUTH_AUDIT_LOG_EVENT_TYPE
  CHECK (EVENT_TYPE IN (
    'REGISTER_SUCCESS','REGISTER_FAILURE',
    'LOGIN_SUCCESS','LOGIN_FAILURE','ACCOUNT_LOCKOUT',
    'PASSWORD_VERIFIED_2FA_REQUIRED',
    '2FA_SETUP','2FA_ENABLED','2FA_DISABLED',
    '2FA_VERIFY_SUCCESS','2FA_VERIFY_FAILURE'
  ));

-- -----------------------------------------------------------------------------
-- End of migration 002_login_audit_events.sql
-- -----------------------------------------------------------------------------
