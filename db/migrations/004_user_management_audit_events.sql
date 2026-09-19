-- =============================================================================
-- Migration: 004_user_management_audit_events.sql
-- Phase:     F-2.1 - Backend User Management API
-- Purpose:   Allow AUTH_AUDIT_LOG to record ADMIN user-management events
--            (create/status-change) by widening the existing
--            CK_AUTH_AUDIT_LOG_EVENT_TYPE constraint. No new table or column
--            is required for this phase — USERS already has every field the
--            User Management API needs (ROLE, IS_ACTIVE, CREATED_AT,
--            UPDATED_AT, TWO_FACTOR_ENABLED, TWO_FACTOR_SECRET all predate
--            this migration).
--
-- SAFETY NOTES (read before running):
--   - This migration only replaces one CHECK constraint on AUTH_AUDIT_LOG. It
--     does NOT touch USERS, any business table, or any existing row.
--   - Dropping and recreating a CHECK constraint does not affect existing
--     rows (all existing EVENT_TYPE values are a subset of the new list), so
--     no data is at risk. It is not possible to ADD a value to an IN (...)
--     list via ALTER TABLE ... MODIFY CONSTRAINT — it must be dropped and
--     recreated (same approach as 002_login_audit_events.sql).
--   - Run inside a tool that stops on the first error
--     (WHENEVER SQLERROR EXIT).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- PRE-FLIGHT (run manually and review before applying anything below):
--
--   -- Confirm the current constraint definition (expect the 11-value list
--   -- from db/migrations/002_login_audit_events.sql, NOT including
--   -- USER_CREATE_SUCCESS / USER_CREATE_FAILURE / USER_STATUS_CHANGE):
--   SELECT search_condition FROM user_constraints
--   WHERE constraint_name = 'CK_AUTH_AUDIT_LOG_EVENT_TYPE';
--
--   -- If USER_CREATE_SUCCESS, USER_CREATE_FAILURE, or USER_STATUS_CHANGE is
--   -- already present, STOP — do not run this file again.
-- -----------------------------------------------------------------------------

WHENEVER SQLERROR EXIT SQL.SQLCODE;

ALTER TABLE AUTH_AUDIT_LOG DROP CONSTRAINT CK_AUTH_AUDIT_LOG_EVENT_TYPE;

ALTER TABLE AUTH_AUDIT_LOG ADD CONSTRAINT CK_AUTH_AUDIT_LOG_EVENT_TYPE
  CHECK (EVENT_TYPE IN (
    'REGISTER_SUCCESS','REGISTER_FAILURE',
    'LOGIN_SUCCESS','LOGIN_FAILURE','ACCOUNT_LOCKOUT',
    'PASSWORD_VERIFIED_2FA_REQUIRED',
    '2FA_SETUP','2FA_ENABLED','2FA_DISABLED',
    '2FA_VERIFY_SUCCESS','2FA_VERIFY_FAILURE',
    'USER_CREATE_SUCCESS','USER_CREATE_FAILURE',
    'USER_STATUS_CHANGE'
  ));

-- -----------------------------------------------------------------------------
-- End of migration 004_user_management_audit_events.sql
-- -----------------------------------------------------------------------------
