-- =============================================================================
-- Migration: 003_inventory_index.sql
-- Phase:     9 - Inventory Ledger
-- Purpose:   Tighten INVENTORY.CHANGED_BY to NOT NULL (the application always
--            supplies it from the verified JWT user going forward) and add
--            the PRODUCT_ID index required by stock/history lookups.
--
-- SAFETY NOTES (read before running):
--   - This migration only ALTERs the existing INVENTORY table in place. It
--     does NOT drop, recreate, or rename INVENTORY, and does not touch any
--     other table (PRODUCTS, SALES, SALE_ITEMS, USERS, AUTH_AUDIT_LOG, the
--     generic AUDIT_LOG, or any auth/2FA schema).
--   - This migration does NOT insert any rows.
--   - Making CHANGED_BY NOT NULL is safe only because INVENTORY currently
--     has 0 rows (verified during the Phase 9 audit) — there is no existing
--     NULL value that would make the ALTER fail. Re-confirm the row count is
--     still 0 immediately before running this in any other environment.
--   - No trigger is created on INVENTORY. CHANGED_BY/CHANGED_AT remain the
--     sole, authoritative attribution fields, populated by the application.
--   - Run inside a tool that stops on the first error
--     (WHENEVER SQLERROR EXIT).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- PRE-FLIGHT (run manually and review before applying anything below):
--
--   -- Confirm INVENTORY is still empty (required for the NOT NULL change
--   -- below to succeed without a backfill):
--   SELECT COUNT(*) FROM INVENTORY;
--
--   -- Confirm this migration has not already been applied:
--   SELECT column_name, nullable FROM user_tab_columns
--   WHERE table_name = 'INVENTORY' AND column_name = 'CHANGED_BY';
--   SELECT index_name FROM user_indexes
--   WHERE table_name = 'INVENTORY' AND index_name = 'IX_INVENTORY_PRODUCT_ID';
--
--   If CHANGED_BY is already NULLABLE = 'N', or the index already exists,
--   STOP. Do not run this file — report back instead.
-- -----------------------------------------------------------------------------

WHENEVER SQLERROR EXIT SQL.SQLCODE;

-- -----------------------------------------------------------------------------
-- 1. Make INVENTORY.CHANGED_BY NOT NULL (safe: table is empty)
-- -----------------------------------------------------------------------------

ALTER TABLE INVENTORY MODIFY (CHANGED_BY NUMBER NOT NULL);

-- -----------------------------------------------------------------------------
-- 2. Index INVENTORY.PRODUCT_ID (required by stock-sum and history queries)
-- -----------------------------------------------------------------------------

CREATE INDEX IX_INVENTORY_PRODUCT_ID ON INVENTORY(PRODUCT_ID);

-- -----------------------------------------------------------------------------
-- End of migration 003_inventory_index.sql
-- -----------------------------------------------------------------------------
