# Database migrations

Plain, hand-run, tracked SQL files. No migration framework (no Flyway, no
Liquibase) — this project intentionally stays with plain `.sql` files applied
manually against the Oracle database.

## Convention

- Files are named `NNN_description.sql`, zero-padded, in strictly increasing
  order (`001_auth_foundation.sql`, `002_...sql`, ...).
- Each file is additive/reviewable: it says in a header comment what it does
  and does not touch.
- Migrations are never edited after being applied to any shared database.
  A mistake is fixed by adding a new migration, not rewriting history.
- Before applying a migration, always check whether it (or the objects it
  creates) already exist — see the pre-flight queries at the top of each file.

## Applying a migration

Connect with SQL*Plus, SQLcl, or any Oracle client as the schema owner, then
run the file, e.g.:

```
sqlplus system/<password>@localhost:1522/FREEPDB1 @db/migrations/001_auth_foundation.sql
```

Review the pre-flight section at the top of the file first — it tells you
what to check before running anything.

## Validating after a migration

See `db/validate_auth_foundation.js` for a read-only Node script that checks
the schema state after `001_auth_foundation.sql` has been applied (new USERS
columns, constraints, AUTH_AUDIT_LOG structure, indexes, and that
FK_INVENTORY_USER / FK_SALES_CASHIER are still present and valid). It runs no
DDL and inserts no rows.
