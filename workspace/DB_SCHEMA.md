# DB Schema + Migration Plan

## Implemented Migration
- File: `workspace/app/backend/migrations/001_initial_schema.sql`

## Tables
- `tenants`: tenant catalog
- `users`: user identity metadata + role + tenant scope
- `incidents`: real threat incidents used by `/v1/threats/*`
- `service_requests`: operational request queue
- `reports`: generated report metadata and checksums
- `audit_logs`: immutable action/event trace records
- `schema_migrations`: migration ledger

## Threat API Source of Truth
- `incidents` table fields consumed:
  - `tenant_slug`
  - `title`
  - `severity`
  - `status`
  - `blocked`
  - `detected_at`
  - `response_time_minutes`

## Migration Strategy
1. Keep SQL migrations additive and idempotent.
2. `DB_AUTO_MIGRATE=true` applies pending migrations at startup.
3. Use `npm run db:migrate --prefix workspace/app/backend` for explicit migration runs.
4. For breaking schema changes:
   - add compatible columns first,
   - deploy app supporting old+new,
   - backfill,
   - remove legacy fields in later migration.

## Production DB Requirements
- Managed Postgres preferred.
- Backups + PITR enabled.
- SSL/TLS enabled (`DB_SSL_MODE=require`) when host supports it.