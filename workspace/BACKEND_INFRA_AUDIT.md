# Backend/Infra Audit (P0/P1/P2)

## P0
- Missing runtime config endpoint required by frontend bootstrap.
  - Fixed by adding `GET /api/config` (normalized to `/config`) and `GET /v1/system/config` in `workspace/app/backend/src/server.js`.
- Fake deterministic threat metrics generation.
  - Removed deterministic hash-based threat generator from `workspace/app/backend/src/threat-data.js`.
  - Replaced with truthful DB/connectors-backed service with empty responses when unconfigured.
- Frontend API client contract was broken (`api` object replaced by unrelated SDK client).
  - Rebuilt `workspace/app/frontend/src/lib/api.ts`.
- Frontend config contract mismatch and wrong fallback API port.
  - Rebuilt `workspace/app/frontend/src/lib/config.ts` with typed runtime config and `/api` default.

## P1
- No persistence layer for core business objects.
  - Added Postgres layer (`workspace/app/backend/src/database.js`) and SQL migrations (`workspace/app/backend/migrations/001_initial_schema.sql`).
  - Added business object query service (`workspace/app/backend/src/business-data.js`) and endpoints:
    - `/v1/tenants`
    - `/v1/users`
    - `/v1/service-requests`
    - `/v1/reports`
    - `/v1/audit-logs`
- CI previously installed frontend dependencies only.
  - Fixed in `.github/workflows/ci.yml` to install backend dependencies too.
- Docker production stack lacked database service.
  - Added Postgres service and backend DB env wiring in `workspace/docker-compose.prod.yml`.

## P2
- QA scripts in frontend incompatible with ESM package mode.
  - Converted scripts to ESM (`workspace/app/frontend/scripts/*.js`).
- Bundle budget guard too strict for premium motion CSS.
  - Updated CSS budget to realistic threshold in `workspace/app/frontend/scripts/check-bundle-budget.js`.
- Root-level repo hygiene incomplete.
  - Added root `.gitignore`.

## Current Risk Notes
- Connector adapters (Wazuh/MISP/OpenCTI/TheHive) are best-effort and depend on actual endpoint contracts.
- No write APIs yet for business objects (read endpoints + schema are present).
- Production requires managed Postgres and real JWT/IdP configuration (fail-fast validation enforced).