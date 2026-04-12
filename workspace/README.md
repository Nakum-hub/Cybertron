# Cybertron Workspace

This folder contains the full-stack Cybertron monorepo used for local development and deployment.

## Structure
- `app/frontend` - Vite + React interface
- `app/backend` - Node.js API with security middleware and RBAC workflows
- `docker-compose.dev.yml` - local stack (frontend, backend, postgres)
- `docker-compose.prod.yml` - production stack template
- `scripts/start-dev.js` - single-command dev orchestrator

## Local Start
1. Install dependencies
   - `npm install --prefix app/frontend`
   - `npm install --prefix app/backend`
2. Run full stack
   - `npm start` (from repo root or workspace root)
   - `npm stop` (from repo root or workspace root)
3. URLs
   - Frontend: `http://127.0.0.1:3000`
   - Backend health: `http://127.0.0.1:8001/v1/system/health`

## Local Production Compose
1. Choose one environment template:
   - Internet-facing deployment: copy `.env.production.example` to `.env`
   - Local Docker validation: copy `.env.production.local.example` to `.env.production.local`
2. Build and start the stack
   - Internet-facing deployment:
     - `npm run deploy:prod:build`
     - `npm run deploy:prod:up`
     - With public edge TLS: `npm run deploy:prod:edge:up`
   - Local Docker validation:
     - `npm run deploy:prod:build:local`
     - `npm run deploy:prod:up:local`
3. Bootstrap the first usable admin account explicitly
   - `npm run deploy:prod:bootstrap-admin -- --password "<strong-password>"`
4. Run the authenticated production smoke check through the frontend proxy
   - `npm run deploy:prod:smoke -- --password "<strong-password>"`
5. Before any internet launch, run the go-live gate against the real deployed URL
   - `npm run qa:go-live -- --env-file .env --base-url https://app.your-domain.com --email "<admin-email>" --password "<strong-password>"`
6. Tear down when finished
   - `npm run deploy:prod:down`

The local-production template keeps public registration disabled, makes browser auth work on `http://127.0.0.1:8088`, and still preserves truthful origin enforcement.
The go-live gate rejects `.env.production.local`, `.example` templates, placeholder secrets, local-only storage/LLM endpoints, and any deployment where the default bootstrap admin still works.

If you do not already have a production env file, generate a secure bootstrap file first:
- `npm run deploy:prod:env:generate --prefix workspace -- --output .env`

That generator rotates JWT, metrics, database, and Redis secrets for you, sets the frontend behind a loopback-only port for edge TLS, and leaves only the truly external values as `REPLACE_ME_*`.

If you want the deployed stack to use the local H100 for AI inference, run `npm run ml:serve:vllm --prefix workspace` on the host, then set:
- `LLM_PROVIDER=openai`
- `OPENAI_BASE_URL=http://host.docker.internal:8000/v1`
- `OPENAI_API_KEY=<same token passed to the vLLM server>`
- `OPENAI_MODEL=cybertron-local`

That H100 host path is for machine-local validation, not an internet-facing production launch. The go-live gate will block local-only AI endpoints for public deployments.

If the GPU is on a Lightning AI machine and Cybertron is running somewhere else, start the model server on Lightning and forward it over SSH instead:
- Run `bash workspace/ml/start_vllm_openai_lora.sh` on the Lightning GPU host
- Run `bash workspace/ml/tunnel_lightning_vllm.sh` on the machine hosting Cybertron
- Then set `OPENAI_BASE_URL=http://127.0.0.1:18000/v1`

The Threat Command console now exposes `/v1/threat-intel/ai/runtime`, so you can verify that the tunneled Lightning runtime is actually reachable before you take the app public.

For a materially stronger local adapter before internet launch, build the official-source corpus first:
- `npm run ml:build:official-corpus --prefix workspace`
- `npm run ml:build:enterprise-corpus --prefix workspace`

The vLLM launcher now prefers the T4-trained `1.5B` adapter automatically on smaller GPUs such as a Tesla T4, and otherwise prefers the stronger `14B` adapter when that artifact exists.

## Quality Gates
- `npm run qa:smoke --prefix workspace`
- `npm run qa:full --prefix workspace`
- `npm run qa:red-team --prefix workspace`
- `npm run qa:failure --prefix workspace`
- `npm run qa:backend:load --prefix workspace` (sustained load profile, default 5 minutes)
- `npm run qa:backend:strict --prefix workspace` (strict DB-backed backend QA on machines without Docker/Postgres via embedded DB)
- `npm run qa:backend:coverage --prefix workspace` (backend unit coverage with HTML and lcov output in `app/backend/coverage`)
- `npm run qa:release --prefix workspace` (truthful release preflight; warns on local runtime payload)
- `npm run qa:connectors --prefix workspace -- --env-file .env` (honest Wazuh/MISP/OpenCTI/TheHive readiness)
- `npm run qa:go-live:self-check --prefix workspace` (verifies the launch gate rejects unsafe envs and accepts secure ones)
- `npm run qa:go-live --prefix workspace -- --env-file .env --base-url https://app.your-domain.com --email "<admin-email>" --password "<strong-password>"` (internet deployment gate)
- `npm run clean:runtime:dry-run --prefix workspace` (preview cleanup of `.runtime` and legacy `uploads`)

## Reports Center
- Upload endpoint: `POST /v1/reports/upload` (`multipart/form-data`, field name `file`)
- Download endpoint: `GET /v1/reports/:reportId/download`
- Storage: local runtime directory by default (`REPORT_STORAGE_DRIVER=local`, `.runtime/uploads/reports`) with optional S3 adapter.

## Core Principles
- No fabricated threat telemetry.
- Empty states are explicit when data/connectors are not configured.
- Tenant isolation and role checks are enforced server-side.
