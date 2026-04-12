# Cybertron

Cybertron is a full-stack cybersecurity platform foundation with a cinematic frontend, secured backend APIs, and deploy-ready infrastructure.

## Quick Start
- `npm install --prefix workspace/app/frontend`
- `npm install --prefix workspace/app/backend`
- `npm start`
- `npm stop`

## Local Production Stack
- Internet-facing deployment:
  - Copy `workspace/.env.production.example` to `workspace/.env` and set real secrets.
  - `npm run deploy:prod:build`
  - `npm run deploy:prod:up`
- Local Docker validation:
  - Copy `workspace/.env.production.local.example` to `workspace/.env.production.local`
  - `npm run deploy:prod:build:local`
  - `npm run deploy:prod:up:local`
- `npm run deploy:prod:bootstrap-admin -- --password "<strong-password>"`
- `npm run deploy:prod:smoke -- --password "<strong-password>"`
- `npm run deploy:prod:down`

## Quality Gates
- `npm run qa`
- `npm run qa:frontend`
- `npm run qa:red-team` (backend abuse/security blackbox checks)
- `npm run qa:backend:strict` (strict DB-backed backend QA using embedded DB when Docker/Postgres is unavailable)
- `npm run qa:release`
- `npm run clean:runtime:dry-run`

## Key Docs
- `workspace/UI_MOTION_AUDIT.md`
- `workspace/BACKEND_INFRA_AUDIT.md`
- `workspace/MOTION_STYLE_GUIDE.md`
- `workspace/FINAL_ARCHITECTURE.md`
- `workspace/DB_SCHEMA.md`
- `workspace/RUNBOOK.md`
- `workspace/README.md`

## Monorepo Layout
- Frontend: `workspace/app/frontend`
- Backend: `workspace/app/backend`
- Production compose: `workspace/docker-compose.prod.yml`
