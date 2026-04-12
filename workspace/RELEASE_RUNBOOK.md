# Release Runbook

## Goal
Publish Cybertron safely to startup production environments with repeatable steps.

## Pre-Release
1. Copy `workspace/.env.production.example` to `workspace/.env`, rotate every placeholder secret, and fill in the target public domain.
   - Or generate a bootstrap env with `npm run deploy:prod:env:generate --prefix workspace -- --output .env`
2. Run `npm install`.
3. Run `npm run qa:full`.
4. Run `npm run qa:backend:load`.
5. Run `npm run qa:release:self-check`.
6. Review `workspace/PRODUCTION_READINESS.md` and ensure all release-gate items are satisfied.
7. Confirm docs and changelog updates.

## Build And Package
1. Run `npm run release:full`.
2. Run `npm run deploy:prod:build`.
3. Verify artifacts:
   - `workspace/app/frontend/dist/`
   - `build/latest/`
   - `build/v1/`
4. Confirm `sitemap.xml` exists in all artifact directories.

## Deploy
1. Export production env vars:
   - `FRONTEND_ORIGIN`
   - `CORS_ALLOWED_ORIGINS`
   - `METRICS_AUTH_TOKEN`
2. Run `npm run deploy:prod:edge:up --prefix workspace` for public HTTPS edge deployment, or `npm run deploy:prod:up --prefix workspace` if TLS is terminated elsewhere.
3. Run `npm run qa:connectors --prefix workspace -- --env-file .env --require-healthy` if external connectors are configured.
4. Run `npm run qa:go-live --prefix workspace -- --env-file .env --base-url https://app.your-domain.com --email "<admin-email>" --password "<strong-password>"`.
5. Run staging smoke checks (routes, auth callback, API connectivity, readiness endpoint).
6. Promote same image set to production.

## Rollback
1. Keep previous container image tags and previous `build/latest` snapshot.
2. If production regression occurs, run `npm run deploy:prod:down`, redeploy previous image set.
3. Open incident log and assign P0/P1 owner.

## Post-Release
1. Verify analytics ingestion and API health.
2. Check frontend error logs.
3. Update `workspace/TEAM_EXECUTION_BOARD.md` with outcomes and next tasks.
