# Cybertron Copilot Instructions

- Treat the repo-root `package.json` and `workspace/package.json` as the command surface. Prefer root scripts like `npm start`, `npm stop`, `npm run qa:frontend`, and `npm run deploy:prod:build:local`.
- Frontend lives in `workspace/app/frontend` and uses React, TypeScript, Vite, and ESLint. Keep type safety intact; do not hide contract drift with `any`.
- Backend lives in `workspace/app/backend` and must preserve RBAC, tenant isolation, CSRF, CORS, rate limiting, plan gating, and auth/session correctness.
- AI honesty is mandatory. Template, rule-based, or fallback output must never be represented as equivalent to live LLM output.
- Do not remove product depth, premium UI layers, or major screens just to make checks pass.
- Keep plan access enforcement server-side. Internal/admin tooling must stay inaccessible to normal client tenants.
- Default local runtime artifacts belong under `workspace/.runtime`; do not add new release payload under tracked paths.
- Prefer fixes that keep these commands green: `npm run qa:frontend`, `npm run qa:backend:strict:skip-load`, `npm run qa:failure`, `npm run qa:ui-wiring:transaction`, `npm run qa:distributed:local`, and `npm run build:full`.
- Use `workspace/docker-compose.dev.yml` and `workspace/docker-compose.prod.yml` for production-like validation instead of inventing ad hoc start flows.
- The repo does not use Prettier as the primary formatter today. Respect existing formatting and ESLint-driven fixes.
