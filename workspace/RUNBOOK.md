# Runbook

## Local Development
1. Install dependencies
   - `npm install --prefix workspace/app/frontend`
   - `npm install --prefix workspace/app/backend`
   - Copy `workspace/.env.example` to `workspace/.env` and adjust values if needed.
2. Start full stack
   - `npm start` (from `C:\app\Cybertron`)
   - By default this performs a clean restart of ports `3000` and `8001` and brings up both frontend and backend.
   - Optional: `START_DEV_FORCE_FRESH=false npm start` to reuse already-running healthy services.
3. Frontend URL
   - `http://localhost:3000`
4. Backend health
   - `http://localhost:8001/v1/system/health`

## Local QA
- Full workspace gate: `npm run qa:full --prefix workspace`
- Backend load smoke: `npm run qa:backend:load --prefix workspace`
- Backend red-team checks only: `npm run qa:red-team --prefix app/backend`

## Deployment Path 1 (Recommended)
### Frontend
- Host static build on Vercel / Netlify / Cloudflare Pages or containerized Nginx.
- Configure reverse proxy to backend for `/api/*`.

### Backend
- Deploy container to Render / Fly.io / DigitalOcean App Platform / AWS ECS / Azure Container Apps.
- Required envs:
  - `NODE_ENV=production`
  - `AUTH_MODE=jwt_hs256`
  - `JWT_SECRET` strong secret
  - `DATABASE_URL` managed Postgres DSN
  - `CORS_ALLOWED_ORIGINS` frontend domain
  - `FRONTEND_ORIGIN` frontend domain
  - `METRICS_AUTH_TOKEN`

### Database
- Use managed Postgres (Neon / Supabase / Railway / RDS / Azure PostgreSQL).
- Ensure backups and SSL.

## Deployment Path 2 (Low-Cost Git-Connected)
- Frontend: Netlify/Vercel free tier from repo.
- Backend: Render/Fly.io free/low-cost web service from repo container.
- Database: free-tier managed Postgres (Neon/Supabase/Railway starter).
- Security floor remains unchanged (JWT secret, CORS allowlist, no demo auth in production).

## Docker Compose Production
- Dev up: `npm run deploy:dev:up --prefix workspace`
- Dev logs: `npm run deploy:dev:logs --prefix workspace`
- Dev down: `npm run deploy:dev:down --prefix workspace`
- Build: `npm run deploy:prod:build --prefix workspace`
- Up: `npm run deploy:prod:up --prefix workspace`
- Logs: `npm run deploy:prod:logs --prefix workspace`
- Down: `npm run deploy:prod:down --prefix workspace`

## Security Checklist
- `ALLOW_INSECURE_DEMO_AUTH=false`
- `AUTH_MODE=jwt_hs256`
- `JWT_SECRET` strong random value
- `ALLOW_PUBLIC_REGISTRATION=false` unless explicitly required
- `AUTH_MAX_FAILED_ATTEMPTS` and `AUTH_LOCKOUT_MS` tuned for brute-force control
- `AUTH_RATE_LIMIT_WINDOW_MS` and `AUTH_RATE_LIMIT_MAX_REQUESTS` tuned for auth endpoint abuse control
- `CORS_ALLOWED_ORIGINS` explicit domains only
- `ENFORCE_ORIGIN_VALIDATION=true`
- `METRICS_REQUIRE_AUTH=true`
- `METRICS_AUTH_TOKEN` set
- `DATABASE_URL` set (required for real threat persistence)
- TLS enabled at edge/load balancer
