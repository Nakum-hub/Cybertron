# Cybertron Frontend

Vite + React + Tailwind frontend for Cybertron corporate site and platform shell.

## Key Capabilities
- Cinematic landing page with preserved 3D-style motion system and route transitions.
- Runtime config bootstrap via `GET /api/config`.
- Auth callback/error routes wired to backend auth flow.
- Platform shell (`/platform`) with tenant/role-aware module routing.

## Commands
- `npm run dev` start frontend dev server on `http://localhost:3000`
- `npm run build` production build
- `npm run qa:full` lint + typecheck + build + smoke + bundle budget
- `npm run preview` preview production build

## Runtime Config Contract
Frontend loads runtime config before render from `/api/config`.
Supported fields:
- `apiBaseUrl` / `API_BASE_URL`
- `authLoginPath`, `authTokenPath`, `authMePath`, `authLogoutPath`
- `threatSummaryPath`, `threatIncidentsPath`
- `systemHealthPath`, `platformAppsPath`
- `analyticsEnabled`, `environment`

If runtime config is unavailable, frontend falls back to `.env` values.

## Motion System
- Shared motion tokens in `src/lib/motion.ts`
- Unified CSS motion variables in `src/index.css`
- Reduced-motion support via `prefers-reduced-motion`

## Build Notes
- `build:full` also runs smoke checks and bundle budget guard.
- Nginx reverse-proxy is configured at `nginx/default.conf` for `/api/*` -> backend.
