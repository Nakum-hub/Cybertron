# Final Architecture

## System Layout

Internet
 -> CDN / Edge / TLS
 -> Frontend (Vite build on Nginx)
 -> `/api/*` reverse proxy
 -> Backend (Node HTTP service)
 -> PostgreSQL (persistent system of record)
 -> Optional external sources (Wazuh / MISP / OpenCTI / TheHive)

## Runtime Data Flow
1. Browser loads frontend.
2. Frontend bootstraps runtime settings from `GET /api/config`.
3. Frontend calls backend APIs through `/api/v1/...`.
4. Backend enforces origin policy, auth, rate limits, overload shedding, and role checks.
5. Threat endpoints read PostgreSQL first, then optional connectors.
6. If no source is configured, backend returns truthful empty payloads.

## Security Boundary Summary
- Frontend static host: no direct DB connectivity.
- Backend: only trusted service with DB credentials and connector secrets.
- Security headers + CORS allowlist + auth checks + request IDs applied in backend.
- Production config validation blocks unsafe startup.

## Scaling Notes
- Current session/rate-limiter stores are in-memory (single instance baseline).
- For multi-instance production, move to distributed state store (Redis) for sessions/rate-limits.
- Postgres can be managed service with read replicas for analytics/reporting growth.