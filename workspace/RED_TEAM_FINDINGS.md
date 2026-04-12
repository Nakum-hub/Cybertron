# Red Team Findings (Latest Sprint)

## Scope
- Backend blackbox abuse checks
- Frontend-to-backend auth workflow checks
- Routing, legal surface, and API contract consistency checks

## Findings Before Fix
1. Auth endpoint brute-force pressure had no dedicated limiter.
   - Only global rate limiting existed, allowing aggressive auth-path retries.
2. Frontend auth card was mostly visual.
   - No direct password login submission to backend token endpoint from the showcase card.
3. Legal/public policy pages were missing as actual routes.
   - Footer links pointed to email addresses instead of immutable pages.
4. Service request list contract mismatch risk.
   - Response from backend list endpoint omitted fields expected by frontend workflows.

## Fixes Implemented
1. Added dedicated auth abuse limiter.
   - New env vars: `AUTH_RATE_LIMIT_WINDOW_MS`, `AUTH_RATE_LIMIT_MAX_REQUESTS`
   - Enforced on `POST` auth-sensitive routes.
2. Added real password login flow in frontend auth showcase.
   - Stores access/refresh tokens via frontend auth storage helpers.
3. Added legal routes/pages.
   - `/legal/privacy`
   - `/legal/terms`
   - `/legal/cookies`
4. Fixed service-request list shape.
   - Includes `tenant` and `description` fields for workflow consistency.
5. Added backend red-team script.
   - `workspace/app/backend/scripts/red-team-check.js`
   - Integrated into workspace backend QA gate.

## Verification
- `npm run qa` (repo root)
- `npm run qa:red-team` (repo root)

