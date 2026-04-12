# Security Checklist

## Authentication
- [ ] Verify callback token handling only accepts expected token format.
- [ ] Ensure logout clears local token and invalidates backend session when available.
- [ ] Confirm protected API calls require bearer token by default.

## Frontend Data Handling
- [ ] Validate all API error states are user-safe and do not leak internal details.
- [ ] Avoid storing sensitive data beyond session token.
- [ ] Ensure no secrets are embedded in frontend source/env files.

## Headers And Platform
- [ ] Configure CSP at hosting layer for scripts/styles/connect-src.
- [ ] Enforce HTTPS and HSTS in production environment.
- [ ] Configure secure cookie policies when backend session cookies are introduced.

## Release Security Gates
- [ ] Run `npm run qa:full` before release.
- [ ] Review dependency vulnerabilities (`npm audit`).
- [ ] Security role sign-off required for auth/API changes.
