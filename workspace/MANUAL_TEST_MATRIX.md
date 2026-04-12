# Manual Test Matrix

## Core Navigation
- [ ] Desktop nav links scroll to expected sections.
- [ ] Mobile menu opens, navigates, and closes correctly.

## Auth Flow
- [ ] `/auth/callback?token=...` stores token and redirects.
- [ ] Missing token callback handled gracefully.
- [ ] `/auth/error` message and auto-redirect behavior works.

## Dashboard
- [ ] Dashboard renders fallback data without backend.
- [ ] Dashboard renders live API data when backend is available.

## Build And Artifacts
- [ ] `dist/index.html` references valid built assets.
- [ ] `dist/sitemap.xml` generated.
- [ ] `build/latest` and `build/v1` synced with current build.

## Cross-Device
- [ ] Mobile layout intact on narrow viewport.
- [ ] Desktop spacing and typography remain stable.
