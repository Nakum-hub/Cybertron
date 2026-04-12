# Engineering Standards

## Code Quality
- TypeScript strict mode required.
- No unchecked `any` for domain models.
- Prefer composable modules over monolithic files.

## Testing And Validation
- Minimum gates: `typecheck`, `build`, `qa:smoke`, `perf:budget`.
- New features must include at least one validation path (automated or explicit manual matrix entry).

## API Integration
- Use centralized API client (`src/lib/api.ts`).
- Surface user-safe error states.
- Keep endpoint paths environment-driven via config.

## Security Baseline
- No secrets in client source.
- Token lifecycle handled through shared auth utility.
- Security checklist review required for auth/API changes.

## Release Discipline
- Releases run through `npm run release:full`.
- Artifact sync and rollback path must be available.
- Post-release verification required.
