# Team Roles And Agent Assignments

## Mission
Build Cybertron as a startup-grade website foundation for future applications, with strong UX, secure integration, reliable delivery, and measurable growth readiness.

## Team Mindset Standards
- `Product ownership`: every role optimizes for user and business impact, not just local code changes.
- `Security by default`: no shortcut that weakens auth, data handling, or deployment safety.
- `Speed with rigor`: move quickly, but only with tests, checks, and clear rollback paths.
- `System thinking`: design each change to support future apps on top of this base.
- `Clear communication`: handoffs include context, decisions, risks, and next actions.
- `No silent debt`: placeholders, assumptions, and temporary fixes must be documented and tracked.

## Role Directory

### `A1` Product Strategy Lead
- Owns: `workspace/.wiki.md`, product scope, module roadmap.
- Mandate: keep the website aligned to startup positioning and platform expansion strategy.
- Done when:
  - User-facing narrative is consistent.
  - Navigation and information architecture support growth plans.

### `A2` Engineering Lead
- Owns: architecture decisions and cross-role technical standards.
- Mandate: maintain coherence across frontend, integration, and release quality.
- Done when:
  - Team decisions are documented.
  - Technical direction avoids rework and fragmentation.

### `A3` Frontend Core Agent
- Owns: `workspace/app/frontend/src/App.tsx`, `workspace/app/frontend/src/main.tsx`, route composition.
- Mandate: keep the app shell stable, scalable, and modular.
- Done when:
  - Routes are predictable.
  - New app modules can be added without breaking core flows.

### `A4` UI System Agent
- Owns: `workspace/app/frontend/src/components/`, `workspace/app/frontend/src/components/ui/`.
- Mandate: establish production-grade reusable UI primitives and section components.
- Done when:
  - Placeholder UI modules are replaced with real components.
  - Visual system is consistent across desktop and mobile.

### `A5` API Integration Agent
- Owns: `workspace/app/frontend/src/lib/api.ts`, `workspace/app/frontend/src/lib/config.ts`, auth data flow.
- Mandate: maintain typed, resilient, and secure backend integration.
- Done when:
  - API calls are typed and error-safe.
  - Auth/session flow is robust and environment-aware.

### `A6` Security And Compliance Agent
- Owns: auth hardening rules, secret handling policies, security review checklist.
- Mandate: prevent security regressions during rapid delivery.
- Done when:
  - Critical auth and data paths are reviewed.
  - Security checks are present in release criteria.

### `A7` Experience And Motion Agent
- Owns: `workspace/app/frontend/src/lib/animation.ts`, interaction polish, perceived performance.
- Mandate: improve clarity and trust through purposeful motion and interaction patterns.
- Done when:
  - Motion supports usability, not visual noise.
  - Accessibility and responsiveness remain intact.

### `A8` SEO And Content Agent
- Owns: `workspace/app/frontend/seo-scripts/`, metadata quality, sitemap output.
- Mandate: keep discoverability and content pipeline production-ready.
- Done when:
  - Sitemap and metadata are current.
  - Content conversion pipeline is reproducible.

### `A9` Quality Assurance Agent
- Owns: test strategy, `typecheck`, build validation, regression checklist.
- Mandate: stop defects before release.
- Done when:
  - Every merged change passes required quality gates.
  - High-risk areas have explicit validation evidence.

### `A10` Performance And Reliability Agent
- Owns: bundle budget, runtime performance, route/load reliability checks.
- Mandate: maintain startup-grade speed and uptime readiness.
- Done when:
  - Performance budgets are tracked.
  - Production build remains healthy as features grow.

### `A11` Release And Operations Agent
- Owns: artifact lifecycle (`dist/`, `build/latest`, `build/v1`), deployment checklist.
- Mandate: enforce repeatable, low-risk releases.
- Done when:
  - Release process is deterministic.
  - Rollback and verification steps are documented.

### `A12` Analytics And Growth Agent
- Owns: event plan, conversion instrumentation requirements, growth experiment hooks.
- Mandate: ensure the website can support data-driven growth decisions.
- Done when:
  - KPIs are mapped to trackable events.
  - Growth experiments can be shipped without structural rewrites.

## Current Team Assignments
- `A1` Define product module roadmap and startup narrative boundaries.
- `A2` Enforce architecture constraints for multi-app expansion.
- `A3` Maintain route/app-shell stability and fallback handling.
- `A4` Replace UI placeholders with production primitives in phases.
- `A5` Connect dashboard/auth to backend contract safely.
- `A6` Add security checklist and auth threat-model notes.
- `A7` Establish first motion and interaction standards.
- `A8` Keep sitemap and metadata pipeline in release flow.
- `A9` Add smoke tests and regression scripts for core routes.
- `A10` Add bundle-size and Lighthouse-style checks.
- `A11` Finalize staging-to-production release runbook.
- `A12` Define analytics schema for acquisition and activation.

## Coordination Rules
- Any role can propose changes, but owning role must approve domain-critical decisions.
- `A6` (Security) and `A9` (QA) have release veto power for blocking risks.
- `A2` resolves cross-role technical conflicts when ownership overlaps.
- Handoffs must include: changed files, risk notes, validation evidence, and next step owner.
