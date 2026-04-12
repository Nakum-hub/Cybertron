# Team Operating Model

## Objective
Run Cybertron development like a disciplined startup team with clear ownership, fast feedback, and production-safe execution.

## Cadence
- `Daily sync`: blockers, priorities, ownership updates.
- `Twice-weekly planning`: adjust scope, dependencies, and release target.
- `Weekly quality review`: defects, performance drift, security concerns.
- `Release review`: checklist sign-off from Engineering Lead, QA, Security, and Release Ops.

## Workflow Stages
1. `Intake`
2. `Discovery`
3. `Implementation`
4. `Validation`
5. `Release`
6. `Post-release review`

## Definition Of Ready
- Problem statement is clear.
- Role owner is assigned.
- Dependencies and risks are identified.
- Acceptance criteria is measurable.

## Definition Of Done
- Code and docs updated.
- `typecheck` and `build` pass.
- Role-specific checks are complete.
- Change impact and rollback notes are documented.

## Handoff Template
- `Owner`
- `Scope completed`
- `Files changed`
- `Risks/assumptions`
- `Validation performed`
- `Next role and expected output`

## Decision Protocol
- Product direction: Product Strategy Lead (`A1`) final call.
- Technical architecture: Engineering Lead (`A2`) final call.
- Security-critical decisions: Security Agent (`A6`) approval required.
- Release readiness: QA (`A9`) + Release Ops (`A11`) joint sign-off.

## Risk Classes
- `P0`: security/data loss/critical outage risk, immediate block.
- `P1`: user-impacting bug in primary flow, hotfix priority.
- `P2`: degraded quality/performance, scheduled in next cycle.
- `P3`: cosmetic/non-blocking, backlog.

## Team Behavior Rules
- Never leave ambiguous placeholders without explicit backlog items.
- No production release without documented validation evidence.
- Prefer small, reviewable increments over large unbounded rewrites.
- Keep docs synchronized with code after each significant change.
