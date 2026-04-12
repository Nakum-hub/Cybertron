# Analytics Plan

## Objectives
- Measure acquisition, activation, and trust signals for Cybertron launch.
- Enable data-driven iteration for website-to-product conversion.

## Core Events
- `nav_click`: top-level navigation interactions.
- `cta_click`: primary conversion actions.
- `auth_action`: login/logout/callback events.
- `threat_view`: exposure to dashboard telemetry section.
- `pricing_view`: exposure to pricing section.

## Event Payload Baseline
- `timestamp`
- `environment`
- `location`
- `target`
- `label`
- `action`

## Initial KPIs
- Landing-to-pricing view rate.
- CTA click-through rate.
- Auth initiation rate.
- Auth success vs auth error ratio.

## Implementation Notes
- Events are emitted via `src/lib/analytics.ts`.
- Non-production environments log events for debugging.
- Production collector can be connected through `window.dataLayer` ingestion.
