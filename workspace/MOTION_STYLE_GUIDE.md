# Motion Style Guide

## Motion Tokens
Source: `workspace/app/frontend/src/lib/motion.ts` and `workspace/app/frontend/src/index.css`

### Durations
- `instant`: 120ms
- `fast`: 180ms
- `base`: 280ms
- `slow`: 420ms
- `cinematic`: 720ms

### Easings
- `standard`: `cubic-bezier(0.22, 1, 0.36, 1)`
- `smooth`: `cubic-bezier(0.4, 0, 0.2, 1)`

### 3D/Parallax
- Scene tilt max: 16deg
- Card tilt max: 5deg
- Layer shift: 40px baseline

## Patterns
- Page chrome: ambient mesh + grid + orb layers.
- Reveal: `.reveal-up` + `.is-visible` intersection activation.
- Card depth: `.panel-3d` with pointer glow and local tilt vars.
- CTA micro-interaction: `.magnetic-btn` with pointer-driven offsets.
- Loading: `.skeleton-line` shimmer placeholders.

## Reduced Motion Rules
- Keep visual hierarchy and polish; reduce amplitude/frequency.
- Disable perpetual ambient animations only when motion-reduced preference is active.
- Replace large transforms with mild/none transforms.
- Preserve transitions for clarity (shortened duration), do not hard-cut UI state changes.

## Do/Do Not
- Do reuse token variables and shared classes.
- Do use `requestAnimationFrame` for pointer/scroll-driven updates.
- Do not introduce isolated hardcoded transition curves per component.
- Do not replace cinematic style with generic template motion.