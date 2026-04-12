# Performance Checklist

## Build-Time
- [ ] Run `npm run perf:budget`.
- [ ] Confirm JS and CSS assets are within budget.

## Runtime
- [ ] Verify initial route load and navigation responsiveness.
- [ ] Avoid blocking long tasks in initial render path.
- [ ] Ensure fallback data keeps dashboard responsive on API failure.

## Ongoing
- [ ] Revisit bundle budget when adding large dependencies.
- [ ] Measure Lighthouse/Web Vitals on staging regularly.
