# GitHub Student Pack Redemption Checklist For Cybertron

Use this checklist to redeem benefits in the right order. Do not burn time-limited credits before Cybertron is ready to use them.

## Now

- [ ] Confirm GitHub Student verification is active
- [ ] Confirm GitHub Copilot Pro is enabled in account settings
- [ ] Confirm GitHub Pro benefits are active
- [ ] Confirm GitHub Codespaces is available on the account
- [ ] Confirm GitHub Models access works from the GitHub UI or API
- [ ] Install GitHub CLI
- [ ] Sign in with `gh auth login`
- [ ] If `gh` is not recognized in the current terminal after install, open a new terminal session
- [ ] Install the Cybertron VS Code extension set:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\install-vscode-extensions.ps1 -Set expanded`
- [ ] Run GitHub tooling verification:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\verify-github-tooling.ps1`
- [ ] Open Cybertron once in VS Code and accept recommended workspace extensions
- [ ] Open Cybertron once in a dev container or Codespace
- [ ] Redeem 1Password
- [ ] Redeem Doppler
- [ ] Redeem Codecov

## When External Demo Or Staging Is 1-2 Weeks Away

- [ ] Redeem DigitalOcean credits
- [ ] Create a Cybertron staging project
- [ ] Deploy the Dockerized stack externally
- [ ] Decide between Datadog and Honeybadger
- [ ] Redeem the chosen observability offer
- [ ] Add staging telemetry and alert basics
- [ ] Redeem BrowserStack if real browser/device validation is now necessary

## When Billing And Go-To-Market Become Real

- [ ] Redeem one domain offer only
- [ ] Point the domain at Cybertron demo/staging or launch environment
- [ ] Redeem Stripe benefit
- [ ] Validate subscription/upgrade flows end-to-end
- [ ] If marketing traffic matters, add GitHub Pages or a public microsite only if useful

## When Product Complexity Justifies It

- [ ] Choose only one feature-flag platform:
  - DevCycle
  - ConfigCat
- [ ] Redeem LocalStack if AWS-shaped storage/integration work is active
- [ ] Redeem Testmail if email flows are part of staging QA
- [ ] Redeem DeepScan only if frontend static-analysis signal is worth the added noise
- [ ] Redeem GitLens/GitKraken only if repo history/review complexity is becoming a tax

## Intentionally Deferred

- [ ] Appwrite
  - Keep deferred unless you intentionally build a side project outside the Cybertron core backend
- [ ] MongoDB Atlas
  - Keep deferred unless you intentionally add a MongoDB-specific service
- [ ] AstraSecurity
  - Keep deferred until the external web surface is mature enough for that layer to matter

## Activation Order Summary

1. GitHub-native benefits
2. Editor/workspace enablement
3. Secret management and coverage visibility
4. External demo/staging infrastructure
5. Monitoring and browser/device validation
6. Domain and billing
7. Feature flags and cloud-emulation extras
