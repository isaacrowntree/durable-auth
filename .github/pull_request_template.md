## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves. -->

## Verification

- [ ] `npm run typecheck` and `npm test`
- [ ] `npm run test:integration` (the Durable Object on workerd)
- [ ] `npm run test:e2e` (real WebAuthn in Chromium) — for any change to a route or the client
- [ ] A schema change appends to `MIGRATIONS` and adds an upgrade test in both suites

## Notes for reviewers

<!-- Anything non-obvious — especially threat-model impact: who can now do what, and what an attacker learns from each response. -->
