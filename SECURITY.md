# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's **[private vulnerability reporting](https://github.com/isaacrowntree/durable-auth/security/advisories/new)**
(Security → Report a vulnerability). Include what you found, how to reproduce
it, and the impact. You'll get a response as soon as reasonably possible, and
credit in the release notes if you'd like it.

## Scope

**In scope:** flaws in this library — signing in as someone else, getting
around a passkey, a step-up check or a recovery code, learning whether an
email has an account, session or cookie weaknesses, a cross-origin request
that changes state, or anything that leaks a secret from the store.

**Out of scope:** how an app is deployed — its Worker secrets, its email
domain, its rate-limit and Turnstile settings, and its own routes' use of
`auth.session()`. The security of the inbox behind a recovery email is the
user's; see "What it doesn't do" in the README.

## Supported versions

Fixes land on `main` and ship as a patch release. Please test against the
latest release before reporting.

## Design notes for reviewers

- Session tokens: 32 random bytes; the store keeps `SHA-256(token)` only.
- Codes: six digits, rejection-sampled from 32-bit values; stored as
  `SHA-256(purpose:email:code)`. The attempt caps (5 a code, 10 a day per
  email, 1,000 a day across all emails, 5 codes an hour per email) are the
  protection, not the hash. Changing the recovery email retires codes sent
  to the old one.
- Challenges: single use, deleted on first sight, bound to a purpose and (for
  registration, adding a passkey and step-up) to an account.
- WebAuthn: `userVerification: "required"` everywhere; verification is
  `@simplewebauthn/server`.
- Every state-changing route checks `Origin` against the allowed origins; a
  request without one needs `Sec-Fetch-Site: same-origin`.
- Step-up gates are checked before any effect, so the client's single retry
  after confirming is safe.
- Schema migrations only add, and a database is never marked older than it
  is, so rolling a deploy back and forward again is safe.
