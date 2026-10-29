# Changelog

## 0.2.0 — 2026-10-29

- **Breaking:** `sendCode` now needs `codeSecret`, a Worker secret of at
  least 32 characters (`openssl rand -base64 32 | wrangler secret put
  CODE_SECRET`). `createAuth` throws without it. Emailed codes are stored as
  HMAC-SHA-256 under that key instead of a plain SHA-256, so a copy of the
  store alone can no longer be used to try the million six-digit codes
  offline. Codes sent before the upgrade stop working; they expire within
  10 minutes anyway.

## 0.1.0 — 2026-10-19

First release, extracted from [Rampset](https://github.com/isaacrowntree/rampset),
where it has run in production since October 2026.

- Passkey sign-up and sign-in in one Durable Object, with `createAuth` on the
  server and `createAuthClient` in the browser.
- Recovery by emailed code; `cloudflareEmail` sends over Cloudflare Email Sending.
- Step-up: deleting the account, changing the recovery email, and adding or
  removing a passkey need a passkey used in the last five minutes. The client
  confirms and retries on its own.
- Passkey list and remove; sign out other devices; an `allowSignup` hook;
  configurable `rpID`, origins, cookie name and base path; `parseProfile` for
  the app's own account data.
- A daily alarm sweeps expired challenges, sessions and codes.
- Opens Rampset's original database in place (schema version 1 → 2).
