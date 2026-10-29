# Changelog

## 0.3.1 — 2026-10-29

- Relative imports in the published files now carry their `.js` extension,
  so tools that resolve ESM strictly (Node, Deno, some test runners) can load
  the package, not only bundlers.

## 0.3.0 — 2026-10-29

Security fixes, from a review of the whole library:

- **Recovery no longer leaks whether an email has an account through the
  hourly cap.** `recover-start` counted towards an email's cap only when an
  account owned it, and `email-start` answered 429 at that cap, so mixing
  the two told a registered email from a free one. Recovery now counts
  either way, and adding an email counts against the asking account.
- **Wrong guesses at verification codes can't pause recovery.** They
  counted towards the 1,000-a-day cap across all emails, and adding an
  email needs no Turnstile, so one account could switch off recovery for
  everyone for a day. Verification now has its own budget: 10 wrong
  guesses a day and 5 codes an hour, per account.
- **Another account can't burn your verification code or spend your
  recovery allowance.** Verification codes are keyed by the account that
  asked, and asking to add someone else's email no longer counts against
  that email's cap.
- **Removing a passkey signs out every other session**, so a lost device
  that's still signed in is shut out with its key. The "never the last
  passkey" check and the delete are one step, so two removals at once can't
  leave an account with none.
- **Adding a passkey checks the session is fresh at the verify step too**,
  not only when the options were issued.
- Sign-up (account and passkey) and recovery (every session and passkey)
  are single, atomic store calls; schema migrations run in a transaction.
- Passkey counters only move forward.
- Rate limits count an IPv6 client by its /64.

Also:

- `turnstile.verify` is told the form (`"signup"` or `"recover"`), and
  `turnstileVerifier(secret, { hostnames, checkAction })` can check the
  hostname and action Turnstile reports.
- New exports: `sameOrigin(req, origins?)`, the origin rule the routes use,
  for an app's own routes; `rateLimitSubject(ip)`; the `Transaction` and
  `TurnstileAction` types.
- `AuthStore.deletePasskey` returns `"removed" | "missing" | "last"`;
  `deletePasskeysFor` is replaced by `revokeEverything`, and sign-up uses
  `createAccountWithPasskey`. Schema version 3 rebuilds the codes table in
  place; outstanding codes carry over.
- Docs: SECURITY.md, the docs site and llms.txt described codes as plain
  SHA-256 after 0.2.0; they now say HMAC under `codeSecret`. The example's
  local `CODE_SECRET` moves to a gitignored `.dev.vars`.
- CI: the publish job that holds the npm token no longer runs dev
  dependencies; actions are pinned by commit SHA.

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
