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
  `HMAC-SHA-256(codeSecret, purpose:email:code)`. The key is a Worker
  secret the store never holds, so a copy of the store can't be used to try
  the million codes offline. Online, the attempt caps are the protection.
  Recovery codes: 5 guesses a code, 10 a day per email, 1,000 a day across
  all emails, 5 codes an hour per email (counted whether or not the email
  has an account). Verification codes (adding an email) are keyed to the
  account that asked: 5 guesses a code, 10 a day and 5 codes an hour per
  account, and they never touch recovery's caps. Changing the recovery email
  retires codes sent to the old one.
- Challenges: single use, deleted on first sight, bound to a purpose and (for
  registration, adding a passkey and step-up) to an account.
- WebAuthn: `userVerification: "required"` everywhere; verification is
  `@simplewebauthn/server`.
- Every state-changing route checks `Origin` against the allowed origins; a
  request without one needs `Sec-Fetch-Site: same-origin`.
- Step-up gates are checked before any effect, so the client's single retry
  after confirming is safe.
- Steps that write more than one thing — sign-up (account and passkey),
  recovery (every session and passkey), removing a passkey (checked against
  being the last, then other sessions signed out) — are one store call each,
  run as one transaction in the Durable Object.
- Schema migrations run in a transaction, only add (or rebuild a table with
  the same rows), and a database is never marked older than it is, so
  rolling a deploy back and forward again is safe.
- Rate limits count an IPv6 client by its /64.

## OWASP ASVS mapping

Against [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en)
(May 2025): V6 Authentication, V7 Session Management, and the cookie, CSRF
and anti-automation parts of V3 and V2. The requirement summaries are ours;
read the standard for the exact wording. "App's" means the requirement falls
to the app using durable-auth, not to the library. Requirements on passwords
(V6.2), identity providers (V6.8, V7.6), TOTP, SMS and push (parts of V6.5,
V6.6) don't apply: there are none.

| ASVS 5.0.0 | In short | How durable-auth meets it | Status |
|---|---|---|---|
| **V6 Authentication** | | | |
| 6.1.1 (L1) | Document the brute-force and anti-automation controls, including how they avoid malicious lockout | README "Security model"; caps in `store.ts`. A stranger *can* lock one email's recovery for a day, or everyone's with a flood of wrong recovery guesses (each behind Turnstile when configured); that's documented as the trade, and passkey sign-in is unaffected. Verification codes have their own budgets, so a signed-in account can't spend anyone's recovery allowance | Partially |
| 6.1.3, 6.3.4 (L2) | Every way in is documented, with its controls applied consistently | Two: passkey sign-in, and email-code recovery (optional, `sendCode`). Recovery is weaker than a passkey and says so ("The email account is the recovery factor") | Met |
| 6.3.1 (L1) | Brute-force controls are in place | `AuthStore.redeemCode`: 5 guesses a code; recovery 10 a day per email and 1,000 a day overall; verification 10 a day per account. `issueCode`: 5 recovery codes an hour per email, 5 verification codes an hour per account; `rateLimit` per IP (IPv6 per /64) per route kind | Met |
| 6.3.2 (L1) | No default accounts | There are none | Met |
| 6.3.3 (L2) | Multi-factor, or an equivalent combination, to get in | Passkeys with `userVerification: "required"` (a device plus its biometric or PIN) everywhere. Email recovery is a single factor | Partially |
| 6.3.5 (L3) | Tell users about suspicious sign-in attempts | No hook for it | Not met |
| 6.3.6 (L3) | Email is not an authentication factor | Email recovery signs in with an emailed code. Leave out `sendCode` to meet this | Not met by default |
| 6.3.7 (L3) | Tell users when their authentication details change | No notification when a passkey is added or removed or the email changes | Not met |
| 6.3.8 (L3) | Failed attempts don't reveal which users exist | `recover-start` and `email-start` answer the same whether or not the email has an account, under caps that count the same either way (recovery per email, verification per asking account, so neither can read the other) and (with `waitUntil`) the same timing; there are no usernames to probe. Tested as a sequence mixing both routes | Met |
| 6.4.2 (L1) | No password hints or secret questions | None | Met |
| 6.4.3 (L2) | Resetting doesn't bypass other factors | Recovery replaces the passkey by design, so it bypasses it; it then revokes every passkey and session (`recover-verify`) so a stolen device is shut out | Partially |
| 6.4.4 (L2) | Replacing a lost factor proves identity as well as enrolment did | Sign-up proves nothing beyond a passkey; recovery needs the verified email *and* the code | Met |
| 6.5.1 (L2) | One-time codes work once | `redeemCode` deletes on success; challenges are deleted on first sight (`consumeChallenge`). Property-tested in `store.property.test.ts` | Met |
| 6.5.2 (L2) | Low-entropy codes stored with a salted password hash | HMAC-SHA-256 under `codeSecret`, a Worker secret the store never holds, over purpose, email and code (`hashCode`). Not a slow password hash, but a copy of the store alone can't test a guess; with the key as well, the attempt caps and 10-minute life are what's left | Partially |
| 6.5.3 (L2) | Codes come from a CSPRNG | `crypto.getRandomValues`, rejection-sampled (`sixDigitCode`) | Met |
| 6.5.4 (L2) | Codes have at least 20 bits of entropy | Six random digits, which the standard names as sufficient | Met |
| 6.5.5 (L2) | Out-of-band codes live 10 minutes at most | `CODE_TTL_MS` = 10 minutes | Met |
| 6.5.6 (L3) | Any factor can be revoked if lost | `passkey-delete`; recovery revokes every passkey | Met |
| 6.5.7 (L3) | Biometrics only alongside something you have | A biometric only unlocks the passkey on its device | Met |
| 6.6.2 (L2) | An emailed code is bound to the request it was sent for | Bound to email, purpose and account (a verification code to the account that asked), and replaced by that account's newer code; not bound to the browser that asked | Partially |
| 6.6.3 (L2) | Emailed codes are rate limited against brute force | As 6.3.1 | Met |
| 6.7.2 (L3) | Challenge nonces are at least 64 bits and unique | SimpleWebAuthn's 32 random bytes, single use, 5-minute life, bound to purpose and account | Met |
| **V7 Session management** | | | |
| 7.1.1 (L2) | Document inactivity and absolute lifetimes, and any deviation from NIST 800-63B | README: a sliding one-year session, with step-up (5 minutes) for sensitive actions instead of re-authentication. No justification against 800-63B is written down | Partially |
| 7.1.2 (L2) | Document how many concurrent sessions are allowed | Unlimited; not stated | Partially |
| 7.2.1 (L1) | Tokens verified by a trusted backend | `AuthStore.session` looks up the token's hash | Met |
| 7.2.2 (L1) | Dynamically generated tokens | Random per sign-in | Met |
| 7.2.3 (L1) | Reference tokens from a CSPRNG with 128+ bits | 256 bits (`randomToken`), stored as SHA-256 | Met |
| 7.2.4 (L1) | New token on every authentication, the old one ended | New session on sign-in, sign-up and recovery. Step-up marks the existing session verified rather than rotating it, and signing in doesn't end a session the browser already had | Partially |
| 7.3.1 (L2) | Inactivity timeout | A year unused (`SESSION_TTL_MS`) — long, and the app's to shorten by wrapping `auth.session()` | Partially |
| 7.3.2 (L2) | Absolute maximum lifetime | None: a session in use slides forever | Not met |
| 7.4.1 (L1) | A terminated session can't be used again | `logout` deletes the row; expiry deletes it on sight | Met |
| 7.4.2 (L1) | Deleting an account ends its sessions | `delete-account` signs out everywhere first | Met |
| 7.4.3 (L2) | Option to end other sessions after a factor changes | `logout-others`; recovery ends them all itself, and removing a passkey ends every session but the one removing it | Met |
| 7.4.4 (L2) | Visible logout | The app's UI, calling the client's `signOut()` | App's |
| 7.4.5 (L2) | Admins can end a user's (or everyone's) sessions | `deleteSessionsFor` is on the store; no admin route | App's |
| 7.5.1 (L2) | Re-authenticate before changing email or factors | `requireFresh` on `email-start`, `passkey-options`, `passkey-verify`, `passkey-delete` and `delete-account`, with a passkey (user-verified) or, just after recovery, the emailed code | Met |
| 7.5.2 (L2) | Users can see and end their sessions | `logout-others` ends them, but there's no list to see | Partially |
| 7.5.3 (L3) | Extra authentication before highly sensitive operations | Step-up on the library's own; the app's own can check `session.verifiedAt` | App's |
| **V3 Web frontend, V2 business logic** | | | |
| 3.3.1, 3.3.3 (L1, L2) | `Secure` and the `__Host-` prefix on cookies | `SessionCookie`, over HTTPS (dropped only on http://localhost) | Met |
| 3.3.2 (L2) | `SameSite` set for the cookie's purpose | `SameSite=Lax` | Met |
| 3.3.4 (L2) | `HttpOnly`, and the token only ever in `Set-Cookie` | Both | Met |
| 3.5.1 (L1) | Cross-origin requests to sensitive functions are refused without relying on preflight | `sameOrigin`: an allowed `Origin`, or `Sec-Fetch-Site: same-origin` | Met |
| 3.5.3 (L1) | Sensitive functions aren't on safe methods | Every state change is POST or PUT | Met |
| 2.4.1 (L2) | Anti-automation against excessive calls | Store caps always; per-IP `rateLimit` and Turnstile are options, off unless configured | App's |
