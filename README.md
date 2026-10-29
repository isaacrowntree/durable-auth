# durable-auth

**Passkey sign-in for Cloudflare Workers, kept in one Durable Object.**
Accounts, passkeys, sessions and email recovery in the Durable Object's own
SQLite. No auth service, no user database, nothing to configure in a dashboard.

[![npm](https://img.shields.io/npm/v/durable-auth?color=cb3837&logo=npm)](https://www.npmjs.com/package/durable-auth)
[![ci](https://github.com/isaacrowntree/durable-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/isaacrowntree/durable-auth/actions/workflows/ci.yml)
[![codeql](https://github.com/isaacrowntree/durable-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/isaacrowntree/durable-auth/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```
npm i durable-auth
```

**[Docs →](https://isaacrowntree.com/durable-auth/)** ·
[vs Access, Better Auth, Clerk, Auth0](https://isaacrowntree.com/durable-auth/vs.html) ·
[Write-up](https://zackdesign.biz/durable-auth/)

Anyone can create an account with Face ID, Touch ID, Windows Hello or a
security key: no password, and no username to sign in, because the passkey says who
they are. An optional recovery email gets them back in after losing every device.
It runs in production behind [Rampset](https://liftlog.zackdesign.biz), an
offline-first barbell app, and pairs with
[durable-sync](https://github.com/isaacrowntree/durable-sync).

---

## Why this exists

On an all-Cloudflare stack, the usual ways to put a login on an app each cost
something:

- **Cloudflare Access** is a dashboard allowlist of emails. It's fine for a team,
  but the wrong shape for an app anyone can sign up to.
- **Hosted auth** (Clerk, Auth0) is another vendor, another bill, and your
  users live somewhere else.
- **Auth libraries** (Better Auth and friends) want a database and an adapter.
  On Workers that means D1 plus migrations to sign a user in.

A Durable Object already has the property sign-in needs most: **it does one
thing at a time, with its own SQLite.** "Check this code, then burn it" and
"check this challenge, then consume it" are atomic without transactions.
"This email belongs to one account" is a plain `UNIQUE` constraint. So this is
small on purpose: one Durable Object, about 1,500 lines of TypeScript, and
[SimpleWebAuthn](https://simplewebauthn.dev) for the passkey cryptography,
which is the one part nobody should write themselves.

## What you get

| | |
|---|---|
| **Passkeys** | discoverable (no username), user verification required, single-use challenges bound to their purpose and account |
| **Sessions** | 256-bit tokens in an `HttpOnly`, `SameSite=Lax`, `__Host-` cookie; only a SHA-256 hash is stored; sliding one-year expiry |
| **Step-up** | deleting the account, changing the recovery email, and adding or removing a passkey need a passkey (or, just after recovery, the emailed code) used in the last 5 minutes. The client asks for it and retries on its own |
| **Recovery** | six-digit codes by email, 10-minute expiry, 5 guesses a code, 5 codes an hour and 10 wrong guesses a day per email, 1,000 wrong guesses a day in all. Recovering signs every device out and revokes every passkey. Adding an email has its own budget, per account, so it can't spend anyone's recovery allowance |
| **No enumeration** | "is this email registered?" can't be learned from recovery or from adding an email: the answers, the rate limits and (with `waitUntil`) the timing are the same either way |
| **Also** | passkey list and remove, sign out other devices, a sign-up hook, per-IP rate limits, Turnstile, a daily sweep of expired rows |

## Server

```ts
// worker.ts
import { AuthDurableObject, createAuth, cloudflareEmail, rateLimitBinding } from "durable-auth/server";

export class Auth extends AuthDurableObject {}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const auth = createAuth({
      store: env.AUTH,
      rpName: "My App",
      sendCode: cloudflareEmail(env.EMAIL, { from: "noreply@myapp.com", appName: "My App" }),
      codeSecret: env.CODE_SECRET, // openssl rand -base64 32 | wrangler secret put CODE_SECRET
      rateLimit: rateLimitBinding(env.AUTH_LIMITER),
      waitUntil: (work) => ctx.waitUntil(work),
    });

    const handled = await auth.handle(req); // everything under /auth/*
    if (handled) return handled;

    const account = await auth.account(req); // your routes: who's signed in?
    if (!account) return new Response("Sign in first", { status: 401 });
    return new Response(`Hello, ${account.name}`);
  },
};
```

```jsonc
// wrangler.jsonc
{
  "durable_objects": { "bindings": [{ "name": "AUTH", "class_name": "Auth" }] },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Auth"] }],
  // Optional: recovery email (onboard the domain with `wrangler email sending enable`).
  "send_email": [{ "name": "EMAIL" }],
  // Optional: per-IP limits on the sign-in routes.
  "ratelimits": [{ "name": "AUTH_LIMITER", "namespace_id": "1001", "simple": { "limit": 10, "period": 60 } }]
}
```

Onboarding a domain to Cloudflare Email Sending only adds records on a
`cf-bounce` subdomain, so a domain whose mail is on Gmail or Workspace keeps
working.

## Client

```ts
import { createAuthClient, authErrorMessage } from "durable-auth/client";

const auth = createAuthClient();

await auth.register("Sam");          // passkey prompt → account → signed in
await auth.signIn();                 // passkey prompt, no username
await auth.session();                // Account | null (signed out) | undefined (offline)

await auth.startEmailVerification("sam@example.com");
await auth.finishEmailVerification("sam@example.com", "123456");

// On a new device, after losing the old one:
await auth.startRecovery("sam@example.com");
await auth.finishRecovery("sam@example.com", "123456");
await auth.addPasskey();             // recovery revoked the old passkeys

await auth.deleteAccount();          // may prompt for the passkey first (step-up)
```

Every call either returns what it promised or throws an `AuthError` with a
message fit to show the user. `authErrorMessage(e, fallback)` returns `null`
when the user simply dismissed the passkey prompt.

## Options

`createAuth(options)`. Only `store` and `rpName` are required.

| Option | Default | |
|---|---|---|
| `store` | | the Durable Object namespace |
| `rpName` | | shown in the passkey prompt |
| `basePath` | `"/auth"` | routes live at `<basePath>/<action>` |
| `cookieName` | `"session"` | `__Host-` is added over HTTPS |
| `rpID` | request hostname | set it to share passkeys across subdomains |
| `origins` | request origin | allowed for passkeys and for POSTs |
| `parseProfile` | any object ≤ 4 KB | validate your own account data; throw `AuthInputError` to refuse |
| `allowSignup` | everyone | `(req, { name }) => boolean`: invite codes, a waitlist, a domain |
| `sendCode` | off | `(to, code, purpose) => Promise<void>`; `cloudflareEmail(...)` is one |
| `codeSecret` | | required with `sendCode`: a Worker secret of 32+ characters that codes are hashed under |
| `turnstile` | off | `{ siteKey, verify: turnstileVerifier(secret, { hostnames, checkAction }) }`; `verify` gets the form, `"signup"` or `"recover"` |
| `rateLimit` | off | `(key) => Promise<boolean>`; `rateLimitBinding(...)` is one |
| `onDeleteAccount` | | remove your app's data for the user before the account goes |
| `waitUntil` | | pass it, or recovery answers before sending and leaks timing |
| `reauthWindowMs` | 5 min | how recent "recent" is for step-up |

## Routes

All JSON. POSTs must come from an allowed origin.

| | Route | |
|---|---|---|
| | `GET config` | `{ email, turnstileSiteKey }` |
| | `GET session` | the signed-in account |
| | `POST register-options` → `register-verify` | create an account |
| | `POST login-options` → `login-verify` | sign in |
| | `POST reauth-options` → `reauth-verify` | step-up |
| | `GET passkeys` | the account's passkeys, without key material |
| 🔒 | `POST passkey-options` → `passkey-verify` | add a passkey |
| 🔒 | `POST passkey-delete` | remove one, never the last; signs out every other device |
| | `POST recover-start` → `recover-verify` | recovery by email |
| 🔒 | `POST email-start` → `email-verify` | set the recovery email |
| | `PUT profile` | name, and a partial profile update |
| | `POST logout`, `POST logout-others` | sign out here, or everywhere else |
| 🔒 | `POST delete-account` | |

🔒 = step-up. A stale session gets `403 { reauth: true }`; the client confirms
with a passkey and retries.

## Security model

What it defends against, and how:

- **Stolen database.** The database holds only hashes of session tokens and codes, plus
  passkey *public* keys. None of these is a credential.
- **Phishing.** Passkeys are bound to your domain by the browser. There's no
  password to type into the wrong site.
- **A stolen cookie or an unlocked, borrowed phone.** That's a session, not the
  person: step-up stops it from deleting the account, taking over the recovery
  email, or adding its own passkey.
- **A stolen phone.** Recover by email on another device. Every session is signed out and
  every passkey revoked, including the one on the stolen phone.
- **A lost device that's still signed in.** Remove its passkey from another
  device: every session but that one is signed out with it.
- **Guessing codes.** Five guesses a code, ten a day per email and a thousand a
  day across every email: about one chance in a thousand a day of any account
  falling to guessing, at the attacker's full effort. Codes are
  rejection-sampled and uniform, and stored as an HMAC under `codeSecret`, so
  a copy of the database alone can't be used to try them offline.
- **Learning who has an account.** Recovery and email verification answer the
  same way, at the same speed, whether or not the email is registered — and
  their hourly caps count the same either way, so the caps can't be used to
  tell either.
- **CSRF.** `SameSite=Lax` keeps the cookie off cross-site POSTs, and every
  POST must carry an allowed `Origin` (or `Sec-Fetch-Site: same-origin`).
  `sameOrigin(req)` is exported, to apply the same rule to your own routes.
- **Bots signing up.** Per-IP rate limits (an IPv6 client counts as its /64),
  optional Turnstile, and `allowSignup`.

What it doesn't do:

- **No organisations, roles or invitations.** It knows accounts, not tenants.
  Keep those in your app, keyed by account id, and use `allowSignup` for
  invites.
- **No OAuth or social login, and no passwords.** That's deliberate.
- **The email account is the recovery factor.** Whoever controls the inbox can
  recover the account. Leave `sendCode` out, and recovery means a second passkey on
  another device (or a synced one).
- **Recovery can be paused by a stranger.** The guess caps that make codes
  safe can be spent by someone else: ten wrong recovery guesses lock one
  email's recovery for a day, and a flood of them locks everyone's. Rate
  limits and Turnstile keep that expensive; it's the trade for codes that
  can't be brute-forced.
- **Sessions in use don't expire.** A session slides a year from its last
  use; there's no absolute lifetime. Step-up guards what matters, and
  `logout-others` or removing a passkey ends the rest.
- **The profile is the user's to write.** Anything a user mustn't set on
  themselves — a plan, a role — belongs in your own storage, or gets refused
  in `parseProfile`.
- **One Durable Object serves every account.** Sign-in is rare, but
  `auth.session(req)` is a round trip to it. That's plenty for thousands of
  active users. Past that, cache the session in your Worker for a few seconds.

Found a hole? See [SECURITY.md](SECURITY.md).

## Related

durable-auth is one of three open-source pieces that fit together:

- **[Rampset](https://isaacrowntree.github.io/rampset/)** — the offline-first
  barbell app it was extracted from, running it in production.
  [Try it](https://liftlog.zackdesign.biz).
- **[durable-sync](https://isaacrowntree.com/durable-sync/)** — offline-first
  sync in a Durable Object per user. Key its journal by the account id
  `auth.session(req)` returns.

## Run the example

```bash
npm install
npm run example    # → http://localhost:8790
```

[`examples/basic`](examples/basic) is a complete app: a 50-line Worker and a
one-page script. Sent emails land in `.wrangler/tmp/email/`.

## Tests

```bash
npm test                  # unit: the store on node:sqlite, every route
npm run test:integration  # the Durable Object on workerd's own SQLite
npm run test:e2e          # the example app in Chromium, real WebAuthn
```

The end-to-end suite uses Chrome's virtual authenticator, so the passkey
cryptography is real, not mocked. It signs up, signs in, recovers a lost
device by email (and checks the lost device is locked out), and confirms a
stale session with a passkey before deleting an account. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
