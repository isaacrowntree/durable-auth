# Contributing

## Tests

Three suites. The first is the one you run constantly.

```bash
npm test                  # unit — the store on node:sqlite, and every route
npm run test:integration  # the Durable Object on workerd's own SQLite
npm run test:e2e          # the example app in Chromium with real WebAuthn
```

**Unit** (`src/**/*.test.ts`) is instant. The store runs on Node's built-in
`node:sqlite`; the routes run against it with the passkey cryptography stubbed,
so what's under test is everything around the signature check: challenges,
step-up, codes, sessions and who may do what.

**Integration** (`test/integration/`) boots `workerd` through
[`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/)
and drives the routes into the real Durable Object. It catches what
`node:sqlite` can't: DO SQLite's BLOBs and NULL bindings, the schema
migrations' ALTERs, and the structured clone on every RPC.

**End-to-end** (`e2e/`) runs [`examples/basic`](examples/basic) under
`wrangler dev` and drives it in Chromium. Each "device" gets its own virtual
authenticator over the Chrome DevTools Protocol, so registration and
assertions are real WebAuthn, verified by the real library. Sent emails are
read from `.wrangler/tmp/email/`. The step-up window is shortened to three
seconds for this suite only.

Write the failing test first, and prefer the suite that would catch the bug
in production: a change to a route wants a journey, not just a unit test.

### Local setup gotcha

The pool pulls in `sharp` (via `wrangler`), whose prebuilt binaries may lag the
newest Node. If a first `npm install` fails building it, `npm install
--ignore-scripts` skips it.

## Schema changes

Append to `MIGRATIONS` in `src/server/store.ts`; never edit a shipped
statement. Every database ever created has to open in place — add a case to
the "schema version" tests in both the unit and integration suites.

## Publishing

`prepublishOnly` runs the unit suite and the build. Releases go out by tag;
see the top of `.github/workflows/publish.yml`.
