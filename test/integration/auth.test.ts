/** Sign-in against the real auth Durable Object.
 *
 * The unit suite runs these same handlers over AuthStore on node:sqlite. What
 * only this suite can catch is the seam between that and production: the
 * DO's own SQLite (BLOBs, NULL bindings, UNIQUE, ALTER), and the RPC every
 * call crosses — arguments and results structured-cloned on the way. */
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- response shapes vary per action
type Json = Record<string, any>;
const ORIGIN = "https://app.test";
const KEY = [1, 2, 3, 250, 0, 7];

async function call(action: string, body?: unknown, cookie?: string) {
  const res = await SELF.fetch(`${ORIGIN}/auth/${action}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, ...(cookie ? { cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: res.status,
    body: (await res.json()) as Json,
    cookie: res.headers.get("set-cookie")?.split(";")[0],
  };
}

const response = (id: string, challenge: string, publicKey = KEY) => ({
  id,
  publicKey,
  response: { clientDataJSON: btoa(JSON.stringify({ challenge })).replace(/=+$/, "") },
});

async function signUp(name: string, keyId: string) {
  const { body: options } = await call("register-options", { name });
  return call("register-verify", { name, profile: { unit: "kg" }, response: response(keyId, options.challenge) });
}

async function signIn(keyId: string, publicKey = KEY) {
  const { body: options } = await call("login-options", {});
  return call("login-verify", { response: response(keyId, options.challenge, publicKey) });
}

const fetchJson = async (path: string) => (await (await SELF.fetch(`${ORIGIN}${path}`)).json()) as Json;
const sentCodes = async () => (await fetchJson("/sent")) as unknown as { to: string; code: string }[];

describe("the auth Durable Object", () => {
  it("creates an account and keeps it signed in", async () => {
    const created = await signUp("Isaac", "k-create");
    expect(created.status).toBe(200);
    expect(created.body.account.profile).toEqual({ unit: "kg" });
    expect(created.cookie).toMatch(/^__Host-session=/);
    const me = await call("session", undefined, created.cookie);
    expect(me.body.account.id).toBe(created.body.account.id);
  });

  it("returns the stored public key byte-for-byte at sign-in", async () => {
    const created = await signUp("Isaac", "k-bytes");
    const ok = await signIn("k-bytes");
    expect(ok.status).toBe(200);
    expect(ok.body.account.id).toBe(created.body.account.id);
    // ...and a different key for the same credential id doesn't verify.
    expect((await signIn("k-bytes", [9, 9, 9])).status).toBe(400);
    const { body } = await call("passkeys", undefined, ok.cookie);
    expect(body.passkeys[0]).toMatchObject({ id: "k-bytes", deviceType: "multiDevice", backedUp: true });
    expect(body.passkeys[0].lastUsedAt).toEqual(expect.any(Number));
  });

  it("holds an email to one account, and recovers it with the emailed code", async () => {
    const a = await signUp("A", "k-a");
    const b = await signUp("B", "k-b");
    await call("email-start", { email: "a@example.com" }, a.cookie);
    const [{ code }] = (await sentCodes()) as [{ code: string }];
    expect((await call("email-verify", { email: "a@example.com", code }, a.cookie)).status).toBe(200);
    // Someone else's email: the same answer as success, and no email sent —
    // the UNIQUE constraint holds without telling B whose it is.
    expect((await call("email-start", { email: "A@example.com" }, b.cookie)).status).toBe(200);
    expect(await sentCodes()).toEqual([]);

    await call("recover-start", { email: "a@example.com" });
    const [recovery] = (await sentCodes()) as [{ code: string }];
    const back = await call("recover-verify", { email: "a@example.com", code: recovery.code });
    expect(back.body.account.id).toBe(a.body.account.id);
    // Recovery signs every other session out (NULL-safe `IS NOT ?` on DO SQLite)
    // and takes the lost device's passkey away.
    expect((await call("session", undefined, a.cookie)).status).toBe(401);
    expect((await call("session", undefined, back.cookie)).status).toBe(200);
    expect((await signIn("k-a")).status).toBe(400);
  });

  it("asks a stale session to confirm with its passkey before deleting the account", async () => {
    const created = await signUp("Gone", "k-gone");
    await SELF.fetch(`${ORIGIN}/later`);
    expect(await call("delete-account", {}, created.cookie)).toMatchObject({ status: 403, body: { reauth: true } });

    const { body: options } = await call("reauth-options", {}, created.cookie);
    expect((await call("reauth-verify", { response: response("k-gone", options.challenge) }, created.cookie)).status).toBe(200);
    expect((await call("delete-account", {}, created.cookie)).status).toBe(200);
    expect(await fetchJson("/deleted")).toEqual([created.body.account.id]);
    expect((await signIn("k-gone")).status).toBe(400);
  });

  it("opens a schema-version-1 database in place", async () => {
    expect(await fetchJson("/legacy")).toEqual({
      account: { id: "u1", name: "Old", email: null, profile: {} },
      key: [1, 2, 3],
      session: { userId: "u1", verifiedAt: 0 },
      passkeys: [{ id: "k1", createdAt: 0, lastUsedAt: null, deviceType: null, backedUp: null }],
    });
  });
});
