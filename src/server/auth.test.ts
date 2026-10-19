import { describe, it, expect, beforeEach, vi } from "vitest";
import { memorySql } from "../../test/sqlite";
import { AuthInputError, createAuth, type Auth, type AuthOptions, type WebAuthn } from "./auth";
import { AuthStore } from "./store";
import { asyncStore } from "./stub";
import { base64url, hashCode, sha256 } from "./crypto";

const ORIGIN = "https://app.test";
const PROFILE = { unit: "kg", plan: "5x5" };
const MINUTE = 60 * 1000;

/** WebAuthn with the cryptography stubbed out: options carry a fresh
 * challenge, and a "response" verifies when it names a credential. What's
 * under test is everything around the signature check. */
function fakeWebAuthn(): WebAuthn {
  let n = 0;
  return {
    generateRegistrationOptions: (async () => ({ challenge: `reg-${++n}` })) as never,
    generateAuthenticationOptions: (async (o: unknown) => ({ challenge: `auth-${++n}`, ...(o as object) })) as never,
    verifyRegistrationResponse: (async ({ response }: { response: { id: string } }) => ({
      verified: true,
      registrationInfo: {
        credential: { id: response.id, publicKey: new Uint8Array([7]), counter: 0 },
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
      },
    })) as never,
    verifyAuthenticationResponse: (async () => ({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    })) as never,
  };
}

function passkeyResponse(id: string, challenge: string) {
  const clientDataJSON = base64url(new TextEncoder().encode(JSON.stringify({ challenge })));
  return { id, rawId: id, type: "public-key", response: { clientDataJSON }, clientExtensionResults: {} };
}

let t: number;
let options: AuthOptions;
let auth: Auth;
let sent: { to: string; code: string; purpose: string }[];
/** The store under the routes, for states no route sequence can reach. */
let raw: AuthStore;

/** Apply option changes made inside a test. */
const rebuild = () => (auth = createAuth(options));

beforeEach(() => {
  t = 1_000;
  sent = [];
  raw = new AuthStore(memorySql());
  options = {
    store: asyncStore(raw),
    rpName: "Test",
    basePath: "/api/auth",
    now: () => t,
    webauthn: fakeWebAuthn(),
    sendCode: async (to, code, purpose) => void sent.push({ to, code, purpose }),
    onDeleteAccount: vi.fn(async () => {}),
  };
  rebuild();
});

async function call(action: string, init: { method?: string; body?: unknown; cookie?: string; origin?: string } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (init.cookie) headers.cookie = init.cookie;
  const method = init.method ?? (init.body === undefined ? "GET" : "POST");
  if (method !== "GET") headers.origin = init.origin ?? ORIGIN;
  const res = (await auth.handle(
    new Request(`${ORIGIN}/api/auth/${action}`, {
      method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    }),
  ))!;
  const setCookie = res.headers.get("set-cookie");
  return {
    status: res.status,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- response shapes vary per action
    body: (await res.json()) as Record<string, any>,
    cookie: setCookie ? setCookie.split(";")[0] : undefined,
  };
}

async function signUp(name = "Isaac", keyId = "key-1", profile: unknown = PROFILE) {
  const options = await call("register-options", { body: { name } });
  const res = await call("register-verify", {
    body: { name, profile, response: passkeyResponse(keyId, options.body.challenge) },
  });
  return res;
}

describe("creating an account", () => {
  it("signs the new account straight in", async () => {
    const res = await signUp();
    expect(res.status).toBe(200);
    expect(res.body.account).toMatchObject({ name: "Isaac", email: null, profile: PROFILE });
    expect(res.cookie).toMatch(/^__Host-session=/);

    const me = await call("session", { cookie: res.cookie });
    expect(me.body.account.id).toBe(res.body.account.id);
    // The same cookie again, so the browser's expiry slides with use.
    expect(me.cookie).toBe(res.cookie);
  });

  it("won't verify against a challenge it never issued", async () => {
    const res = await call("register-verify", {
      body: { name: "Isaac", profile: PROFILE, response: passkeyResponse("k", "made-up") },
    });
    expect(res.status).toBe(400);
  });

  // The challenge carries the account id it's minting, so replaying one
  // registration can't mint the same account twice.
  it("won't redeem the same challenge twice", async () => {
    const options = await call("register-options", { body: { name: "Isaac" } });
    const body = { name: "Isaac", profile: PROFILE, response: passkeyResponse("k1", options.body.challenge) };
    expect((await call("register-verify", { body })).status).toBe(200);
    expect((await call("register-verify", { body })).status).toBe(400);
  });

  it("needs Turnstile when the server has it", async () => {
    const verify = vi.fn(async (token: string) => token === "human");
    options.turnstile = { siteKey: "site", verify };
    rebuild();
    expect((await call("register-options", { body: { name: "Bot" } })).status).toBe(400);
    expect((await call("register-options", { body: { name: "Bot", turnstileToken: "robot" } })).status).toBe(400);
    expect((await call("register-options", { body: { name: "Isaac", turnstileToken: "human" } })).status).toBe(200);
    // No token, no round trip to Cloudflare.
    expect(verify.mock.calls.map(([token]) => token)).toEqual(["robot", "human"]);
    expect((await call("config")).body.turnstileSiteKey).toBe("site");
  });
});

describe("signing in with a passkey", () => {
  it("finds the account from the passkey alone", async () => {
    const created = await signUp("Isaac", "key-1");
    const options = await call("login-options", { body: {} });
    const res = await call("login-verify", { body: { response: passkeyResponse("key-1", options.body.challenge) } });
    expect(res.status).toBe(200);
    expect(res.body.account.id).toBe(created.body.account.id);
    expect(res.cookie).not.toBe(created.cookie);
  });

  it("refuses a passkey no account uses", async () => {
    const options = await call("login-options", { body: {} });
    const res = await call("login-verify", { body: { response: passkeyResponse("stranger", options.body.challenge) } });
    expect(res.status).toBe(400);
  });
});

describe("sessions", () => {
  it("are 401 without a cookie", async () => {
    expect((await call("session")).status).toBe(401);
  });

  it("end on logout", async () => {
    const { cookie } = await signUp();
    const out = await call("logout", { body: {}, cookie });
    expect(out.cookie).toMatch(/=$/);
    expect((await call("session", { cookie })).status).toBe(401);
  });

  it("refuse a state change posted from another origin", async () => {
    const { cookie } = await signUp();
    const res = await call("logout", { body: {}, cookie, origin: "https://evil.test" });
    expect(res.status).toBe(403);
    expect((await call("session", { cookie })).status).toBe(200);
  });
});

describe("recovery email", () => {
  async function withEmail(email = "isaac@example.com") {
    const created = await signUp();
    await call("email-start", { body: { email }, cookie: created.cookie });
    const { code } = sent.pop()!;
    const verified = await call("email-verify", { body: { email, code }, cookie: created.cookie });
    return { ...created, verified };
  }

  it("is attached once the emailed code comes back", async () => {
    const { verified } = await withEmail();
    expect(verified.body.account.email).toBe("isaac@example.com");
  });

  // Open sign-up makes "is this email taken?" a question anyone could ask.
  // Starting looks the same either way, and nothing reaches the owner's
  // inbox; only proving you hold the email (the code) can claim it.
  it("can't be another account's email — without saying whose it is", async () => {
    await withEmail("shared@example.com");
    const other = await signUp("Sam", "key-2");
    const res = await call("email-start", { body: { email: "shared@example.com" }, cookie: other.cookie });
    expect(res.status).toBe(200);
    expect(sent).toHaveLength(0);
  });

  it("isn't offered when the server can't send email", async () => {
    options.sendCode = undefined;
    rebuild();
    const { cookie } = await signUp();
    expect((await call("config")).body.email).toBe(false);
    expect((await call("email-start", { body: { email: "a@example.com" }, cookie })).status).toBe(404);
  });
});

describe("recovering an account", () => {
  async function accountWithEmail() {
    const created = await signUp();
    await call("email-start", { body: { email: "isaac@example.com" }, cookie: created.cookie });
    const { code } = sent.pop()!;
    await call("email-verify", { body: { email: "isaac@example.com", code }, cookie: created.cookie });
    return created;
  }

  // The lost phone may be in a thief's hands, still holding the passkey.
  // Recovery has to take that key away too, not just its session.
  it("revokes the lost phone's passkey, so it can't sign straight back in", async () => {
    await accountWithEmail();
    await call("recover-start", { body: { email: "isaac@example.com" } });
    const { code } = sent.pop()!;
    await call("recover-verify", { body: { email: "isaac@example.com", code } });

    const options = await call("login-options", { body: {} });
    const res = await call("login-verify", { body: { response: passkeyResponse("key-1", options.body.challenge) } });
    expect(res.status).toBe(400);
  });

  // An account that exists costs an email send; one that doesn't, nothing.
  // Timing alone would tell a stranger which is which — so the send happens
  // after the answer.
  it("answers before the email goes out", async () => {
    await accountWithEmail();
    const pending: Promise<unknown>[] = [];
    options.waitUntil = (p) => void pending.push(p);
    rebuild();
    expect((await call("recover-start", { body: { email: "isaac@example.com" } })).status).toBe(200);
    expect(sent).toHaveLength(0);
    await Promise.all(pending);
    expect(sent).toHaveLength(1);
  });

  it("signs in with the emailed code — and signs the lost device out", async () => {
    const lost = await accountWithEmail();
    expect((await call("recover-start", { body: { email: "Isaac@Example.com" } })).status).toBe(200);
    const { code } = sent.pop()!;

    const res = await call("recover-verify", { body: { email: "isaac@example.com", code } });
    expect(res.status).toBe(200);
    expect(res.body.account.id).toBe(lost.body.account.id);
    expect((await call("session", { cookie: res.cookie })).status).toBe(200);
    expect((await call("session", { cookie: lost.cookie })).status).toBe(401);
  });

  // Same answer either way, and no email: a stranger can't use this to learn
  // who has an account.
  it("answers the same for an email with no account", async () => {
    const res = await call("recover-start", { body: { email: "nobody@example.com" } });
    expect(res.status).toBe(200);
    expect(sent).toHaveLength(0);
  });

  // Past the hourly cap the answer can't change either — only the inbox
  // stops filling.
  it("answers the same past the hourly cap, and sends nothing more", async () => {
    await accountWithEmail();
    sent = [];
    for (let i = 0; i < 6; i++) {
      expect((await call("recover-start", { body: { email: "isaac@example.com" } })).status).toBe(200);
    }
    expect(sent).toHaveLength(4); // the verify-email code was the hour's first
  });

  it("refuses a wrong code", async () => {
    await accountWithEmail();
    await call("recover-start", { body: { email: "isaac@example.com" } });
    const { code } = sent.pop()!;
    const wrong = code === "000000" ? "111111" : "000000";
    expect((await call("recover-verify", { body: { email: "isaac@example.com", code: wrong } })).status).toBe(400);
  });

  it("lets the recovered account add a passkey for this device", async () => {
    await accountWithEmail();
    await call("recover-start", { body: { email: "isaac@example.com" } });
    const { code } = sent.pop()!;
    const { cookie } = await call("recover-verify", { body: { email: "isaac@example.com", code } });

    const options = await call("passkey-options", { body: {}, cookie });
    const added = await call("passkey-verify", { body: { response: passkeyResponse("key-new", options.body.challenge) }, cookie });
    expect(added.status).toBe(200);

    const login = await call("login-options", { body: {} });
    const res = await call("login-verify", { body: { response: passkeyResponse("key-new", login.body.challenge) } });
    expect(res.status).toBe(200);
  });
});

describe("the profile", () => {
  // A device changes one thing at a time; the rest of the stored profile
  // must survive it.
  it("takes a partial update and keeps the rest", async () => {
    const { cookie } = await signUp();
    const res = await call("profile", { method: "PUT", body: { profile: { theme: "light" } }, cookie });
    expect(res.body.account.profile).toEqual({ unit: "kg", plan: "5x5", theme: "light" });
  });

  it("is the app's to validate, on sign-up and on every change", async () => {
    options.parseProfile = (input) => {
      const p = input as { plan?: unknown };
      if (p?.plan !== "5x5") throw new AuthInputError("Unknown plan");
      return { plan: p.plan };
    };
    rebuild();
    const options_ = await call("register-options", { body: { name: "Isaac" } });
    const refused = await call("register-verify", {
      body: { name: "Isaac", profile: { plan: "nope" }, response: passkeyResponse("k", options_.body.challenge) },
    });
    expect(refused).toMatchObject({ status: 400, body: { error: "Unknown plan" } });

    const { cookie, body } = await signUp();
    expect(body.account.profile).toEqual({ plan: "5x5" });
    expect((await call("profile", { method: "PUT", body: { profile: { plan: "x" } }, cookie })).status).toBe(400);
  });

  it("refuses anything but a small object by default", async () => {
    const { cookie } = await signUp();
    const big = { blob: "x".repeat(5000) };
    expect((await call("profile", { method: "PUT", body: { profile: big }, cookie })).status).toBe(400);
  });
});

describe("deleting an account", () => {
  // Another phone pushing mid-delete must not recreate what's being erased.
  it("signs every device out before removing the data", async () => {
    const { cookie } = await signUp();
    let sessionDuringDelete = 0;
    options.onDeleteAccount = async () => {
      sessionDuringDelete = (await call("session", { cookie })).status;
    };
    rebuild();
    await call("delete-account", { body: {}, cookie });
    expect(sessionDuringDelete).toBe(401);
  });

  it("removes its data, then the account", async () => {
    const { cookie, body } = await signUp();
    const res = await call("delete-account", { body: {}, cookie });
    expect(res.status).toBe(200);
    expect(res.cookie).toBe("__Host-session=");
    expect(options.onDeleteAccount).toHaveBeenCalledWith(body.account.id);
    expect((await call("session", { cookie })).status).toBe(401);
  });
});

describe("registering a passkey that's already in use", () => {
  it("fails without leaving an account behind", async () => {
    await signUp("Isaac", "key-1");
    const options = await call("register-options", { body: { name: "Copycat" } });
    const res = await call("register-verify", {
      body: { name: "Copycat", profile: PROFILE, response: passkeyResponse("key-1", options.body.challenge) },
    });
    expect(res.status).toBe(400);
    // The one account still signs in with it.
    const login = await call("login-options", { body: {} });
    expect((await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } })).body.account.name).toBe("Isaac");
  });
});

describe("rate limits", () => {
  it("turn away a client over its limit", async () => {
    options.rateLimit = async () => false;
    rebuild();
    expect((await call("login-options", { body: {} })).status).toBe(429);
  });

  // One bucket per kind of route and per client, so a flood of sign-ins
  // can't use up anyone's recovery attempts.
  it("count each client in its own bucket per kind of route", async () => {
    const keys: string[] = [];
    options.rateLimit = async (key) => (keys.push(key), true);
    rebuild();
    const at = (ip?: string) =>
      auth.handle(
        new Request(`${ORIGIN}/api/auth/login-options`, {
          method: "POST",
          headers: { origin: ORIGIN, ...(ip ? { "cf-connecting-ip": ip } : {}) },
          body: "{}",
        }),
      );
    expect((await at("203.0.113.7"))!.status).toBe(200);
    expect((await at())!.status).toBe(200);
    expect(keys).toEqual(["login:203.0.113.7", "login:unknown"]);

    keys.length = 0;
    const { cookie } = await signUp(); // register ×2
    const login = await call("login-options", { body: {} }); // login
    await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } }); // login
    t += 6 * MINUTE;
    const reauth = await call("reauth-options", { body: {}, cookie }); // login
    await call("reauth-verify", { body: { response: passkeyResponse("key-1", reauth.body.challenge) }, cookie }); // login
    await call("email-start", { body: { email: "i@example.com" }, cookie }); // email
    await call("email-verify", { body: { email: "i@example.com", code: sent.pop()!.code }, cookie }); // email
    await call("recover-start", { body: { email: "i@example.com" } }); // email
    await call("recover-verify", { body: { email: "i@example.com", code: sent.pop()!.code } }); // email
    expect(keys.map((k) => k.split(":")[0])).toEqual(["register", "register", ...Array(4).fill("login"), ...Array(4).fill("email")]);
  });
});

describe("step-up before sensitive actions", () => {
  const stale = () => (t += 6 * MINUTE);

  async function confirm(cookie: string, keyId = "key-1") {
    const options_ = await call("reauth-options", { body: {}, cookie });
    return call("reauth-verify", { body: { response: passkeyResponse(keyId, options_.body.challenge) }, cookie });
  }

  // A borrowed unlocked phone, or a stolen cookie, is a session — not the
  // person. Deleting everything should need the person.
  it("asks a session that hasn't used its passkey lately to confirm before deleting the account", async () => {
    const { cookie } = await signUp();
    stale();
    const refused = await call("delete-account", { body: {}, cookie });
    expect(refused).toMatchObject({ status: 403, body: { reauth: true } });
    expect(options.onDeleteAccount).not.toHaveBeenCalled();

    expect((await confirm(cookie!)).status).toBe(200);
    expect((await call("delete-account", { body: {}, cookie })).status).toBe(200);
  });

  it("offers only the account's own passkeys, and won't take another's", async () => {
    const mine = await signUp("Isaac", "key-1");
    await signUp("Sam", "key-2");
    stale();
    const options_ = await call("reauth-options", { body: {}, cookie: mine.cookie });
    expect(options_.body.allowCredentials).toEqual([{ id: "key-1", transports: undefined }]);
    const wrong = await call("reauth-verify", {
      body: { response: passkeyResponse("key-2", options_.body.challenge) },
      cookie: mine.cookie,
    });
    expect(wrong.status).toBe(400);
    expect((await call("delete-account", { body: {}, cookie: mine.cookie })).status).toBe(403);
  });

  // Whoever controls the recovery email controls the account.
  it("guards changing the recovery email", async () => {
    const { cookie } = await signUp();
    stale();
    expect((await call("email-start", { body: { email: "new@example.com" }, cookie })).status).toBe(403);
    expect(sent).toHaveLength(0);
    await confirm(cookie!);
    expect((await call("email-start", { body: { email: "new@example.com" }, cookie })).status).toBe(200);
  });

  it("guards adding a passkey once the account has one", async () => {
    const { cookie } = await signUp();
    stale();
    expect(await call("passkey-options", { body: {}, cookie })).toMatchObject({ status: 403, body: { reauth: true } });
  });

  it("guards removing a passkey", async () => {
    const { cookie } = await signUp("Isaac", "key-1");
    const options_ = await call("passkey-options", { body: {}, cookie });
    await call("passkey-verify", { body: { response: passkeyResponse("key-2", options_.body.challenge) }, cookie });
    stale();
    expect(await call("passkey-delete", { body: { id: "key-1" }, cookie })).toMatchObject({ status: 403, body: { reauth: true } });
    expect(raw.passkey("key-1")).not.toBeNull();
    await confirm(cookie!);
    expect((await call("passkey-delete", { body: { id: "key-1" }, cookie })).status).toBe(200);
  });

  // The documented five minutes, to the millisecond: on the edge is still
  // fresh, one past it isn't.
  it("trusts a passkey for five minutes by default", async () => {
    const { cookie } = await signUp();
    t += 5 * MINUTE;
    expect((await call("email-start", { body: { email: "a@example.com" }, cookie })).status).toBe(200);
    t += 1;
    expect(await call("email-start", { body: { email: "a@example.com" }, cookie })).toMatchObject({ status: 403, body: { reauth: true } });
  });

  // Just recovered by email, with every passkey revoked: the recovery
  // session has the step-up window to add one — and a cookie stolen later
  // can't use the empty account to plant its own.
  it("lets a just-recovered account add a passkey, but not a stale one", async () => {
    const { cookie } = await signUp();
    await call("email-start", { body: { email: "i@example.com" }, cookie });
    await call("email-verify", { body: { email: "i@example.com", code: sent.pop()!.code }, cookie });
    await call("recover-start", { body: { email: "i@example.com" } });
    const recovered = await call("recover-verify", { body: { email: "i@example.com", code: sent.pop()!.code } });
    expect((await call("passkey-options", { body: {}, cookie: recovered.cookie })).status).toBe(200);

    // The window runs from the recovery, to the millisecond.
    t += 5 * MINUTE;
    expect((await call("passkey-options", { body: {}, cookie: recovered.cookie })).status).toBe(200);
    t += 1;
    // No passkey to confirm with, so not "confirm it's you": recover again.
    const refused = await call("passkey-options", { body: {}, cookie: recovered.cookie });
    expect(refused).toMatchObject({ status: 403, body: { error: "Recover your account by email again to add a passkey" } });
    expect(refused.body.reauth).toBeUndefined();
    expect(await call("reauth-options", { body: {}, cookie: recovered.cookie })).toMatchObject({
      status: 409,
      body: { needsPasskey: true },
    });
  });
});

describe("telling who has an account", () => {
  // Adding someone else's email must look exactly like adding a free one —
  // down to when the hourly cap kicks in.
  it("can't be done by asking to add an email that's taken", async () => {
    const owner = await signUp("Owner", "key-o");
    await call("email-start", { body: { email: "taken@example.com" }, cookie: owner.cookie });
    await call("email-verify", { body: { email: "taken@example.com", code: sent.pop()!.code }, cookie: owner.cookie });
    t += 61 * MINUTE; // a fresh hour for the cap
    const prober = await signUp("Prober", "key-p");
    const statuses = async (email: string) => {
      const out = [];
      for (let i = 0; i < 6; i++) out.push((await call("email-start", { body: { email }, cookie: prober.cookie })).status);
      return out;
    };
    expect(await statuses("taken@example.com")).toEqual(await statuses("free@example.com"));
  });
});

describe("sign-up", () => {
  // allowSignup and Turnstile approved a name; the verify step can't swap it.
  it("keeps the name it was approved under", async () => {
    options.allowSignup = (_req, { name }) => name === "Invited";
    rebuild();
    const options_ = await call("register-options", { body: { name: "Invited" } });
    const res = await call("register-verify", {
      body: { name: "Somebody else", profile: PROFILE, response: passkeyResponse("k", options_.body.challenge) },
    });
    expect(res.body.account.name).toBe("Invited");
  });

  it("hands allowSignup the request's body, for an invite code", async () => {
    options.allowSignup = (_req, { body }) => body.invite === "let-me-in";
    rebuild();
    expect((await call("register-options", { body: { name: "A" } })).status).toBe(403);
    expect((await call("register-options", { body: { name: "A", invite: "let-me-in" } })).status).toBe(200);
  });
});

describe("managing passkeys", () => {
  async function twoKeys() {
    const { cookie } = await signUp("Isaac", "key-1");
    const options_ = await call("passkey-options", { body: {}, cookie });
    await call("passkey-verify", { body: { response: passkeyResponse("key-2", options_.body.challenge) }, cookie });
    return cookie!;
  }

  it("lists them without their keys", async () => {
    const cookie = await twoKeys();
    const { body } = await call("passkeys", { cookie });
    expect(body.passkeys.map((k: { id: string }) => k.id)).toEqual(["key-1", "key-2"]);
    expect(body.passkeys[0]).toEqual({ id: "key-1", createdAt: 1000, lastUsedAt: null, deviceType: "multiDevice", backedUp: true });
  });

  it("removes one, but never the last", async () => {
    const cookie = await twoKeys();
    expect((await call("passkey-delete", { body: { id: "key-1" }, cookie })).status).toBe(200);
    expect((await call("passkey-delete", { body: { id: "key-2" }, cookie })).status).toBe(409);
    const login = await call("login-options", { body: {} });
    expect((await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } })).status).toBe(400);
  });

  it("won't touch another account's passkey", async () => {
    const cookie = await twoKeys();
    await signUp("Sam", "key-sam");
    expect((await call("passkey-delete", { body: { id: "key-sam" }, cookie })).status).toBe(404);
  });

  it("records when a passkey signs in", async () => {
    const { cookie } = await signUp();
    t = 5_000;
    const login = await call("login-options", { body: {} });
    await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
    expect((await call("passkeys", { cookie })).body.passkeys[0].lastUsedAt).toBe(5_000);
  });
});

describe("signing out other devices", () => {
  it("keeps this one", async () => {
    const here = await signUp();
    const login = await call("login-options", { body: {} });
    const there = await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
    expect((await call("logout-others", { body: {}, cookie: here.cookie })).status).toBe(200);
    expect((await call("session", { cookie: here.cookie })).status).toBe(200);
    expect((await call("session", { cookie: there.cookie })).status).toBe(401);
  });
});

describe("who may sign up", () => {
  it("is the app's call", async () => {
    options.allowSignup = (_req, { name }) => name === "Invited";
    rebuild();
    expect((await call("register-options", { body: { name: "Stranger" } })).status).toBe(403);
    expect((await call("register-options", { body: { name: "Invited" } })).status).toBe(200);
  });
});

describe("routing and origins", () => {
  it("leaves paths outside basePath to the app", async () => {
    expect(await auth.handle(new Request(`${ORIGIN}/api/other`))).toBeNull();
    expect(await auth.handle(new Request(`${ORIGIN}/api/authx/session`))).toBeNull();
  });

  it("accepts posts from the origins it's told about", async () => {
    options.origins = [ORIGIN, "https://admin.app.test"];
    rebuild();
    expect((await call("login-options", { body: {}, origin: "https://admin.app.test" })).status).toBe(200);
    expect((await call("login-options", { body: {}, origin: "https://evil.test" })).status).toBe(403);
  });

  it("refuses a post with no Origin unless fetch metadata says same-origin", async () => {
    const post = (headers: Record<string, string>) =>
      auth.handle(new Request(`${ORIGIN}/api/auth/login-options`, { method: "POST", headers, body: "{}" }));
    expect((await post({}))!.status).toBe(403);
    expect((await post({ "sec-fetch-site": "cross-site" }))!.status).toBe(403);
    expect((await post({ "sec-fetch-site": "same-origin" }))!.status).toBe(200);
  });

  it("keeps __Host- and Secure on a plain-http host that isn't this machine", async () => {
    const res = (await auth.handle(
      new Request("http://app.test/api/auth/logout", { method: "POST", headers: { origin: "http://app.test" } }),
    ))!;
    expect(res.headers.get("set-cookie")).toMatch(/^__Host-session=; .*; Secure$/);
  });

  it("drops __Host- and Secure over plain http (localhost)", async () => {
    const res = (await auth.handle(
      new Request("http://localhost/api/auth/logout", { method: "POST", headers: { origin: "http://localhost" } }),
    ))!;
    expect(res.headers.get("set-cookie")).toMatch(/^session=; .*HttpOnly; SameSite=Lax; Max-Age=0$/);
  });

  it("tells the app who's signed in", async () => {
    const { cookie, body } = await signUp();
    const req = new Request(`${ORIGIN}/anything`, { headers: { cookie: cookie! } });
    expect((await auth.account(req))?.id).toBe(body.account.id);
    expect(await auth.account(new Request(`${ORIGIN}/anything`))).toBeNull();
  });
});

// ---- the refusals ------------------------------------------------------------

describe("malformed requests", () => {
  const post = (action: string, body: string) =>
    auth.handle(new Request(`${ORIGIN}/api/auth/${action}`, { method: "POST", headers: { origin: ORIGIN }, body }));

  it("are 400s with a message, not crashes", async () => {
    for (const body of ["not json", "42", "null"]) {
      const res = (await post("register-options", body))!;
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Expected a JSON body" });
    }
  });

  it("are 404 for an action that doesn't exist, or the wrong method", async () => {
    expect((await call("nope", { body: {} })).status).toBe(404);
    expect((await call("login-options")).status).toBe(404);
  });

  it("refuse a name that's missing, blank or too long", async () => {
    for (const name of [undefined, 42, "   ", "x".repeat(65)]) {
      expect(await call("register-options", { body: { name } })).toMatchObject({
        status: 400,
        body: { error: "Enter a name up to 64 characters" },
      });
    }
    expect((await call("register-options", { body: { name: "x".repeat(64) } })).status).toBe(200);
  });

  it("refuse an email that isn't one, or is longer than an address can be", async () => {
    for (const email of [undefined, 42, "no-at-sign", "a@b", "a b@example.com", "a@example.com x", `${"a".repeat(243)}@example.com`]) {
      expect(await call("recover-start", { body: { email } })).toMatchObject({ status: 400, body: { error: "Enter a valid email" } });
    }
    expect((await call("recover-start", { body: { email: `${"a".repeat(242)}@example.com` } })).status).toBe(200);
  });

  it("refuse a code that isn't six digits, but forgive spaces", async () => {
    for (const code of [undefined, 123456, "12345", "1234567", "12a456"]) {
      expect(await call("recover-verify", { body: { email: "a@example.com", code } })).toMatchObject({
        status: 400,
        body: { error: "Enter the 6-digit code" },
      });
    }
    expect((await call("recover-verify", { body: { email: "a@example.com", code: " 123 456 " } })).body.error).toBe(
      "That code is wrong or has expired",
    );
  });

  it("refuse a passkey response that's missing, or whose challenge can't be read", async () => {
    const { cookie } = await signUp();
    for (const action of ["register-verify", "login-verify", "reauth-verify", "passkey-verify"]) {
      expect(await call(action, { body: {}, cookie })).toMatchObject({ status: 400, body: { error: "Missing passkey response" } });
    }
    const unreadable = [
      { id: "k" },
      { id: "k", response: { clientDataJSON: "!!!" } },
      { id: "k", response: { clientDataJSON: base64url(new TextEncoder().encode("{}")) } },
      { id: "k", response: { clientDataJSON: base64url(new TextEncoder().encode('{"challenge":""}')) } },
      { id: "k", response: { clientDataJSON: base64url(new TextEncoder().encode('{"challenge":42}')) } },
    ];
    for (const response of unreadable) {
      expect(await call("login-verify", { body: { response } })).toMatchObject({
        status: 400,
        body: { error: "Malformed passkey response" },
      });
    }
  });

  it("refuse to delete a passkey without saying which", async () => {
    const { cookie } = await signUp();
    expect(await call("passkey-delete", { body: { id: 42 }, cookie })).toMatchObject({ status: 400, body: { error: "Which passkey?" } });
  });
});

describe("a passkey that doesn't verify", () => {
  // The library throws on some bad responses and returns verified: false on
  // others. Both are the user's 400, never the Worker's 500.
  it("creates no account, whether the library throws or says no", async () => {
    const registrationInfo = {
      credential: { id: "key-x", publicKey: new Uint8Array([7]), counter: 0 },
      credentialDeviceType: "multiDevice",
      credentialBackedUp: true,
    };
    for (const verifyRegistrationResponse of [
      async () => {
        throw new Error("bad attestation");
      },
      // "No" is the answer, whatever else comes back with it.
      async () => ({ verified: false, registrationInfo }),
      async () => ({ verified: true }),
    ]) {
      options.webauthn = { ...fakeWebAuthn(), verifyRegistrationResponse: verifyRegistrationResponse as never };
      rebuild();
      const res = await signUp("Isaac", "key-x");
      expect(res).toMatchObject({ status: 400, body: { error: "Passkey couldn't be verified" } });
      expect(res.cookie).toBeUndefined();
    }
    expect(raw.passkey("key-x")).toBeNull();
  });

  it("signs no one in, whether the library throws or says no", async () => {
    await signUp("Isaac", "key-1");
    for (const verifyAuthenticationResponse of [
      async () => {
        throw new Error("bad signature");
      },
      async () => ({ verified: false, authenticationInfo: { newCounter: 1 } }),
      async () => ({ verified: true }),
    ]) {
      options.webauthn = { ...fakeWebAuthn(), verifyAuthenticationResponse: verifyAuthenticationResponse as never };
      rebuild();
      const login = await call("login-options", { body: {} });
      const res = await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
      expect(res).toMatchObject({ status: 400, body: { error: "Passkey couldn't be verified" } });
      expect(res.cookie).toBeUndefined();
    }
    expect(raw.passkeySummaries(raw.passkey("key-1")!.userId)[0]!.lastUsedAt).toBeNull();
  });
});

describe("challenges at the routes", () => {
  it("sign no one in once they've expired", async () => {
    await signUp("Isaac", "key-1");
    const login = await call("login-options", { body: {} });
    t += 5 * MINUTE;
    const res = await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
    expect(res).toMatchObject({ status: 400, body: { error: "That sign-in expired — try again" } });
  });

  // Step-up and adding a passkey bind the challenge to the account that asked.
  // Another account holding it gets nothing from it.
  it("for step-up can't be used by another account", async () => {
    const isaac = await signUp("Isaac", "key-1");
    const sam = await signUp("Sam", "key-2");
    t += 6 * MINUTE;
    const options_ = await call("reauth-options", { body: {}, cookie: isaac.cookie });
    const res = await call("reauth-verify", { body: { response: passkeyResponse("key-2", options_.body.challenge) }, cookie: sam.cookie });
    expect(res).toMatchObject({ status: 400, body: { error: "That expired — try again" } });
    expect((await call("delete-account", { body: {}, cookie: sam.cookie })).status).toBe(403);
  });

  it("for adding a passkey can't be used by another account", async () => {
    const isaac = await signUp("Isaac", "key-1");
    const sam = await signUp("Sam", "key-2");
    const options_ = await call("passkey-options", { body: {}, cookie: isaac.cookie });
    const res = await call("passkey-verify", { body: { response: passkeyResponse("key-3", options_.body.challenge) }, cookie: sam.cookie });
    expect(res).toMatchObject({ status: 400, body: { error: "That expired — try again" } });
    expect(raw.passkey("key-3")).toBeNull();
  });

  // A sign-up started on the release before challenges carried the approved
  // name: it has none to create the account under, so it starts over.
  it("for sign-up without an approved name create nothing", async () => {
    raw.createChallenge("old-reg", "register", "u_old", t);
    const res = await call("register-verify", { body: { profile: PROFILE, response: passkeyResponse("k", "old-reg") } });
    expect(res).toMatchObject({ status: 400, body: { error: "That sign-up expired — try again" } });
    expect(raw.account("u_old")).toBeNull();
  });
});

describe("a code for someone else", () => {
  // The code proves the inbox for the account that asked, not for whoever
  // types it in.
  it("doesn't attach the email to the account that redeems it", async () => {
    const isaac = await signUp("Isaac", "key-1");
    const sam = await signUp("Sam", "key-2");
    await call("email-start", { body: { email: "isaac@example.com" }, cookie: isaac.cookie });
    const { code } = sent.pop()!;
    const res = await call("email-verify", { body: { email: "isaac@example.com", code }, cookie: sam.cookie });
    expect(res).toMatchObject({ status: 400, body: { error: "That code is wrong or has expired" } });
    expect(raw.account(sam.body.account.id)!.email).toBeNull();
  });

  // Routes alone hold one code per email, so this takes the store; it's the
  // UNIQUE check having the last word however the email got taken.
  it("can't take an email another account got first", async () => {
    const isaac = await signUp("Isaac", "key-1");
    const sam = await signUp("Sam", "key-2");
    await call("email-start", { body: { email: "x@example.com" }, cookie: isaac.cookie });
    const { code } = sent.pop()!;
    raw.setEmail(sam.body.account.id, "x@example.com");
    const res = await call("email-verify", { body: { email: "x@example.com", code }, cookie: isaac.cookie });
    expect(res).toMatchObject({ status: 409, body: { error: "That email is already used by another account" } });
    expect(raw.account(isaac.body.account.id)!.email).toBeNull();
  });
});

describe("whatever's left of a deleted account", () => {
  // Deleting an account removes its sessions, passkeys and codes together;
  // if a row ever outlived it, it must lead nowhere.
  it("a session signs into nothing", async () => {
    raw.createSession(await sha256("orphan"), "u_gone", t);
    const cookie = "__Host-session=orphan";
    expect((await call("session", { cookie })).status).toBe(401);
    expect((await call("passkey-options", { body: {}, cookie })).status).toBe(401);
    expect((await call("profile", { method: "PUT", body: { name: "Ghost" }, cookie })).status).toBe(401);
  });

  it("a passkey signs into nothing", async () => {
    raw.addPasskey({ id: "orphan-key", userId: "u_gone", publicKey: new Uint8Array([1]), counter: 0 }, t);
    const login = await call("login-options", { body: {} });
    const res = await call("login-verify", { body: { response: passkeyResponse("orphan-key", login.body.challenge) } });
    expect(res).toMatchObject({ status: 400, body: { error: "No account uses this passkey" } });
    expect(res.cookie).toBeUndefined();
  });

  it("a recovery code signs into nothing", async () => {
    raw.issueCode("gone@example.com", "recover", "u_gone", await hashCode("gone@example.com", "recover", "123456"), t);
    const res = await call("recover-verify", { body: { email: "gone@example.com", code: "123456" } });
    expect(res).toMatchObject({ status: 400, body: { error: "Account not found" } });
    expect(res.cookie).toBeUndefined();
  });
});

describe("email that goes out after the answer", () => {
  it("is sent after adding a recovery email answers", async () => {
    const pending: Promise<unknown>[] = [];
    options.waitUntil = (p) => void pending.push(p);
    rebuild();
    const { cookie } = await signUp();
    expect((await call("email-start", { body: { email: "i@example.com" }, cookie })).status).toBe(200);
    await Promise.all(pending);
    expect(sent.map((s) => s.to)).toEqual(["i@example.com"]);
  });

  // A failed send after the answer has no one to tell; it mustn't surface as
  // an unhandled rejection that takes the Worker's invocation down with it.
  it("swallows a failed send rather than rejecting", async () => {
    const pending: Promise<unknown>[] = [];
    options.waitUntil = (p) => void pending.push(p);
    rebuild();
    const { cookie } = await signUp();
    await call("email-start", { body: { email: "i@example.com" }, cookie });
    await call("email-verify", { body: { email: "i@example.com", code: sent.pop()!.code }, cookie });
    await Promise.all(pending.splice(0));
    options.sendCode = async () => {
      throw new Error("mail is down");
    };
    rebuild();
    expect((await call("email-start", { body: { email: "j@example.com" }, cookie })).status).toBe(200);
    expect((await call("recover-start", { body: { email: "i@example.com" } })).status).toBe(200);
    await expect(Promise.all(pending)).resolves.toBeDefined();
  });

  it("isn't offered for recovery when the server can't send it", async () => {
    options.sendCode = undefined;
    rebuild();
    expect(await call("recover-start", { body: { email: "a@example.com" } })).toMatchObject({
      status: 404,
      body: { error: "Email recovery isn't set up on this server" },
    });
  });
});

describe("the profile route", () => {
  it("renames, under the same rules as sign-up", async () => {
    const { cookie } = await signUp();
    expect((await call("profile", { method: "PUT", body: { name: " Sam " }, cookie })).body.account).toMatchObject({
      name: "Sam",
      profile: PROFILE,
    });
    expect((await call("profile", { method: "PUT", body: { name: "" }, cookie })).status).toBe(400);
  });

  it("leaves the profile alone when what's sent isn't an object", async () => {
    const { cookie } = await signUp();
    for (const profile of [undefined, null, "kg", 7]) {
      expect((await call("profile", { method: "PUT", body: { profile }, cookie })).body.account.profile).toEqual(PROFILE);
    }
  });

  it("starts empty when sign-up sends none, and refuses a list", async () => {
    expect((await signUp("Isaac", "key-1", null)).body.account.profile).toEqual({});
    expect(await signUp("Sam", "key-2", ["kg"])).toMatchObject({ status: 400, body: { error: "Profile must be an object" } });
  });

  // AuthInputError is the app saying no; anything else thrown is a bug, and
  // turning it into a 400 would hide it.
  it("lets a bug in parseProfile through", async () => {
    options.parseProfile = () => {
      throw new TypeError("oops");
    };
    rebuild();
    const options_ = await call("register-options", { body: { name: "Isaac" } });
    await expect(call("register-verify", { body: { profile: {}, response: passkeyResponse("k", options_.body.challenge) } })).rejects.toThrow(
      "oops",
    );
  });
});

describe("defaults", () => {
  // Every account in one Durable Object: the namespace is asked for exactly
  // one instance, by one name.
  it("reach the one auth Durable Object through its namespace", async () => {
    const names: unknown[] = [];
    options.store = {
      idFromName: (name: string) => (names.push(name), `id:${name}`),
      get: (id: unknown) => ({
        run: async (method: string, args: unknown[]) =>
          (raw as unknown as Record<string, (...a: unknown[]) => unknown>)[method]!(...args),
        id,
      }),
    };
    rebuild();
    const { cookie, body } = await signUp();
    expect((await call("session", { cookie })).body.account.id).toBe(body.account.id);
    expect(names).toEqual(["auth"]);
  });

  it("serve under /auth, and forgive a trailing slash on basePath", async () => {
    delete options.basePath;
    rebuild();
    expect((await auth.handle(new Request(`${ORIGIN}/auth/config`)))!.status).toBe(200);
    options.basePath = "/api/auth/";
    rebuild();
    expect((await call("config")).status).toBe(200);
  });

  // No stand-ins: real SimpleWebAuthn and the real clock.
  it("use SimpleWebAuthn and the clock", async () => {
    delete options.webauthn;
    delete options.now;
    rebuild();
    const login = await call("login-options", { body: {} });
    expect(login.body).toMatchObject({ rpId: "app.test", userVerification: "required" });
    expect(login.body.challenge).toMatch(/^[\w-]{20,}$/);
    raw.addPasskey({ id: "key-1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    raw.createAccount("u1", "Isaac", {}, 0);
    const res = await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
    expect(res).toMatchObject({ status: 400, body: { error: "Passkey couldn't be verified" } });
  });
});

describe("what's asked of the authenticator", () => {
  // The library checks what it's told to check. These are the settings that
  // make a passkey mean "this person, on this site": user verification
  // demanded and enforced, the right origin and RP, keys discoverable.
  it("is user verification, every time, on this origin", async () => {
    const seen: Record<string, Record<string, unknown>[]> = { gr: [], vr: [], ga: [], va: [] };
    const fake = fakeWebAuthn();
    const spy =
      (list: Record<string, unknown>[], fn: (o: never) => unknown) =>
      (async (o: Record<string, unknown>) => (list.push(o), fn(o as never))) as never;
    options.webauthn = {
      generateRegistrationOptions: spy(seen.gr!, fake.generateRegistrationOptions),
      verifyRegistrationResponse: spy(seen.vr!, fake.verifyRegistrationResponse),
      generateAuthenticationOptions: spy(seen.ga!, fake.generateAuthenticationOptions),
      verifyAuthenticationResponse: spy(seen.va!, fake.verifyAuthenticationResponse),
    };
    rebuild();

    const { cookie } = await signUp("Isaac", "key-1");
    const add = await call("passkey-options", { body: {}, cookie });
    await call("passkey-verify", { body: { response: passkeyResponse("key-2", add.body.challenge) }, cookie });
    const login = await call("login-options", { body: {} });
    await call("login-verify", { body: { response: passkeyResponse("key-1", login.body.challenge) } });
    const reauth = await call("reauth-options", { body: {}, cookie });
    await call("reauth-verify", { body: { response: passkeyResponse("key-1", reauth.body.challenge) }, cookie });

    for (const o of seen.gr!) {
      expect(o).toMatchObject({
        rpID: "app.test",
        attestationType: "none",
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
      });
    }
    // A new account has nothing to exclude; adding one excludes what it has,
    // so the same authenticator isn't registered twice.
    expect(seen.gr!.map((o) => o.excludeCredentials)).toEqual([[], [{ id: "key-1", transports: undefined }]]);
    for (const o of seen.ga!) expect(o).toMatchObject({ rpID: "app.test", userVerification: "required" });
    for (const o of [...seen.vr!, ...seen.va!]) {
      expect(o).toMatchObject({ requireUserVerification: true, expectedOrigin: [ORIGIN], expectedRPID: "app.test" });
    }
    expect(seen.vr).toHaveLength(2);
    expect(seen.va).toHaveLength(2);
  });

  // Real clientDataJSON is base64url, so it has - and _ where base64 has + and /.
  it("reads the challenge out of real-world base64url", async () => {
    await signUp("Isaac", "key-1");
    for (const challenge of ["c?>?>~", ">????"]) {
      expect(base64url(new TextEncoder().encode(JSON.stringify({ challenge })))).toMatch(/[-_]/);
      raw.createChallenge(challenge, "login", null, t);
      expect((await call("login-verify", { body: { response: passkeyResponse("key-1", challenge) } })).status).toBe(200);
    }
  });
});

describe("challenges and codes nobody issued", () => {
  // A challenge or code that isn't there is the user's 400, not a crash.
  it("are refused at every step that takes one", async () => {
    const { cookie } = await signUp();
    for (const action of ["reauth-verify", "passkey-verify"]) {
      expect(await call(action, { body: { response: passkeyResponse("key-1", "never-issued") }, cookie })).toMatchObject({
        status: 400,
        body: { error: "That expired — try again" },
      });
    }
    expect(await call("email-verify", { body: { email: "i@example.com", code: "123456" }, cookie })).toMatchObject({
      status: 400,
      body: { error: "That code is wrong or has expired" },
    });
  });
});

describe("adding a recovery email", () => {
  it("can re-confirm the email the account already has", async () => {
    const { cookie } = await signUp();
    await call("email-start", { body: { email: "i@example.com" }, cookie });
    await call("email-verify", { body: { email: "i@example.com", code: sent.pop()!.code }, cookie });
    expect((await call("email-start", { body: { email: "i@example.com" }, cookie })).status).toBe(200);
    expect(sent.map((s) => s.to)).toEqual(["i@example.com"]);
  });

  // The email says what the code is for; a recovery wording on an
  // add-this-email code would be a phisher's gift.
  it("sends codes worded for what they do", async () => {
    const { cookie } = await signUp();
    await call("email-start", { body: { email: "i@example.com" }, cookie });
    await call("email-verify", { body: { email: "i@example.com", code: sent[0]!.code }, cookie });
    await call("recover-start", { body: { email: "i@example.com" } });
    expect(sent.map((s) => s.purpose)).toEqual(["verify-email", "recover"]);
  });

  // Past the hourly cap: a 429, and no email whose code couldn't work.
  it(`stops sending after the hourly cap`, async () => {
    const { cookie } = await signUp();
    for (let i = 0; i < 5; i++) expect((await call("email-start", { body: { email: "i@example.com" }, cookie })).status).toBe(200);
    expect(await call("email-start", { body: { email: "i@example.com" }, cookie })).toMatchObject({
      status: 429,
      body: { error: "Too many codes sent to that email — try again in an hour" },
    });
    expect(sent).toHaveLength(5);
  });
});

describe("deleting an account without an onDeleteAccount hook", () => {
  it("still deletes it", async () => {
    delete options.onDeleteAccount;
    rebuild();
    const { cookie, body } = await signUp();
    expect((await call("delete-account", { body: {}, cookie })).status).toBe(200);
    expect(raw.account(body.account.id)).toBeNull();
  });
});

describe("the default profile rules", () => {
  it("take an object up to 4 KB of JSON, and nothing else", async () => {
    // {"a":"…"} is 8 characters around the string.
    expect((await signUp("A", "key-a", { a: "x".repeat(4096 - 8) })).status).toBe(200);
    expect(await signUp("B", "key-b", { a: "x".repeat(4096 - 7) })).toMatchObject({ status: 400, body: { error: "Profile is too large" } });
    expect(await signUp("C", "key-c", "kg")).toMatchObject({ status: 400, body: { error: "Profile must be an object" } });
  });
});
