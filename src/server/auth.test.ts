import { describe, it, expect, beforeEach, vi } from "vitest";
import { memorySql } from "../../test/sqlite";
import { AuthInputError, createAuth, type Auth, type AuthOptions, type WebAuthn } from "./auth";
import { AuthStore } from "./store";
import { asyncStore } from "./stub";
import { base64url } from "./crypto";

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
let sent: { to: string; code: string }[];

/** Apply option changes made inside a test. */
const rebuild = () => (auth = createAuth(options));

beforeEach(() => {
  t = 1_000;
  sent = [];
  options = {
    store: asyncStore(new AuthStore(memorySql())),
    rpName: "Test",
    basePath: "/api/auth",
    now: () => t,
    webauthn: fakeWebAuthn(),
    sendCode: async (to, code) => void sent.push({ to, code }),
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
    expect((await call("passkey-options", { body: {}, cookie })).status).toBe(403);
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

    stale();
    expect((await call("passkey-options", { body: {}, cookie: recovered.cookie })).status).toBe(403);
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
