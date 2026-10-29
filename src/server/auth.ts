/** Sign-in, as one function from a Request to a Response.
 *
 * Passkeys are the login; a verified email is only for getting back in after
 * losing every device. Everything the outside world provides — the store,
 * email, Turnstile, rate limits, WebAuthn itself — arrives in the options, so
 * a Worker is wiring and this file is testable. */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { SessionCookie } from "./cookie";
import { codeKey, hashCode, newAccountId, randomToken, sha256, sixDigitCode } from "./crypto";
import { authStoreFrom, type AuthApi, type AuthNamespace } from "./stub";
import { normalizeEmail, type AccountView, type CodePurpose, type Profile, type StoredPasskey } from "./store";

export interface WebAuthn {
  generateRegistrationOptions: typeof generateRegistrationOptions;
  verifyRegistrationResponse: typeof verifyRegistrationResponse;
  generateAuthenticationOptions: typeof generateAuthenticationOptions;
  verifyAuthenticationResponse: typeof verifyAuthenticationResponse;
}

const realWebAuthn: WebAuthn = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
};

export interface AuthOptions<P extends Profile = Profile> {
  /** The auth Durable Object's namespace (or, in tests, `asyncStore(...)`). */
  store: AuthNamespace | AuthApi;
  /** Shown by the passkey prompt: "Save a passkey for <rpName>?" */
  rpName: string;
  /** Where the routes live: `<basePath>/<action>`. Default "/auth". */
  basePath?: string;
  /** The session cookie's name; `__Host-` is prefixed over HTTPS. Default "session". */
  cookieName?: string;
  /** The passkeys' domain. Default: the request's hostname. Set it to share
   * passkeys across subdomains (rpID "example.com" from app.example.com). */
  rpID?: string;
  /** Origins allowed to sign in and to post to the routes. Default: the
   * request's own origin. */
  origins?: string[];
  /** Validate the app's account data, on sign-up (`current` null) and on
   * every update (`input` is the current profile with `patch`, what the
   * client sent, merged in). The user can write any of it: keep anything
   * they mustn't set themselves (a plan, a role) out of the profile, or
   * refuse it here. Throw `new AuthInputError(message)` to refuse. Default:
   * any JSON object up to 4 KB. */
  parseProfile?: (input: unknown, current: P | null, patch: unknown) => P;
  /** Who may create an account. Default: anyone. Return false to refuse.
   * `body` is the request's JSON — e.g. an invite code your page sent. */
  allowSignup?: (req: Request, attempt: { name: string; body: Record<string, unknown> }) => boolean | Promise<boolean>;
  /** Send a one-time code. Absent: recovery by email is off, and `config`
   * says so. See `cloudflareEmail` for Cloudflare Email Sending. */
  sendCode?: (to: string, code: string, purpose: CodePurpose) => Promise<void>;
  /** Required with `sendCode`: the key emailed codes are hashed under, from
   * a Worker secret (`openssl rand -base64 32`), at least 32 characters.
   * Changing it invalidates codes already sent, nothing else. */
  codeSecret?: string;
  /** Cloudflare Turnstile on sign-up and recovery. See `turnstileVerifier`. */
  turnstile?: { siteKey: string; verify: (token: string, ip: string | null) => Promise<boolean> };
  /** true = allowed. Keys look like "login:<ip>". See `rateLimitBinding`. */
  rateLimit?: (key: string) => Promise<boolean>;
  /** Remove what the account owns outside auth, before the account itself
   * goes. If this throws, the account survives to retry with. */
  onDeleteAccount?: (userId: string) => Promise<void>;
  /** Finish work after the response — pass `ctx.waitUntil.bind(ctx)`.
   * Without it, recovery emails are sent before answering, which lets a
   * stranger time the answer to learn whether an email has an account. */
  waitUntil?: (work: Promise<unknown>) => void;
  /** How recently a passkey (or an emailed code) must have been used for a
   * sensitive action: deleting the account, changing its recovery email,
   * adding or removing a passkey. Default 5 minutes. */
  reauthWindowMs?: number;
  /** Default 64. */
  maxNameLength?: number;
  now?: () => number;
  /** For tests: stand-in passkey cryptography. */
  webauthn?: WebAuthn;
}

export interface Session {
  userId: string;
  /** Hash of the session token — the key to sign this one session out. */
  tokenHash: string;
  verifiedAt: number;
}

export interface Auth<P extends Profile = Profile> {
  /** The response for a request under `basePath`, or null for any other path. */
  handle(req: Request): Promise<Response | null>;
  /** The request's signed-in session, or null. Use it to guard your own routes. */
  session(req: Request): Promise<Session | null>;
  /** The request's signed-in account, or null. */
  account(req: Request): Promise<AccountView<P> | null>;
}

/** A 400 with a message fit to show the user. Throw it from `parseProfile`. */
export class AuthInputError extends Error {
  readonly status: number = 400;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

function fail(status: number, message: string, extra?: Record<string, unknown>): never {
  throw new HttpError(status, message, extra);
}

const REAUTH_WINDOW_MS = 5 * 60 * 1000;
const PROFILE_MAX_BYTES = 4096;

export function createAuth<P extends Profile = Profile>(options: AuthOptions<P>): Auth<P> {
  const store: AuthApi = "idFromName" in options.store ? authStoreFrom(options.store as AuthNamespace) : options.store;
  const basePath = (options.basePath ?? "/auth").replace(/\/$/, "");
  const cookie = new SessionCookie(options.cookieName ?? "session");
  const webauthn = options.webauthn ?? realWebAuthn;
  const now = options.now ?? Date.now;
  const reauthWindow = options.reauthWindowMs ?? REAUTH_WINDOW_MS;
  const maxName = options.maxNameLength ?? 64;
  if (options.sendCode && (options.codeSecret?.length ?? 0) < 32) {
    throw new Error("durable-auth: sendCode needs codeSecret, at least 32 characters (openssl rand -base64 32)");
  }
  let codeHashKey: Promise<CryptoKey> | undefined;
  const codeHash = (email: string, purpose: CodePurpose, code: string) =>
    (codeHashKey ??= codeKey(options.codeSecret!)).then((k) => hashCode(k, email, purpose, code));
  const parseProfile = options.parseProfile ?? (defaultProfile as unknown as NonNullable<AuthOptions<P>["parseProfile"]>);

  // ---- helpers ------------------------------------------------------------

  function relyingParty(req: Request): { rpID: string; origins: string[] } {
    const url = new URL(req.url);
    return { rpID: options.rpID ?? url.hostname, origins: options.origins ?? [url.origin] };
  }

  /** A state-changing request must come from our own pages. SameSite=Lax
   * already keeps the cookie off cross-site POSTs; this refuses them outright,
   * so nothing depends on a browser getting SameSite right. Browsers send
   * Origin on every POST; without one, only a same-origin fetch metadata
   * header will do. */
  function sameOrigin(req: Request): boolean {
    if (req.method === "GET" || req.method === "HEAD") return true;
    const origin = req.headers.get("origin");
    if (origin === null) return req.headers.get("sec-fetch-site") === "same-origin";
    return relyingParty(req).origins.includes(origin);
  }

  async function session(req: Request): Promise<Session | null> {
    const token = cookie.read(req);
    if (!token) return null;
    const tokenHash = await sha256(token);
    const found = await store.session(tokenHash, now());
    return found ? { ...found, tokenHash } : null;
  }

  async function requireSession(req: Request): Promise<Session> {
    return (await session(req)) ?? fail(401, "Not signed in");
  }

  /** Sensitive actions want the user, not just their cookie: a passkey or an
   * emailed code within the window. The client answers `reauth: true` with
   * the reauth ceremony and retries (see the client's `withReauth`). */
  function requireFresh(s: Session): void {
    if (now() - s.verifiedAt > reauthWindow) {
      fail(403, "Confirm it's you to continue", { reauth: true });
    }
  }

  async function signedIn(req: Request, account: AccountView): Promise<Response> {
    const token = randomToken();
    await store.createSession(await sha256(token), account.id, now());
    return Response.json({ account }, { headers: { "set-cookie": cookie.set(req, token) } });
  }

  function clientIp(req: Request): string | null {
    return req.headers.get("cf-connecting-ip");
  }

  async function limit(req: Request, bucket: string): Promise<void> {
    if (!options.rateLimit) return;
    const ok = await options.rateLimit(`${bucket}:${clientIp(req) ?? "unknown"}`);
    if (!ok) fail(429, "Too many attempts — wait a minute and try again");
  }

  async function requireHuman(req: Request, token: unknown): Promise<void> {
    if (!options.turnstile) return;
    if (typeof token !== "string" || !(await options.turnstile.verify(token, clientIp(req)))) {
      fail(400, "Couldn't confirm you're human — try again");
    }
  }

  function parseName(v: unknown): string {
    const name = typeof v === "string" ? v.trim() : "";
    if (!name || name.length > maxName) fail(400, `Enter a name up to ${maxName} characters`);
    return name;
  }

  function profileFrom(input: unknown, current: P | null, patch: unknown): P {
    try {
      return parseProfile(input, current, patch);
    } catch (e) {
      if (e instanceof AuthInputError) fail(400, e.message);
      throw e;
    }
  }

  async function registration(req: Request, userId: string, name: string, purpose: "register" | "add-passkey", exclude: StoredPasskey[] = []) {
    const options_ = await webauthn.generateRegistrationOptions({
      rpName: options.rpName,
      rpID: relyingParty(req).rpID,
      userName: name,
      userDisplayName: name,
      userID: new TextEncoder().encode(userId),
      attestationType: "none",
      excludeCredentials: exclude.map((k) => ({ id: k.id, transports: k.transports as never })),
      // Discoverable, so signing in on a new device needs no username.
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    await store.createChallenge(options_.challenge, purpose, userId, now(), purpose === "register" ? name : null);
    return options_;
  }

  /** Verify a new passkey and return it ready to store, or fail. */
  async function verifiedPasskey(req: Request, response: RegistrationResponseJSON, challenge: string, userId: string): Promise<StoredPasskey> {
    const { rpID, origins } = relyingParty(req);
    const result = await webauthn
      .verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origins,
        expectedRPID: rpID,
        requireUserVerification: true,
      })
      .catch(() => ({ verified: false as const, registrationInfo: undefined }));
    if (!result.verified || !result.registrationInfo) fail(400, "Passkey couldn't be verified");
    const { credential, credentialDeviceType, credentialBackedUp } = result.registrationInfo;
    if (await store.passkey(credential.id)) fail(400, "This passkey is already in use");
    return {
      id: credential.id,
      userId,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
    };
  }

  /** Verify an assertion against one of our passkeys (optionally one of a
   * given account's), recording its use. Returns the key's owner. */
  async function verifiedAssertion(req: Request, response: AuthenticationResponseJSON, challenge: string, onlyUser?: string): Promise<string> {
    const key = await store.passkey(response.id);
    // A passkey we don't know: most often the account was deleted, and the
    // device still offers its key.
    if (!key || (onlyUser !== undefined && key.userId !== onlyUser)) fail(400, "No account uses this passkey");
    const { rpID, origins } = relyingParty(req);
    const result = await webauthn
      .verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origins,
        expectedRPID: rpID,
        credential: {
          id: key.id,
          publicKey: new Uint8Array(key.publicKey),
          counter: key.counter,
          transports: key.transports as never,
        },
        requireUserVerification: true,
      })
      .catch(() => ({ verified: false as const, authenticationInfo: undefined }));
    if (!result.verified || !result.authenticationInfo) fail(400, "Passkey couldn't be verified");
    await store.passkeyUsed(key.id, result.authenticationInfo.newCounter, now());
    return key.userId;
  }

  async function sendCodeFor(email: string, purpose: CodePurpose, userId: string): Promise<void> {
    const code = sixDigitCode();
    const issued = await store.issueCode(email, purpose, userId, await codeHash(email, purpose, code), now());
    if (issued === "ok") await options.sendCode!(email, code, purpose);
  }

  // ---- routes ---------------------------------------------------------------

  type Handler = (req: Request) => Promise<Response>;

  const routes: Record<string, Handler> = {
    "GET config": async () =>
      Response.json({ email: Boolean(options.sendCode), turnstileSiteKey: options.turnstile?.siteKey ?? null }),

    "GET session": async (req) => {
      const { userId } = await requireSession(req);
      const account = (await store.account(userId)) ?? fail(401, "Not signed in");
      // Re-set the same cookie: its browser-side expiry slides with use.
      return Response.json({ account }, { headers: { "set-cookie": cookie.set(req, cookie.read(req)!) } });
    },

    "POST logout": async (req) => {
      const s = await session(req);
      if (s) await store.deleteSession(s.tokenHash);
      return Response.json({ ok: true }, { headers: { "set-cookie": cookie.clear(req) } });
    },

    "POST logout-others": async (req) => {
      const s = await requireSession(req);
      await store.deleteSessionsFor(s.userId, s.tokenHash);
      return Response.json({ ok: true });
    },

    // ---- create an account ------------------------------------------------

    "POST register-options": async (req) => {
      await limit(req, "register");
      const body = await json<{ name?: unknown; turnstileToken?: unknown }>(req);
      const name = parseName(body.name);
      await requireHuman(req, body.turnstileToken);
      if (options.allowSignup && !(await options.allowSignup(req, { name, body }))) {
        fail(403, "Sign-up is closed");
      }
      return Response.json(await registration(req, newAccountId(), name, "register"));
    },

    "POST register-verify": async (req) => {
      await limit(req, "register");
      const body = await json<{ response?: RegistrationResponseJSON; profile?: unknown }>(req);
      const profile = profileFrom(body.profile, null, body.profile);
      const response = body.response ?? fail(400, "Missing passkey response");

      const challenge = clientChallenge(response);
      const issued = await store.consumeChallenge(challenge, "register", now());
      const userId = issued?.userId ?? fail(400, "That sign-up expired — try again");
      // The name sign-up was approved under (allowSignup, Turnstile), not a new one.
      const name = issued?.name ?? fail(400, "That sign-up expired — try again");
      // Checked before the account exists, so a refusal leaves nothing behind.
      const key = await verifiedPasskey(req, response, challenge, userId);

      const at = now();
      const account = await store.createAccount(userId, name, profile, at);
      await store.addPasskey(key, at);
      return signedIn(req, account);
    },

    // ---- sign in with a passkey ---------------------------------------------

    "POST login-options": async (req) => {
      await limit(req, "login");
      const options_ = await webauthn.generateAuthenticationOptions({
        rpID: relyingParty(req).rpID,
        userVerification: "required",
      });
      await store.createChallenge(options_.challenge, "login", null, now());
      return Response.json(options_);
    },

    "POST login-verify": async (req) => {
      await limit(req, "login");
      const body = await json<{ response?: AuthenticationResponseJSON }>(req);
      const response = body.response ?? fail(400, "Missing passkey response");
      const challenge = clientChallenge(response);
      if (!(await store.consumeChallenge(challenge, "login", now()))) fail(400, "That sign-in expired — try again");
      const userId = await verifiedAssertion(req, response, challenge);
      const account = (await store.account(userId)) ?? fail(400, "No account uses this passkey");
      return signedIn(req, account);
    },

    // ---- step-up: prove it's still you --------------------------------------

    "POST reauth-options": async (req) => {
      await limit(req, "login");
      const { userId } = await requireSession(req);
      const keys = await store.passkeysFor(userId);
      if (keys.length === 0) fail(409, "Add a passkey to this account first", { needsPasskey: true });
      const options_ = await webauthn.generateAuthenticationOptions({
        rpID: relyingParty(req).rpID,
        userVerification: "required",
        allowCredentials: keys.map((k) => ({ id: k.id, transports: k.transports as never })),
      });
      await store.createChallenge(options_.challenge, "reauth", userId, now());
      return Response.json(options_);
    },

    "POST reauth-verify": async (req) => {
      await limit(req, "login");
      const s = await requireSession(req);
      const body = await json<{ response?: AuthenticationResponseJSON }>(req);
      const response = body.response ?? fail(400, "Missing passkey response");
      const challenge = clientChallenge(response);
      const issued = await store.consumeChallenge(challenge, "reauth", now());
      if (issued?.userId !== s.userId) fail(400, "That expired — try again");
      await verifiedAssertion(req, response, challenge, s.userId);
      await store.markVerified(s.tokenHash, now());
      return Response.json({ ok: true });
    },

    // ---- the account's passkeys ---------------------------------------------

    "GET passkeys": async (req) => {
      const { userId } = await requireSession(req);
      return Response.json({ passkeys: await store.passkeySummaries(userId) });
    },

    "POST passkey-options": async (req) => {
      const s = await requireSession(req);
      const account = (await store.account(s.userId)) ?? fail(401, "Not signed in");
      const existing = await store.passkeysFor(s.userId);
      // Adding a key is a way in, so it needs a fresh session. One with no
      // passkey to confirm with was just recovered by email — fresh for the
      // window, which is the time it has to add one. After that, the emailed
      // code is the only proof left: recover again.
      if (existing.length === 0 && now() - s.verifiedAt > reauthWindow) {
        fail(403, "Recover your account by email again to add a passkey");
      }
      requireFresh(s);
      return Response.json(await registration(req, s.userId, account.name, "add-passkey", existing));
    },

    "POST passkey-verify": async (req) => {
      const { userId } = await requireSession(req);
      const body = await json<{ response?: RegistrationResponseJSON }>(req);
      const response = body.response ?? fail(400, "Missing passkey response");
      const challenge = clientChallenge(response);
      const issued = await store.consumeChallenge(challenge, "add-passkey", now());
      if (issued?.userId !== userId) fail(400, "That expired — try again");
      await store.addPasskey(await verifiedPasskey(req, response, challenge, userId), now());
      return Response.json({ ok: true });
    },

    "POST passkey-delete": async (req) => {
      const s = await requireSession(req);
      requireFresh(s);
      const { id } = await json<{ id?: unknown }>(req);
      if (typeof id !== "string") fail(400, "Which passkey?");
      const keys = await store.passkeysFor(s.userId);
      if (!keys.some((k) => k.id === id)) fail(404, "No such passkey");
      if (keys.length === 1) fail(409, "That's your only passkey — add another before removing it");
      await store.deletePasskey(s.userId, id);
      return Response.json({ ok: true });
    },

    // ---- recovery by email ---------------------------------------------------

    "POST recover-start": async (req) => {
      if (!options.sendCode) fail(404, "Email recovery isn't set up on this server");
      await limit(req, "email");
      const body = await json<{ email?: unknown; turnstileToken?: unknown }>(req);
      const email = parseEmail(body.email);
      await requireHuman(req, body.turnstileToken);

      // The same answer, in the same time, whether or not the email has an
      // account: this endpoint must not tell a stranger who uses the app. So
      // the lookup and the send happen after the response.
      const work = (async () => {
        const account = await store.accountByEmail(email);
        if (account) await sendCodeFor(email, "recover", account.id);
      })();
      if (options.waitUntil) options.waitUntil(work.catch(() => {}));
      else await work;
      return Response.json({ ok: true });
    },

    "POST recover-verify": async (req) => {
      await limit(req, "email");
      const body = await json<{ email?: unknown; code?: unknown }>(req);
      const email = parseEmail(body.email);
      const code = parseCode(body.code);
      const redeemed = await store.redeemCode(email, "recover", await codeHash(email, "recover", code), now());
      if (!redeemed) fail(400, "That code is wrong or has expired");

      // Recovering means a device was lost — possibly stolen, passkey and all.
      // Sign the account out everywhere and take its passkeys away; the client
      // adds a fresh one for this device next.
      await store.deleteSessionsFor(redeemed.userId);
      await store.deletePasskeysFor(redeemed.userId);
      const account = (await store.account(redeemed.userId)) ?? fail(400, "Account not found");
      return signedIn(req, account);
    },

    // ---- the signed-in account's recovery email ------------------------------

    "POST email-start": async (req) => {
      if (!options.sendCode) fail(404, "Email isn't set up on this server");
      const s = await requireSession(req);
      // Whoever controls the recovery email controls the account.
      requireFresh(s);
      await limit(req, "email");
      const email = parseEmail((await json<{ email?: unknown }>(req)).email);

      // Someone else's email: answer as if sent, and send nothing. Open sign-up
      // would otherwise make this a way to ask who uses the app — so it counts
      // against the same hourly cap, and the real send happens after the
      // answer, the same way recover-start's does.
      const owner = await store.accountByEmail(email);
      const mine = !owner || owner.id === s.userId;
      const code = sixDigitCode();
      const issued = mine
        ? await store.issueCode(email, "verify-email", s.userId, await codeHash(email, "verify-email", code), now())
        : await store.noteCodeRequest(email, now());
      if (issued === "rate-limited") fail(429, "Too many codes sent to that email — try again in an hour");
      if (mine) {
        const send = options.sendCode!(email, code, "verify-email");
        if (options.waitUntil) options.waitUntil(send.catch(() => {}));
        else await send;
      }
      return Response.json({ ok: true });
    },

    // No step-up here: the code was issued to this account while it was fresh.
    "POST email-verify": async (req) => {
      const { userId } = await requireSession(req);
      await limit(req, "email");
      const body = await json<{ email?: unknown; code?: unknown }>(req);
      const email = parseEmail(body.email);
      const code = parseCode(body.code);
      const redeemed = await store.redeemCode(email, "verify-email", await codeHash(email, "verify-email", code), now());
      if (redeemed?.userId !== userId) fail(400, "That code is wrong or has expired");

      const account = await store.setEmail(userId, email);
      if (account === "taken") fail(409, "That email is already used by another account");
      return Response.json({ account });
    },

    // ---- the account itself ----------------------------------------------------

    "PUT profile": async (req) => {
      const { userId } = await requireSession(req);
      const body = await json<{ name?: unknown; profile?: unknown }>(req);
      const current = (await store.account(userId)) ?? fail(401, "Not signed in");
      // Partial: a device changes one thing at a time.
      const patch = body.profile && typeof body.profile === "object" ? body.profile : undefined;
      const account = await store.updateAccount(userId, {
        name: body.name === undefined ? undefined : parseName(body.name),
        profile: patch === undefined ? undefined : profileFrom({ ...current.profile, ...patch }, current.profile as P, patch),
      });
      return Response.json({ account });
    },

    "POST delete-account": async (req) => {
      const s = await requireSession(req);
      requireFresh(s);
      // Every device out first, so nothing in flight recreates what's being
      // erased. Then the app's data — if that fails, the account still exists
      // to retry with — then the account.
      await store.deleteSessionsFor(s.userId);
      await options.onDeleteAccount?.(s.userId);
      await store.deleteAccount(s.userId);
      return Response.json({ ok: true }, { headers: { "set-cookie": cookie.clear(req) } });
    },
  };

  return {
    async handle(req) {
      const path = new URL(req.url).pathname;
      if (!path.startsWith(`${basePath}/`)) return null;
      const action = path.slice(basePath.length + 1);
      try {
        if (!sameOrigin(req)) fail(403, "Cross-origin request refused");
        const route = routes[`${req.method} ${action}`];
        if (!route) return Response.json({ error: "Not found" }, { status: 404 });
        return await route(req);
      } catch (e) {
        if (e instanceof HttpError) return Response.json({ error: e.message, ...e.extra }, { status: e.status });
        throw e;
      }
    },
    session,
    async account(req) {
      const s = await session(req);
      return s ? ((await store.account(s.userId)) as AccountView<P> | null) : null;
    },
  };
}

// ---- parsing --------------------------------------------------------------

/** The challenge the authenticator signed, read back out of clientDataJSON.
 * We look it up ourselves (rather than handing the library a predicate) so
 * the lookup also tells us which account a registration is for. */
function clientChallenge(response: { response?: { clientDataJSON?: string } }): string {
  try {
    const b64 = response.response!.clientDataJSON!.replace(/-/g, "+").replace(/_/g, "/");
    const data = JSON.parse(atob(b64)) as { challenge?: unknown };
    if (typeof data.challenge === "string" && data.challenge) return data.challenge;
  } catch {
    // fall through
  }
  return fail(400, "Malformed passkey response");
}

async function json<T>(req: Request): Promise<T> {
  const body = await req.json().catch(() => null);
  return body && typeof body === "object" ? (body as T) : fail(400, "Expected a JSON body");
}

function parseEmail(v: unknown): string {
  const email = typeof v === "string" ? normalizeEmail(v) : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, "Enter a valid email");
  return email;
}

function parseCode(v: unknown): string {
  const code = typeof v === "string" ? v.replace(/\s/g, "") : "";
  if (!/^\d{6}$/.test(code)) fail(400, "Enter the 6-digit code");
  return code;
}

function defaultProfile(input: unknown): Profile {
  if (input === undefined || input === null) return {};
  if (typeof input !== "object" || Array.isArray(input)) throw new AuthInputError("Profile must be an object");
  if (JSON.stringify(input).length > PROFILE_MAX_BYTES) throw new AuthInputError("Profile is too large");
  return input as Profile;
}
