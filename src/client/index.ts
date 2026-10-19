/** The browser side of durable-auth: the routes, and the passkey ceremonies
 * between them. Every call either returns what it promised or throws an
 * AuthError whose message is fit to show the user.
 *
 *   const auth = createAuthClient();            // routes at /auth
 *   const account = await auth.register("Sam");  // passkey prompt, signed in
 *
 * Sensitive calls (deleteAccount, startEmailVerification, addPasskey once the
 * account has one, removePasskey) may need the user to confirm with their
 * passkey first. The client does that itself — one more prompt, then the
 * call again — so callers never see it. */

import { startAuthentication, startRegistration, WebAuthnError } from "@simplewebauthn/browser";

/** `cancelled`: the user dismissed the passkey sheet — usually nothing to show.
 * `already-registered`: this device already has a passkey for the account. */
export type AuthErrorKind = "cancelled" | "already-registered";

export class AuthError extends Error {
  constructor(
    message: string,
    /** The HTTP status, or 0 when the request never got an answer. */
    readonly status = 0,
    readonly kind?: AuthErrorKind,
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export interface Account<P = Record<string, unknown>> {
  id: string;
  name: string;
  email: string | null;
  profile: P;
}

export interface PasskeySummary {
  id: string;
  createdAt: number;
  lastUsedAt: number | null;
  deviceType: "singleDevice" | "multiDevice" | null;
  backedUp: boolean | null;
}

export interface AuthConfig {
  /** Whether the server can send codes — offer recovery by email only if so. */
  email: boolean;
  turnstileSiteKey: string | null;
}

export interface AuthClientOptions {
  /** Where the server's routes are. Default "/auth". */
  basePath?: string;
  /** Per request. Default 15 s — a sign-in shouldn't hang on a dead network. */
  timeoutMs?: number;
}

type RegistrationOptions = Parameters<typeof startRegistration>[0]["optionsJSON"];
type AuthenticationOptions = Parameters<typeof startAuthentication>[0]["optionsJSON"];

/** True when this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}

/** The message to show for a failed step, or null when there's nothing to say
 * (the user dismissed the prompt). */
export function authErrorMessage(e: unknown, fallback: string): string | null {
  if (e instanceof AuthError) return e.kind === "cancelled" ? null : e.message;
  return fallback;
}

export function createAuthClient<P = Record<string, unknown>>(options: AuthClientOptions = {}) {
  const base = (options.basePath ?? "/auth").replace(/\/$/, "");
  const timeoutMs = options.timeoutMs ?? 15_000;

  async function call<T>(action: string, body?: unknown, method = body === undefined ? "GET" : "POST"): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${base}/${action}`, {
        method,
        credentials: "same-origin",
        headers: body === undefined ? undefined : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw new AuthError("You're offline — connect and try again.");
    }
    const data = (await res.json().catch(() => null)) as (T & { error?: string }) | null;
    if (!res.ok) {
      throw new AuthError(data?.error ?? `Something went wrong (${res.status})`, res.status, undefined, data ?? {});
    }
    return data as T;
  }

  /** The passkey prompt, with the browser's errors turned into plain words. */
  async function ceremony<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (e) {
      // Dismissing the sheet surfaces as NotAllowedError — bare, or wrapped.
      const name = e instanceof Error ? ((e.cause as Error | undefined)?.name ?? e.name) : "";
      if (name === "NotAllowedError" || (e instanceof WebAuthnError && e.code === "ERROR_CEREMONY_ABORTED")) {
        throw new AuthError("Cancelled.", 0, "cancelled");
      }
      if (e instanceof WebAuthnError && e.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED") {
        throw new AuthError("This device already has a passkey for your account.", 0, "already-registered");
      }
      throw new AuthError("This browser couldn't use a passkey.");
    }
  }

  async function reauth(): Promise<void> {
    const optionsJSON = await call<AuthenticationOptions>("reauth-options", {});
    const response = await ceremony(() => startAuthentication({ optionsJSON }));
    await call("reauth-verify", { response });
  }

  /** Run a sensitive call; if the server wants the user to confirm first,
   * confirm with their passkey and run it once more. */
  async function withReauth<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (e) {
      if (!(e instanceof AuthError && e.body.reauth === true)) throw e;
      await reauth();
      return run();
    }
  }

  const addPasskey = () =>
    withReauth(async () => {
      const optionsJSON = await call<RegistrationOptions>("passkey-options", {});
      const response = await ceremony(() => startRegistration({ optionsJSON }));
      await call("passkey-verify", { response });
    });

  return {
    config: () => call<AuthConfig>("config"),

    /** The signed-in account; null when signed out; undefined when we couldn't
     * tell (offline). Offline is not signed out. */
    async session(): Promise<Account<P> | null | undefined> {
      try {
        return (await call<{ account: Account<P> }>("session")).account;
      } catch (e) {
        return e instanceof AuthError && e.status === 401 ? null : undefined;
      }
    },

    /** Create an account with a new passkey, and sign in. */
    async register(name: string, profile?: Partial<P>, turnstileToken?: string): Promise<Account<P>> {
      const optionsJSON = await call<RegistrationOptions>("register-options", { name, turnstileToken });
      const response = await ceremony(() => startRegistration({ optionsJSON }));
      return (await call<{ account: Account<P> }>("register-verify", { name, profile, response })).account;
    },

    /** Sign in with any passkey this device offers — no username. */
    async signIn(): Promise<Account<P>> {
      const optionsJSON = await call<AuthenticationOptions>("login-options", {});
      const response = await ceremony(() => startAuthentication({ optionsJSON }));
      return (await call<{ account: Account<P> }>("login-verify", { response })).account;
    },

    signOut: () => call("logout", {}),
    signOutOtherDevices: () => call("logout-others", {}),

    /** Confirm it's still the user. The sensitive calls here do this for
     * themselves; use it to guard a sensitive route of your own. */
    reauth,

    /** A passkey for this device on the signed-in account — after recovering
     * by email, or to add another device. */
    addPasskey,
    passkeys: async () => (await call<{ passkeys: PasskeySummary[] }>("passkeys")).passkeys,
    removePasskey: (id: string) => withReauth(() => call("passkey-delete", { id })),

    startRecovery: (email: string, turnstileToken?: string) => call("recover-start", { email, turnstileToken }),
    /** Signs in, and signs every other device out and revokes their passkeys.
     * Call addPasskey next. */
    finishRecovery: async (email: string, code: string) =>
      (await call<{ account: Account<P> }>("recover-verify", { email, code })).account,

    startEmailVerification: (email: string) => withReauth(() => call("email-start", { email })),
    finishEmailVerification: async (email: string, code: string) =>
      (await call<{ account: Account<P> }>("email-verify", { email, code })).account,

    updateProfile: async (patch: { name?: string; profile?: Partial<P> }) =>
      (await call<{ account: Account<P> }>("profile", patch, "PUT")).account,

    deleteAccount: () => withReauth(() => call("delete-account", {})),
  };
}

export type AuthClient<P = Record<string, unknown>> = ReturnType<typeof createAuthClient<P>>;
