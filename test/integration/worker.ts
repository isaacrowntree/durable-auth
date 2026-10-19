/** createAuth in front of the real auth Durable Object.
 *
 * Everything is the library's code except the edges a test can't reach: the
 * passkey cryptography (a fake that still round-trips the stored public key —
 * see below) and the email provider (codes are kept for the test to read). */
import { DurableObject } from "cloudflare:workers";
import { AuthDurableObject, AuthStore, createAuth, type AuthNamespace, type WebAuthn } from "../../src/server/index";

export class Auth extends AuthDurableObject {}

/** A database from schema version 1, opened by today's AuthStore — the
 * ALTERs running on DO SQLite rather than node:sqlite. */
export class Legacy extends DurableObject {
  upgrade() {
    const sql = this.ctx.storage.sql;
    sql.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, profile TEXT NOT NULL, created_at INTEGER NOT NULL)`);
    sql.exec(`CREATE TABLE passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT, created_at INTEGER NOT NULL)`);
    sql.exec(`CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL)`);
    sql.exec(`INSERT INTO users VALUES ('u1', 'Old', NULL, '{}', 0)`);
    sql.exec(`INSERT INTO passkeys VALUES ('k1', 'u1', ?, 0, NULL, 0)`, new Uint8Array([1, 2, 3]));
    sql.exec(`INSERT INTO sessions VALUES ('h1', 'u1', ?, 0)`, Date.now() + 1e9);
    const store = new AuthStore(sql);
    new AuthStore(sql); // and again: idempotent
    return {
      account: store.account("u1"),
      key: [...store.passkey("k1")!.publicKey],
      session: store.session("h1", 1),
      passkeys: store.passkeySummaries("u1"),
    };
  }
}

interface Env {
  AUTH: AuthNamespace;
  LEGACY: DurableObjectNamespace<Legacy>;
}

const sent: { to: string; code: string }[] = [];
const deleted: string[] = [];
let n = 0;
let clockOffset = 0;

/** Registration stores whatever public key the "authenticator" claims; sign-in
 * verifies only if the key read back out of DO SQLite is byte-for-byte the
 * one it stored. That's the round trip — BLOB column, then RPC — that only
 * this suite exercises. */
const webauthn: WebAuthn = {
  generateRegistrationOptions: (async () => ({ challenge: `reg-${++n}` })) as never,
  generateAuthenticationOptions: (async () => ({ challenge: `auth-${++n}` })) as never,
  verifyRegistrationResponse: (async ({ response }: { response: { id: string; publicKey: number[] } }) => ({
    verified: true,
    registrationInfo: {
      credential: { id: response.id, publicKey: new Uint8Array(response.publicKey), counter: 0 },
      credentialDeviceType: "multiDevice",
      credentialBackedUp: true,
    },
  })) as never,
  verifyAuthenticationResponse: (async ({
    response,
    credential,
  }: {
    response: { publicKey: number[] };
    credential: { publicKey: Uint8Array };
  }) => ({
    verified:
      credential.publicKey instanceof Uint8Array && [...credential.publicKey].join() === response.publicKey.join(),
    authenticationInfo: { newCounter: 1 },
  })) as never,
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/sent") return Response.json(sent.splice(0));
    if (url.pathname === "/deleted") return Response.json(deleted.splice(0));
    if (url.pathname === "/later") {
      clockOffset += 10 * 60 * 1000;
      return Response.json({ ok: true });
    }
    if (url.pathname === "/legacy") {
      return Response.json(await env.LEGACY.get(env.LEGACY.idFromName("legacy")).upgrade());
    }
    const auth = createAuth({
      store: env.AUTH,
      rpName: "Integration",
      now: () => Date.now() + clockOffset,
      webauthn,
      sendCode: async (to, code) => void sent.push({ to, code }),
      onDeleteAccount: async (userId) => void deleted.push(userId),
    });
    return (await auth.handle(req)) ?? new Response("Not found", { status: 404 });
  },
};
