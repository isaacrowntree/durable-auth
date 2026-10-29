import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { memorySql, memoryTransaction } from "../../test/sqlite.js";
import {
  AuthStore,
  CHALLENGE_TTL_MS,
  CODE_MAX_ATTEMPTS,
  CODE_TTL_MS,
  CODES_PER_HOUR,
  MAX_CODE_FAILURES,
  MAX_GLOBAL_CODE_FAILURES,
  SCHEMA_VERSION,
  SESSION_TTL_MS,
} from "./store.js";

const PROFILE = { unit: "kg", theme: "dark" };
const DAY = 24 * 60 * 60 * 1000;
let store: AuthStore;

beforeEach(() => {
  store = new AuthStore(memorySql());
});

describe("challenges", () => {
  it("are single use", () => {
    store.createChallenge("c1", "login", null, 0);
    expect(store.consumeChallenge("c1", "login", 1)).toEqual({ userId: null, name: null });
    expect(store.consumeChallenge("c1", "login", 2)).toBeNull();
  });

  it("carry the account a registration is minting", () => {
    store.createChallenge("c1", "register", "u_new", 0, "Sam");
    expect(store.consumeChallenge("c1", "register", 1)).toEqual({ userId: "u_new", name: "Sam" });
  });

  // A login challenge replayed into the registration flow (or vice versa)
  // must not verify — and is burned for trying.
  it("only redeem for the purpose they were issued for", () => {
    store.createChallenge("c1", "login", null, 0);
    expect(store.consumeChallenge("c1", "register", 1)).toBeNull();
    expect(store.consumeChallenge("c1", "login", 2)).toBeNull();
  });

  it("expire", () => {
    store.createChallenge("c1", "login", null, 0);
    expect(store.consumeChallenge("c1", "login", CHALLENGE_TTL_MS)).toBeNull();
  });

  // The constant, not just the rule: a passkey prompt left open a few
  // minutes must still work.
  it("last five minutes", () => {
    store.createChallenge("c1", "login", null, 0);
    expect(store.consumeChallenge("c1", "login", 5 * 60 * 1000 - 1)).not.toBeNull();
  });
});

describe("accounts", () => {
  it("round-trip with their profile", () => {
    store.createAccount("u1", "Isaac", PROFILE, 0);
    expect(store.account("u1")).toEqual({ id: "u1", name: "Isaac", email: null, profile: PROFILE });
  });

  it("find by email, case-insensitively", () => {
    store.createAccount("u1", "Isaac", PROFILE, 0);
    store.setEmail("u1", "Isaac@Example.com");
    expect(store.accountByEmail("isaac@example.COM")?.id).toBe("u1");
  });

  // Recovery sends a code to an email and signs into whichever account owns
  // it. Two owners would make that ambiguous — or a takeover.
  it("refuse an email another account already has", () => {
    store.createAccount("u1", "A", PROFILE, 0);
    store.createAccount("u2", "B", PROFILE, 0);
    store.setEmail("u1", "a@example.com");
    expect(store.setEmail("u2", "A@example.com")).toBe("taken");
    expect(store.setEmail("u1", "a@example.com")).not.toBe("taken");
  });

  // An address someone deleted their account to be rid of isn't kept in
  // the rate-limit tables either.
  it("take their email out of the code logs when deleted", () => {
    const db = new DatabaseSync(":memory:");
    store = new AuthStore(memorySql(db));
    store.createAccount("u1", "A", PROFILE, 0);
    store.setEmail("u1", "a@example.com");
    store.issueCode("a@example.com", "recover", "u1", "real", 0);
    store.redeemCode("a@example.com", "recover", "wrong", 1);
    store.deleteAccount("u1");
    const rows = (table: string) => db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE email = 'a@example.com'`).get();
    expect(rows("code_log")).toEqual({ n: 0 });
    expect(rows("code_failures")).toEqual({ n: 0 });
    expect(() => store.deleteAccount("u1")).not.toThrow();
  });

  it("delete everything they own in auth", () => {
    store.createAccount("u1", "A", PROFILE, 0);
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    store.createSession("h1", "u1", 0);
    store.deleteAccount("u1");
    expect(store.account("u1")).toBeNull();
    expect(store.passkey("k1")).toBeNull();
    expect(store.session("h1", 1)).toBeNull();
  });
});

describe("passkeys", () => {
  it("store the public key as bytes and the transports as a list", () => {
    store.addPasskey(
      { id: "k1", userId: "u1", publicKey: new Uint8Array([1, 2, 3]), counter: 4, transports: ["internal"] },
      0,
    );
    const key = store.passkey("k1")!;
    expect([...key.publicKey]).toEqual([1, 2, 3]);
    expect(key).toMatchObject({ userId: "u1", counter: 4, transports: ["internal"] });
    store.passkeyUsed("k1", 9, 5);
    expect(store.passkey("k1")!.counter).toBe(9);
  });

  it("keep what the authenticator said about backup — including no, and nothing", () => {
    const key = { userId: "u1", publicKey: new Uint8Array([1]), counter: 0 };
    store.addPasskey({ ...key, id: "yes", deviceType: "multiDevice", backedUp: true }, 0);
    store.addPasskey({ ...key, id: "no", deviceType: "singleDevice", backedUp: false }, 1);
    store.addPasskey({ ...key, id: "unsaid" }, 2);
    expect(["yes", "no", "unsaid"].map((id) => store.passkey(id))).toMatchObject([
      { deviceType: "multiDevice", backedUp: true },
      { deviceType: "singleDevice", backedUp: false },
      { deviceType: undefined, backedUp: undefined },
    ]);
    expect(store.passkeySummaries("u1").map((k) => k.backedUp)).toEqual([true, false, null]);
  });
});

describe("sessions", () => {
  it("resolve to their account until they expire", () => {
    store.createSession("h1", "u1", 0);
    expect(store.session("h1", 1)?.userId).toBe("u1");
    expect(store.session("h1", SESSION_TTL_MS)).toBeNull();
  });

  // Logged in once per device: a session that keeps being used never expires.
  it("slide forward with use", () => {
    store.createSession("h1", "u1", 0);
    const later = SESSION_TTL_MS - DAY;
    expect(store.session("h1", later)?.userId).toBe("u1");
    expect(store.session("h1", SESSION_TTL_MS + DAY)?.userId).toBe("u1");
  });

  it("can all be revoked, optionally keeping one", () => {
    store.createSession("h1", "u1", 0);
    store.createSession("h2", "u1", 0);
    store.createSession("h3", "u2", 0);
    store.deleteSessionsFor("u1", "h2");
    expect(store.session("h1", 1)).toBeNull();
    expect(store.session("h2", 1)?.userId).toBe("u1");
    store.deleteSessionsFor("u1");
    expect(store.session("h2", 1)).toBeNull();
    expect(store.session("h3", 1)?.userId).toBe("u2");
  });
});

describe("codes", () => {
  it("redeem once, for the account they were issued to", () => {
    store.issueCode("a@example.com", "recover", "u1", "hash", 0);
    expect(store.redeemCode("A@example.com", "recover", "hash", 1)).toEqual({ userId: "u1" });
    expect(store.redeemCode("a@example.com", "recover", "hash", 2)).toBeNull();
  });

  it("don't redeem across purposes", () => {
    store.issueCode("a@example.com", "verify-email", "u1", "hash", 0);
    expect(store.redeemCode("a@example.com", "recover", "hash", 1)).toBeNull();
  });

  it("expire", () => {
    store.issueCode("a@example.com", "recover", "u1", "hash", 0);
    expect(store.redeemCode("a@example.com", "recover", "hash", CODE_TTL_MS)).toBeNull();
  });

  // The email promises ten minutes.
  it("last ten minutes", () => {
    store.issueCode("a@example.com", "recover", "u1", "hash", 0);
    expect(store.redeemCode("a@example.com", "recover", "hash", 10 * 60 * 1000 - 1)).toEqual({ userId: "u1" });
  });

  // Six digits is a million guesses. The cap makes it five.
  it(`die after ${CODE_MAX_ATTEMPTS} wrong guesses, even if the next is right`, () => {
    store.issueCode("a@example.com", "recover", "u1", "hash", 0);
    for (let i = 0; i < CODE_MAX_ATTEMPTS; i++) {
      expect(store.redeemCode("a@example.com", "recover", `wrong${i}`, 1)).toBeNull();
    }
    expect(store.redeemCode("a@example.com", "recover", "hash", 1)).toBeNull();
  });

  it("are replaced by a newer code", () => {
    store.issueCode("a@example.com", "recover", "u1", "old", 0);
    store.issueCode("a@example.com", "recover", "u1", "new", 1);
    expect(store.redeemCode("a@example.com", "recover", "old", 2)).toBeNull();
  });

  // Five guesses per code, five codes an hour, would still be hundreds of
  // guesses a day against one email. Failures count across codes.
  it(`lock the email for a day after ${MAX_CODE_FAILURES} wrong guesses, however many codes`, () => {
    let failures = 0;
    for (let round = 0; failures < MAX_CODE_FAILURES; round++) {
      store.issueCode("a@example.com", "recover", "u1", `real${round}`, round * 61 * 60 * 1000);
      for (let i = 0; i < CODE_MAX_ATTEMPTS && failures < MAX_CODE_FAILURES; i++, failures++) {
        store.redeemCode("a@example.com", "recover", "wrong", round * 61 * 60 * 1000 + 1);
      }
    }
    const later = 5 * 61 * 60 * 1000;
    store.issueCode("a@example.com", "recover", "u1", "right", later);
    expect(store.redeemCode("a@example.com", "recover", "right", later + 1)).toBeNull();
    // A day on, it works again.
    store.issueCode("a@example.com", "recover", "u1", "right", later + DAY);
    expect(store.redeemCode("a@example.com", "recover", "right", later + DAY + 1)).toEqual({ userId: "u1" });
  });

  // Ten guesses at each of many known emails would otherwise add up.
  it(`stop redeeming anywhere after ${MAX_GLOBAL_CODE_FAILURES} wrong guesses a day across every email`, () => {
    for (let i = 0; i < MAX_GLOBAL_CODE_FAILURES; i++) {
      store.issueCode(`e${i}@example.com`, "recover", "u1", "real", 0);
      store.redeemCode(`e${i}@example.com`, "recover", "wrong", 1);
    }
    store.issueCode("fresh@example.com", "recover", "u2", "right", 2);
    expect(store.redeemCode("fresh@example.com", "recover", "right", 3)).toBeNull();
    store.issueCode("fresh@example.com", "recover", "u2", "right", DAY + 2);
    expect(store.redeemCode("fresh@example.com", "recover", "right", DAY + 3)).toEqual({ userId: "u2" });
  });

  // Changing the recovery email must retire a code already sent to the old one.
  it("for recovery die when the account's email changes", () => {
    store.createAccount("u1", "A", PROFILE, 0);
    store.setEmail("u1", "old@example.com");
    store.issueCode("old@example.com", "recover", "u1", "hash", 0);
    store.setEmail("u1", "new@example.com");
    expect(store.redeemCode("old@example.com", "recover", "hash", 1)).toBeNull();
  });

  it(`are capped at ${CODES_PER_HOUR} an hour per email`, () => {
    for (let i = 0; i < CODES_PER_HOUR; i++) {
      expect(store.issueCode("a@example.com", "recover", "u1", `h${i}`, i)).toBe("ok");
    }
    expect(store.issueCode("a@example.com", "recover", "u1", "more", 10)).toBe("rate-limited");
    expect(store.issueCode("b@example.com", "recover", "u2", "other", 10)).toBe("ok");
    expect(store.issueCode("a@example.com", "recover", "u1", "later", 60 * 60 * 1000 + 10)).toBe("ok");
  });

  // A code that only looks sent (someone else's email) spends the same cap,
  // or the cap would tell the two apart.
  it("count requests that send nothing against the same cap", () => {
    for (let i = 0; i < CODES_PER_HOUR; i++) expect(store.noteCodeRequest("A@example.com", i)).toBe("ok");
    expect(store.noteCodeRequest("a@example.com", 10)).toBe("rate-limited");
    expect(store.issueCode("a@example.com", "recover", "u1", "h", 10)).toBe("rate-limited");
  });
});

describe("verification codes", () => {
  // Two accounts after one address each get their own code: one can't
  // replace — and so burn — the other's.
  it("belong to the account that asked", () => {
    store.issueCode("e@example.com", "verify-email", "u1", "mine", 0);
    store.issueCode("e@example.com", "verify-email", "u2", "theirs", 1);
    expect(store.redeemCode("e@example.com", "verify-email", "theirs", 2, "u1")).toBeNull();
    expect(store.redeemCode("e@example.com", "verify-email", "mine", 3, "u1")).toEqual({ userId: "u1" });
    expect(store.redeemCode("e@example.com", "verify-email", "theirs", 4, "u2")).toEqual({ userId: "u2" });
  });

  // Asking to verify an address can't spend that address's recovery
  // allowance, or someone else's.
  it(`are capped at ${CODES_PER_HOUR} an hour per account, apart from recovery's cap`, () => {
    for (let i = 0; i < CODES_PER_HOUR; i++) {
      expect(store.noteCodeRequest(`x${i}@example.com`, i, "verify-email", "u1")).toBe("ok");
    }
    expect(store.issueCode("y@example.com", "verify-email", "u1", "h", 10)).toBe("rate-limited");
    expect(store.issueCode("x0@example.com", "verify-email", "u2", "h", 10)).toBe("ok");
    expect(store.issueCode("x0@example.com", "recover", "u3", "h", 10)).toBe("ok");
  });

  // Wrong guesses at your own verification codes can't pause recovery for
  // everyone (or for anyone).
  it("don't count towards recovery's caps", () => {
    for (let u = 0; u < MAX_GLOBAL_CODE_FAILURES / MAX_CODE_FAILURES + 1; u++) {
      for (let i = 0; i < MAX_CODE_FAILURES; i += CODE_MAX_ATTEMPTS) {
        store.issueCode("victim@example.com", "verify-email", `u${u}`, "real", i);
        for (let j = 0; j < CODE_MAX_ATTEMPTS; j++) store.redeemCode("victim@example.com", "verify-email", "x", i + 1, `u${u}`);
      }
    }
    store.issueCode("victim@example.com", "recover", "owner", "right", 2);
    expect(store.redeemCode("victim@example.com", "recover", "right", 3)).toEqual({ userId: "owner" });
  });

  it(`lock the account's verifying for a day after ${MAX_CODE_FAILURES} wrong guesses`, () => {
    for (let i = 0; i < MAX_CODE_FAILURES; i += CODE_MAX_ATTEMPTS) {
      store.issueCode(`e${i}@example.com`, "verify-email", "u1", "real", i);
      for (let j = 0; j < CODE_MAX_ATTEMPTS; j++) store.redeemCode(`e${i}@example.com`, "verify-email", "x", i + 1, "u1");
    }
    store.issueCode("new@example.com", "verify-email", "u1", "right", 20);
    expect(store.redeemCode("new@example.com", "verify-email", "right", 21, "u1")).toBeNull();
    store.issueCode("new@example.com", "verify-email", "u1", "right", DAY + 21);
    expect(store.redeemCode("new@example.com", "verify-email", "right", DAY + 22, "u1")).toEqual({ userId: "u1" });
  });
});

describe("signing up and recovering", () => {
  const key = { id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 };

  it("creates the account and its passkey together, or neither", () => {
    expect(store.createAccountWithPasskey("u1", "A", PROFILE, key, 0)).toMatchObject({ id: "u1" });
    expect(store.createAccountWithPasskey("u2", "B", PROFILE, { ...key, userId: "u2" }, 0)).toBe("taken");
    expect(store.account("u2")).toBeNull();
    expect(store.passkey("k1")!.userId).toBe("u1");
  });

  it("revokes every session and passkey at once", () => {
    store.createAccountWithPasskey("u1", "A", PROFILE, key, 0);
    store.createSession("s1", "u1", 0);
    store.revokeEverything("u1");
    expect(store.passkeysFor("u1")).toEqual([]);
    expect(store.session("s1", 1)).toBeNull();
  });
});

describe("passkeys an account can see", () => {
  it("list without key material, with when each was last used", () => {
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0, deviceType: "multiDevice", backedUp: true }, 10);
    store.addPasskey({ id: "k2", userId: "u1", publicKey: new Uint8Array([2]), counter: 0 }, 20);
    store.passkeyUsed("k1", 1, 30);
    expect(store.passkeySummaries("u1")).toEqual([
      { id: "k1", createdAt: 10, lastUsedAt: 30, deviceType: "multiDevice", backedUp: true },
      { id: "k2", createdAt: 20, lastUsedAt: null, deviceType: null, backedUp: null },
    ]);
  });

  it("can only be removed by their own account", () => {
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    store.addPasskey({ id: "k2", userId: "u1", publicKey: new Uint8Array([2]), counter: 0 }, 0);
    expect(store.deletePasskey("u2", "k1")).toBe("missing");
    expect(store.passkey("k1")).not.toBeNull();
    expect(store.deletePasskey("u1", "k1")).toBe("removed");
    expect(store.passkey("k1")).toBeNull();
  });

  // Checked in the same step as the delete: two removals at once can't
  // each see two keys and leave none.
  it("never removes the last one", () => {
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    expect(store.deletePasskey("u1", "k1")).toBe("last");
    expect(store.passkey("k1")).not.toBeNull();
  });

  // The key may have gone with a lost device; so does every session but the
  // one removing it.
  it("signs out every other session when one is removed", () => {
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    store.addPasskey({ id: "k2", userId: "u1", publicKey: new Uint8Array([2]), counter: 0 }, 0);
    store.createSession("here", "u1", 0);
    store.createSession("lost", "u1", 0);
    store.createSession("theirs", "u2", 0);
    store.deletePasskey("u1", "k2", "here");
    expect(store.session("here", 1)).not.toBeNull();
    expect(store.session("lost", 1)).toBeNull();
    expect(store.session("theirs", 1)).not.toBeNull();
  });

  // Two sign-ins landing out of order can't wind the counter back.
  it("only moves a counter forward", () => {
    store.addPasskey({ id: "k1", userId: "u1", publicKey: new Uint8Array([1]), counter: 0 }, 0);
    store.passkeyUsed("k1", 5, 1);
    store.passkeyUsed("k1", 3, 2);
    expect(store.passkey("k1")!.counter).toBe(5);
  });
});

describe("step-up", () => {
  it("starts a session verified, and re-verifies it on demand", () => {
    store.createSession("h1", "u1", 100);
    expect(store.session("h1", 101)).toEqual({ userId: "u1", verifiedAt: 100 });
    store.markVerified("h1", 500);
    expect(store.session("h1", 501)?.verifiedAt).toBe(500);
  });
});

describe("pruning", () => {
  // The daily sweep must not hand a guesser a fresh day, or a spammer a
  // fresh hour.
  it("keeps the lockouts and caps still in force", () => {
    for (let round = 0; round < 2; round++) {
      store.issueCode("a@example.com", "recover", "u1", `real${round}`, round);
      for (let i = 0; i < CODE_MAX_ATTEMPTS; i++) store.redeemCode("a@example.com", "recover", "wrong", round);
    }
    for (let i = 2; i < CODES_PER_HOUR; i++) store.issueCode("a@example.com", "recover", "u1", `real${i}`, i);
    store.prune(10);
    expect(store.issueCode("a@example.com", "recover", "u1", "right", 10)).toBe("rate-limited");
    store.issueCode("a@example.com", "verify-email", "u1", "right", 2 * 60 * 60 * 1000);
    store.prune(2 * 60 * 60 * 1000);
    expect(store.redeemCode("a@example.com", "verify-email", "right", 2 * 60 * 60 * 1000)).toBeNull();
  });

  it("drops what has expired and keeps what hasn't", () => {
    store.createChallenge("old", "login", null, 0);
    store.createSession("h-old", "u1", 0);
    store.issueCode("a@example.com", "recover", "u1", "hash", 0);
    const later = SESSION_TTL_MS + 1;
    store.createSession("h-new", "u1", later);
    store.prune(later);
    expect(store.consumeChallenge("old", "login", 0)).toBeNull();
    expect(store.session("h-old", 0)).toBeNull();
    expect(store.redeemCode("a@example.com", "recover", "hash", 0)).toBeNull();
    expect(store.session("h-new", later)?.userId).toBe("u1");
  });
});

// A database from the first release (Rampset's) must open in place: same
// accounts, same passkeys, same sessions — signed in, just not fresh.
describe("a database from schema version 1", () => {
  function v1(): DatabaseSync {
    const db = new DatabaseSync(":memory:");
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, profile TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT, created_at INTEGER NOT NULL);
      CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);`);
    db.prepare(`INSERT INTO users VALUES ('u1', 'Isaac', 'i@example.com', '{"unit":"kg"}', 0)`).run();
    db.prepare(`INSERT INTO passkeys VALUES ('k1', 'u1', ?, 3, '["internal"]', 0)`).run(new Uint8Array([9, 8]));
    db.prepare(`INSERT INTO sessions VALUES ('h1', 'u1', ${SESSION_TTL_MS}, 0)`).run();
    return db;
  }

  it("upgrades without losing anyone", () => {
    const db = v1();
    const upgraded = new AuthStore(memorySql(db));
    expect(upgraded.account("u1")).toEqual({ id: "u1", name: "Isaac", email: "i@example.com", profile: { unit: "kg" } });
    expect([...upgraded.passkey("k1")!.publicKey]).toEqual([9, 8]);
    expect(upgraded.session("h1", 1)).toEqual({ userId: "u1", verifiedAt: 0 });
    // Opening it again is a no-op, not a second ALTER.
    expect(() => new AuthStore(memorySql(db))).not.toThrow();
    expect(db.prepare(`SELECT value FROM durable_auth_meta WHERE key = 'schema'`).get()).toEqual({ value: SCHEMA_VERSION });
  });

  // Codes, requests and failures in flight carry over the codes table's
  // rebuild.
  it("keeps outstanding codes through the upgrade", () => {
    const db = v1();
    db.exec(`CREATE TABLE codes (email TEXT NOT NULL, purpose TEXT NOT NULL, user_id TEXT NOT NULL, code_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, purpose))`);
    db.prepare(`INSERT INTO codes VALUES ('i@example.com', 'recover', 'u1', 'hash', ?, 0)`).run(CODE_TTL_MS);
    const upgraded = new AuthStore(memorySql(db));
    expect(upgraded.redeemCode("i@example.com", "recover", "hash", 1)).toEqual({ userId: "u1" });
  });

  // A migration that fails part-way must leave nothing half-done, or the
  // next start re-runs the ALTERs that did land, fails on them, and the DO
  // never starts again.
  it("rolls a failed upgrade back whole, so it can run again", () => {
    const db = v1();
    new AuthStore(memorySql(db)); // up to date…
    db.prepare(`UPDATE durable_auth_meta SET value = 2 WHERE key = 'schema'`).run(); // …but claims 2,
    // with the rebuilt codes table missing and one late column already there.
    db.exec(`DROP TABLE codes; CREATE TABLE codes (email TEXT NOT NULL, purpose TEXT NOT NULL, user_id TEXT NOT NULL,
      code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, purpose))`);
    // The rebuild runs first, then an ALTER that fails: the column exists.
    const keyColumns = () => (db.prepare(`PRAGMA table_info(codes)`).all() as { pk: number }[]).filter((c) => c.pk > 0).length;
    expect(() => new AuthStore(memorySql(db), memoryTransaction(db))).toThrow();
    expect(keyColumns()).toBe(2); // the rebuild was rolled back with it
    expect(db.prepare(`SELECT value FROM durable_auth_meta WHERE key = 'schema'`).get()).toEqual({ value: 2 });
  });

  // Roll a deploy back and forward again: the older code must not record its
  // older version, or the upgrade re-runs its ALTERs and the DO never starts.
  it("survives older code opening it, then newer code again", () => {
    const db = v1();
    new AuthStore(memorySql(db));
    db.prepare(`UPDATE durable_auth_meta SET value = ? WHERE key = 'schema'`).run(SCHEMA_VERSION + 1); // "newer"
    expect(() => new AuthStore(memorySql(db))).not.toThrow();
    expect(db.prepare(`SELECT value FROM durable_auth_meta WHERE key = 'schema'`).get()).toEqual({ value: SCHEMA_VERSION + 1 });
  });
});
