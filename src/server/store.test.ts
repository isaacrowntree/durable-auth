import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { memorySql } from "../../test/sqlite";
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
} from "./store";

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
    expect(store.deletePasskey("u2", "k1")).toBe(false);
    expect(store.passkey("k1")).not.toBeNull();
    expect(store.deletePasskey("u1", "k1")).toBe(true);
    expect(store.passkey("k1")).toBeNull();
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
