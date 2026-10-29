/** The store's caps and single-use rules, against random histories.
 *
 * store.test.ts shows each rule once, on the path someone thought of. These
 * throw long, interleaved sequences at the real store (node:sqlite) — codes
 * issued, guessed, replayed across purposes and emails, time jumping past
 * every TTL and window — and check two things after every step:
 *
 * - the store answers exactly what a small in-memory model of the rules
 *   answers, so the SQL agrees with the spec on every path, not just one;
 * - the history so far never breaks a security invariant (a code redeemed
 *   twice, after expiry, past its guesses; a cap exceeded).
 *
 * The model decides which wrong guesses count (one aimed at a live code by an
 * email that isn't locked out); the store must agree with it on every answer,
 * so a store that counted differently would diverge as soon as it mattered.
 * Invariants that don't need that judgement are read off the history alone. */

import { describe, it, expect } from "vitest";
import fc from "fast-check";
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
  SESSION_TTL_MS,
  type ChallengePurpose,
  type CodePurpose,
} from "./store";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** Enough to find a broken boundary, small enough that `npm test` stays fast. */
const RUNS = 150;

/** Time only moves forward, as Date.now() does in a Durable Object. Mostly
 * in steps short next to `typical`, so things stay alive long enough to be
 * guessed at; sometimes exactly on, or one ms either side of, a TTL or window,
 * which lands on its edge when it follows the event that started it. */
const wait = (typical: number, ...edges: number[]) =>
  fc.record({
    kind: fc.constant("wait" as const),
    ms: fc.oneof(
      { weight: 3, arbitrary: fc.integer({ min: 0, max: typical }) },
      { weight: 1, arbitrary: fc.constantFrom(...edges.flatMap((e) => [e - 1, e, e + 1])) },
    ),
  });

const within = (log: number[], now: number, window: number) => log.filter((at) => at > now - window).length;

// ---- one-time codes ---------------------------------------------------------

/** Three people, some with more than one way of typing their address. */
const EMAILS = [["ann@example.com", "Ann@Example.COM"], ["bob@example.com", "  bob@example.com "], ["cy@example.com"]];
const PURPOSES: CodePurpose[] = ["recover", "verify-email"];
const norm = (who: number) => EMAILS[who]![0]!;

interface ModelCode {
  userId: string;
  hash: string;
  expiresAt: number;
  attempts: number;
}

type Outcome = "redeemed" | "locked" | "none" | "dead" | "wrong";

/** Where a code lives: one recovery code per email; one verification code
 * per email per account asking. */
const slot = (email: string, purpose: CodePurpose, userId: string) =>
  purpose === "recover" ? `${email}|recover` : `${email}|verify-email|${userId}`;

/** What a cap counts against: recovery, the email; verification, the account. */
const budget = (email: string, purpose: CodePurpose, userId: string) =>
  purpose === "recover" ? `recover|${email}` : `verify|${userId}`;

/** The rules for codes as the docs state them, over plain arrays. */
class CodeModel {
  codes = new Map<string, ModelCode>();
  log: { key: string; at: number }[] = [];
  failures: { key: string; at: number }[] = [];

  issue(email: string, purpose: CodePurpose, userId: string, hash: string, now: number): "ok" | "rate-limited" {
    for (const [k, c] of this.codes) if (c.expiresAt <= now) this.codes.delete(k);
    this.log = this.log.filter((l) => l.at > now - HOUR);
    const key = budget(email, purpose, userId);
    if (this.log.filter((l) => l.key === key).length >= CODES_PER_HOUR) return "rate-limited";
    this.log.push({ key, at: now });
    this.codes.set(slot(email, purpose, userId), { userId, hash, expiresAt: now + CODE_TTL_MS, attempts: 0 });
    return "ok";
  }

  redeem(
    email: string,
    purpose: CodePurpose,
    hash: string,
    now: number,
    userId: string,
  ): { result: { userId: string } | null; outcome: Outcome; code?: string } {
    this.failures = this.failures.filter((f) => f.at > now - DAY);
    const counted = budget(email, purpose, userId);
    const mine = this.failures.filter((f) => f.key === counted).length;
    // The global cap is recovery's alone.
    const everyone = this.failures.filter((f) => f.key.startsWith("recover|")).length;
    if (mine >= MAX_CODE_FAILURES || (purpose === "recover" && everyone >= MAX_GLOBAL_CODE_FAILURES)) {
      return { result: null, outcome: "locked" };
    }
    const key = slot(email, purpose, userId);
    const code = this.codes.get(key);
    if (!code) return { result: null, outcome: "none" };
    if (code.expiresAt <= now || code.attempts >= CODE_MAX_ATTEMPTS) {
      this.codes.delete(key);
      return { result: null, outcome: "dead" };
    }
    if (code.hash !== hash) {
      this.failures.push({ key: counted, at: now });
      code.attempts++;
      return { result: null, outcome: "wrong", code: code.hash };
    }
    this.codes.delete(key);
    return { result: { userId: code.userId }, outcome: "redeemed", code: code.hash };
  }
}

const codeOp = fc.oneof(
  {
    weight: 3,
    arbitrary: fc.record({
      kind: fc.constant("issue" as const),
      who: fc.nat(EMAILS.length - 1),
      spelling: fc.nat(1),
      purpose: fc.constantFrom(...PURPOSES),
      // Which account asks for a verification code: anyone may ask to verify
      // any address, so two accounts can be after the same one.
      by: fc.nat(2),
    }),
  },
  {
    weight: 5,
    arbitrary: fc.record({
      kind: fc.constant("redeem" as const),
      who: fc.nat(EMAILS.length - 1),
      spelling: fc.nat(1),
      purpose: fc.constantFrom(...PURPOSES),
      // "right" is the latest code sent to this email for this purpose — a
      // replay once it's used. The others are what an attacker might hold:
      // an older code, the code for the other purpose, another email's code.
      guess: fc.constantFrom("right", "right", "wrong", "stale", "other-purpose", "other-email", "other-account"),
      by: fc.nat(2),
      // Guessers guess in bursts; one at a time rarely reaches a lockout.
      times: fc.integer({ min: 1, max: 6 }),
    }),
  },
  { weight: 2, arbitrary: wait(2 * 60 * 1000, CODE_TTL_MS, HOUR, DAY) },
);

type CodeOp = typeof codeOp extends fc.Arbitrary<infer T> ? T : never;

interface Issued {
  email: string;
  purpose: CodePurpose;
  at: number;
  userId: string;
}

/** Run a history against store and model together, checking as it goes.
 * `seed` lets a caller put failures on the books first. */
function runCodes(ops: CodeOp[], seed?: (db: DatabaseSync, model: CodeModel) => void): void {
  const db = new DatabaseSync(":memory:");
  const store = new AuthStore(memorySql(db));
  const model = new CodeModel();
  seed?.(db, model);
  let now = 0;
  let n = 0;

  const issued = new Map<string, Issued>();
  const sent = new Map<string, string[]>(); // slot → hashes in issue order
  const okIssues = new Map<string, number[]>(); // budget → when
  const redeemed = new Set<string>();
  const wrongOn = new Map<string, number>(); // code → counted wrong guesses
  const failures = new Map<string, number[]>(); // budget → counted wrong guesses' times
  const allFailures: number[] = [...model.failures.map((f) => f.at)]; // recovery's
  /** Who asks: the email's owner recovers it; anyone may verify it. */
  const asker = (op: { who: number; purpose: CodePurpose; by: number }) =>
    op.purpose === "recover" ? `u${op.who}` : `u${op.by}`;

  for (const op of ops) {
    if (op.kind === "wait") {
      now += op.ms;
      continue;
    }
    const email = norm(op.who);
    const typed = EMAILS[op.who]![op.spelling] ?? email;

    if (op.kind === "issue") {
      const hash = `h${++n}`;
      const userId = asker(op);
      const got = store.issueCode(typed, op.purpose, userId, hash, now);
      expect(got).toBe(model.issue(email, op.purpose, userId, hash, now));
      if (got === "ok") {
        issued.set(hash, { email, purpose: op.purpose, at: now, userId });
        const at = slot(email, op.purpose, userId);
        sent.set(at, [...(sent.get(at) ?? []), hash]);
        const counted = budget(email, op.purpose, userId);
        const times = [...(okIssues.get(counted) ?? []), now];
        okIssues.set(counted, times);
        // However often it's asked, no email gets more recovery codes than the
        // cap an hour, and no account more verification codes.
        expect(within(times, now, HOUR)).toBeLessThanOrEqual(CODES_PER_HOUR);
      }
      continue;
    }

    const userId = asker(op);
    const latest = (e: string, p: CodePurpose, u = userId) => sent.get(slot(e, p, u))?.at(-1);
    const other = op.purpose === "recover" ? "verify-email" : "recover";
    const guess =
      {
        right: latest(email, op.purpose),
        wrong: undefined,
        stale: sent.get(slot(email, op.purpose, userId))?.at(-2),
        "other-purpose": latest(email, other, other === "recover" ? `u${op.who}` : `u${op.by}`),
        "other-email": latest(norm((op.who + 1) % EMAILS.length), op.purpose),
        // Another account's verification code for the same address.
        "other-account": latest(email, op.purpose, `u${(op.by + 1) % 3}`),
      }[op.guess] ?? "not-a-code";

    const counted = budget(email, op.purpose, userId);
    for (let i = 0; i < op.times; i++) {
      const got = store.redeemCode(typed, op.purpose, guess, now, op.purpose === "recover" ? null : userId);
      const expected = model.redeem(email, op.purpose, guess, now, userId);
      expect(got).toEqual(expected.result);

      if (expected.outcome === "wrong") {
        const code = expected.code!;
        wrongOn.set(code, (wrongOn.get(code) ?? 0) + 1);
        failures.set(counted, [...(failures.get(counted) ?? []), now]);
        if (op.purpose === "recover") allFailures.push(now);
        expect(wrongOn.get(code)).toBeLessThanOrEqual(CODE_MAX_ATTEMPTS);
        expect(within(failures.get(counted)!, now, DAY)).toBeLessThanOrEqual(MAX_CODE_FAILURES);
        expect(within(allFailures, now, DAY)).toBeLessThanOrEqual(MAX_GLOBAL_CODE_FAILURES);
      }

      if (got) {
        // Read off the history alone: what was sent, to whom, when.
        const code = issued.get(guess);
        expect(code, "redeemed a hash that was never sent").toBeDefined();
        expect(code!.email).toBe(email);
        expect(code!.purpose).toBe(op.purpose);
        expect(got.userId).toBe(code!.userId);
        // A verification code only ever comes back for the account it went to.
        if (op.purpose === "verify-email") expect(got.userId).toBe(userId);
        expect(guess, "redeemed a code a newer one replaced").toBe(latest(email, op.purpose));
        expect(redeemed.has(guess), "redeemed a code twice").toBe(false);
        expect(now).toBeLessThan(code!.at + CODE_TTL_MS);
        redeemed.add(guess);
        // And the guesses the model counted against it.
        expect(wrongOn.get(guess) ?? 0).toBeLessThan(CODE_MAX_ATTEMPTS);
        expect(within(failures.get(counted) ?? [], now, DAY)).toBeLessThan(MAX_CODE_FAILURES);
        if (op.purpose === "recover") expect(within(allFailures, now, DAY)).toBeLessThan(MAX_GLOBAL_CODE_FAILURES);
      }
    }
  }
}

describe("codes, over random histories", () => {
  it("agree with the model and never break a cap", () => {
    fc.assert(
      fc.property(fc.array(codeOp, { minLength: 1, maxLength: 100, size: "max" }), (ops) => runCodes(ops)),
      { numRuns: RUNS },
    );
  });

  // A thousand failures don't fit in a generated history, so put most of
  // them on the books first: the last few are what the random ops spend.
  // Written straight into the table — a thousand redeemCode calls a run is
  // slow, and store.test.ts already reaches the cap that way.
  it("stop recovery everywhere at the global cap, and start again a day later", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 12 }), fc.array(codeOp, { minLength: 1, maxLength: 60, size: "max" }), (headroom, ops) =>
        runCodes(ops, (db, model) => {
          const seeded = MAX_GLOBAL_CODE_FAILURES - headroom;
          db.prepare(
            `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
             INSERT INTO code_failures (email, at) SELECT 'seed' || i || '@example.com', 0 FROM n`,
          ).run(seeded);
          for (let i = 0; i < seeded; i++) model.failures.push({ key: `recover|seed${i}@example.com`, at: 0 });
        }),
      ),
      { numRuns: RUNS },
    );
  });
});

// ---- challenges ---------------------------------------------------------------

const CHALLENGE_PURPOSES: ChallengePurpose[] = ["register", "login", "add-passkey", "reauth"];

const challengeOp = fc.oneof(
  {
    weight: 2,
    arbitrary: fc.record({
      kind: fc.constant("create" as const),
      purpose: fc.constantFrom(...CHALLENGE_PURPOSES),
      user: fc.option(fc.nat(2), { nil: null }),
    }),
  },
  {
    weight: 3,
    arbitrary: fc.record({
      kind: fc.constant("consume" as const),
      // Which challenge, counting back from the newest; past the end is one
      // that was never issued.
      back: fc.nat(6),
      purpose: fc.constantFrom(...CHALLENGE_PURPOSES),
    }),
  },
  { weight: 1, arbitrary: wait(60 * 1000, CHALLENGE_TTL_MS) },
);

describe("challenges, over random histories", () => {
  it("are consumed at most once, for their purpose, before they expire", () => {
    fc.assert(
      fc.property(fc.array(challengeOp, { minLength: 1, maxLength: 60, size: "max" }), (ops) => {
        const store = new AuthStore(memorySql());
        const model = new Map<string, { purpose: ChallengePurpose; userId: string | null; name: string | null; expiresAt: number }>();
        const created: { id: string; purpose: ChallengePurpose; userId: string | null; name: string | null; at: number }[] = [];
        const seen = new Set<string>();
        let now = 0;

        for (const op of ops) {
          if (op.kind === "wait") {
            now += op.ms;
          } else if (op.kind === "create") {
            const id = `c${created.length}`;
            const userId = op.user === null ? null : `u${op.user}`;
            const name = op.purpose === "register" ? `name-${id}` : null;
            store.createChallenge(id, op.purpose, userId, now, name);
            for (const [k, c] of model) if (c.expiresAt <= now) model.delete(k);
            model.set(id, { purpose: op.purpose, userId, name, expiresAt: now + CHALLENGE_TTL_MS });
            created.push({ id, purpose: op.purpose, userId, name, at: now });
          } else {
            const target = created[created.length - 1 - op.back];
            const id = target?.id ?? "never-issued";
            const got = store.consumeChallenge(id, op.purpose, now);

            const row = model.get(id);
            model.delete(id);
            const expected = row && row.purpose === op.purpose && row.expiresAt > now ? { userId: row.userId, name: row.name } : null;
            expect(got).toEqual(expected);

            if (got) {
              // First sight burns it, so a success is always the first try.
              expect(seen.has(id)).toBe(false);
              expect(target!.purpose).toBe(op.purpose);
              expect(now).toBeLessThan(target!.at + CHALLENGE_TTL_MS);
              expect(got).toEqual({ userId: target!.userId, name: target!.name });
            }
            seen.add(id);
          }
        }
      }),
      { numRuns: RUNS },
    );
  });
});

// ---- sessions -------------------------------------------------------------------

const sessionOp = fc.oneof(
  { weight: 2, arbitrary: fc.record({ kind: fc.constant("create" as const), user: fc.nat(2) }) },
  { weight: 3, arbitrary: fc.record({ kind: fc.constant("resolve" as const), back: fc.nat(5) }) },
  { weight: 1, arbitrary: fc.record({ kind: fc.constant("verify" as const), back: fc.nat(5) }) },
  { weight: 1, arbitrary: fc.record({ kind: fc.constant("signOut" as const), back: fc.nat(5) }) },
  {
    weight: 1,
    arbitrary: fc.record({
      kind: fc.constant("signOutOthers" as const),
      user: fc.nat(2),
      // The session to keep — sometimes another user's, sometimes none.
      keep: fc.option(fc.nat(5), { nil: null }),
    }),
  },
  { weight: 2, arbitrary: wait(2 * DAY, DAY, SESSION_TTL_MS) },
);

interface ModelSession {
  userId: string;
  expiresAt: number;
  lastSeen: number;
  verifiedAt: number;
}

describe("sessions, over random histories", () => {
  it("never resolve once expired or revoked, and signing out others keeps exactly one", () => {
    fc.assert(
      fc.property(fc.array(sessionOp, { minLength: 1, maxLength: 60, size: "max" }), (ops) => {
        const store = new AuthStore(memorySql());
        const model = new Map<string, ModelSession>();
        const tokens: { hash: string; userId: string }[] = [];
        // From the history alone: when each session was last used, and when
        // it last proved its user.
        const touched = new Map<string, number>();
        const verified = new Map<string, number>();
        const revoked = new Set<string>();
        let now = 0;

        const pick = (back: number) => tokens[tokens.length - 1 - back];

        const resolve = (hash: string) => {
          const got = store.session(hash, now);
          const row = model.get(hash);
          let expected = null;
          if (row && row.expiresAt <= now) model.delete(hash);
          else if (row) {
            if (now - row.lastSeen > DAY) Object.assign(row, { lastSeen: now, expiresAt: now + SESSION_TTL_MS });
            expected = { userId: row.userId, verifiedAt: row.verifiedAt };
          }
          expect(got).toEqual(expected);
          if (got) {
            expect(revoked.has(hash), "a revoked session resolved").toBe(false);
            expect(now - touched.get(hash)!, "resolved after a full TTL unused").toBeLessThan(SESSION_TTL_MS);
            expect(got.userId).toBe(tokens.find((t) => t.hash === hash)!.userId);
            expect(got.verifiedAt).toBe(verified.get(hash));
            touched.set(hash, now);
          }
          return got;
        };

        for (const op of ops) {
          switch (op.kind) {
            case "wait":
              now += op.ms;
              break;
            case "create": {
              const hash = `t${tokens.length}`;
              store.createSession(hash, `u${op.user}`, now);
              for (const [k, s] of model) if (s.expiresAt <= now) model.delete(k);
              model.set(hash, { userId: `u${op.user}`, expiresAt: now + SESSION_TTL_MS, lastSeen: now, verifiedAt: now });
              tokens.push({ hash, userId: `u${op.user}` });
              touched.set(hash, now);
              verified.set(hash, now);
              break;
            }
            case "resolve":
              resolve(pick(op.back)?.hash ?? "never-issued");
              break;
            case "verify": {
              const t = pick(op.back);
              if (!t) break;
              store.markVerified(t.hash, now);
              const row = model.get(t.hash);
              if (row) row.verifiedAt = now;
              verified.set(t.hash, now);
              break;
            }
            case "signOut": {
              const t = pick(op.back);
              if (!t) break;
              store.deleteSession(t.hash);
              model.delete(t.hash);
              revoked.add(t.hash);
              break;
            }
            case "signOutOthers": {
              const userId = `u${op.user}`;
              const keep = op.keep === null ? null : (pick(op.keep)?.hash ?? null);
              store.deleteSessionsFor(userId, keep);
              for (const [k, s] of model) if (s.userId === userId && k !== keep) model.delete(k);
              for (const t of tokens) if (t.userId === userId && t.hash !== keep) revoked.add(t.hash);
              // Straight after: of this user's sessions, only the kept one
              // can still answer.
              for (const t of tokens.filter((t) => t.userId === userId)) {
                if (resolve(t.hash)) expect(t.hash).toBe(keep);
              }
              break;
            }
          }
        }
      }),
      { numRuns: RUNS },
    );
  });
});
