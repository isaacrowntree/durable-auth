/** Accounts, passkeys, sessions and one-time codes — the state behind sign-in.
 *
 * Pure logic over a minimal SQL interface: the Durable Object hands it
 * `ctx.storage.sql`, tests hand it node:sqlite. Every method is synchronous —
 * a Durable Object runs one request at a time, so a read followed by a write
 * here is atomic without a transaction, which is exactly what "check the
 * code, then burn it" and "check the challenge, then consume it" need.
 *
 * Secrets never land here in the clear: session tokens and codes arrive
 * already hashed (see crypto.ts). */

/** The slice of a Durable Object's SqlStorage this needs. */
export interface Sql {
  exec(query: string, ...bindings: unknown[]): { toArray(): Record<string, unknown>[] };
}

/** Whatever the app keeps on an account besides its name and email — units,
 * a theme, a plan. Stored as JSON; `createAuth({ parseProfile })` validates it. */
export type Profile = Record<string, unknown>;

export interface AccountView<P extends Profile = Profile> {
  id: string;
  name: string;
  /** Verified recovery email, or null when none has been added. */
  email: string | null;
  profile: P;
}

export interface StoredPasskey {
  id: string;
  userId: string;
  publicKey: Uint8Array;
  counter: number;
  transports?: string[];
  /** "multiDevice" keys sync (iCloud Keychain, Google Password Manager);
   * "singleDevice" ones live and die with one authenticator. */
  deviceType?: "singleDevice" | "multiDevice";
  backedUp?: boolean;
}

/** What an account may see of its own passkeys — never the key material. */
export interface PasskeySummary {
  id: string;
  createdAt: number;
  lastUsedAt: number | null;
  deviceType: "singleDevice" | "multiDevice" | null;
  backedUp: boolean | null;
}

export interface SessionInfo {
  userId: string;
  /** When this session last proved its user with a passkey or an emailed
   * code. Sensitive actions want this to be recent. */
  verifiedAt: number;
}

export type ChallengePurpose = "register" | "login" | "add-passkey" | "reauth";
export type CodePurpose = "recover" | "verify-email";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
export const SESSION_TTL_MS = 365 * DAY;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const CODE_TTL_MS = 10 * 60 * 1000;
export const CODE_MAX_ATTEMPTS = 5;
/** Codes issued per email per hour — a cap on how often we'll email anyone,
 * whoever is asking. */
export const CODES_PER_HOUR = 5;
/** Wrong guesses per email per day, across every code issued to it. Past
 * this, the email can't be used to recover for a day. */
export const MAX_CODE_FAILURES = 10;
/** Wrong guesses a day across every email. The per-email caps don't stop
 * ten guesses at each of a hundred thousand known emails; this does, at the
 * price that a flood of wrong guesses pauses recovery for everyone until it
 * ages out. Put Turnstile and rate limits in front so it never comes to that. */
export const MAX_GLOBAL_CODE_FAILURES = 1000;

/** Version 1 is the schema as first shipped; later versions are ALTERs on top
 * (MIGRATIONS), so a database from any earlier release opens in place. */
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    profile TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL,
    transports TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(user_id)`,
  `CREATE TABLE IF NOT EXISTS challenges (
    challenge TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    user_id TEXT,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)`,
  `CREATE TABLE IF NOT EXISTS codes (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email, purpose)
  )`,
  `CREATE TABLE IF NOT EXISTS code_log (
    email TEXT NOT NULL,
    at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS code_log_email ON code_log(email, at)`,
  `CREATE TABLE IF NOT EXISTS code_failures (
    email TEXT NOT NULL,
    at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS code_failures_email ON code_failures(email, at)`,
  `CREATE TABLE IF NOT EXISTS durable_auth_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
  )`,
];

/** MIGRATIONS[i] takes the schema from version i + 1 to i + 2. Append only. */
const MIGRATIONS: string[][] = [
  [
    // Sessions remember when they last proved their user, for step-up.
    // Existing sessions start stale: their next sensitive action asks again.
    `ALTER TABLE sessions ADD COLUMN verified_at INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE passkeys ADD COLUMN last_used_at INTEGER`,
    `ALTER TABLE passkeys ADD COLUMN device_type TEXT`,
    `ALTER TABLE passkeys ADD COLUMN backed_up INTEGER`,
    // The name a sign-up was approved under, so the verify step can't swap it.
    `ALTER TABLE challenges ADD COLUMN name TEXT`,
    `CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)`,
    `CREATE INDEX IF NOT EXISTS code_failures_at ON code_failures(at)`,
  ],
];

export const SCHEMA_VERSION = MIGRATIONS.length + 1;

interface UserRow {
  id: string;
  name: string;
  email: string | null;
  profile: string;
}

interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: ArrayBuffer | Uint8Array;
  counter: number;
  transports: string | null;
  device_type: string | null;
  backed_up: number | null;
}

const PASSKEY_COLUMNS = `id, user_id, public_key, counter, transports, device_type, backed_up`;

export class AuthStore {
  constructor(private readonly sql: Sql) {
    for (const stmt of SCHEMA) sql.exec(stmt);
    this.migrate();
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql.exec(query, ...bindings).toArray() as T[];
  }

  /** Bring an older database up to SCHEMA_VERSION. A newer one is left as it
   * is — migrations only add, so older code runs on it, and recording the
   * older version would make the next upgrade re-run its ALTERs and fail. */
  private migrate(): void {
    const [row] = this.rows<{ value: number }>(`SELECT value FROM durable_auth_meta WHERE key = 'schema'`);
    const from = row?.value ?? 1;
    if (from >= SCHEMA_VERSION) return;
    for (let version = from; version < SCHEMA_VERSION; version++) {
      for (const stmt of MIGRATIONS[version - 1]!) this.sql.exec(stmt);
    }
    this.sql.exec(`INSERT OR REPLACE INTO durable_auth_meta (key, value) VALUES ('schema', ?)`, SCHEMA_VERSION);
  }

  /** Drop everything past its expiry. Each table is also pruned as it's
   * written, so this is only for a scheduled sweep (a DO alarm). */
  prune(now: number): void {
    this.sql.exec(`DELETE FROM challenges WHERE expires_at <= ?`, now);
    this.sql.exec(`DELETE FROM sessions WHERE expires_at <= ?`, now);
    this.sql.exec(`DELETE FROM codes WHERE expires_at <= ?`, now);
    this.sql.exec(`DELETE FROM code_log WHERE at <= ?`, now - HOUR);
    this.sql.exec(`DELETE FROM code_failures WHERE at <= ?`, now - DAY);
  }

  // ---- challenges --------------------------------------------------------

  /** Remember a WebAuthn challenge we issued. Registration binds it to the
   * account id it's minting, and step-up to the account confirming itself,
   * so the verify step can't be pointed elsewhere. */
  createChallenge(
    challenge: string,
    purpose: ChallengePurpose,
    userId: string | null,
    now: number,
    name: string | null = null,
  ): void {
    this.sql.exec(`DELETE FROM challenges WHERE expires_at <= ?`, now);
    this.sql.exec(
      `INSERT INTO challenges (challenge, purpose, user_id, expires_at, name) VALUES (?, ?, ?, ?, ?)`,
      challenge,
      purpose,
      userId,
      now + CHALLENGE_TTL_MS,
      name,
    );
  }

  /** Single use: a challenge is deleted on first sight, valid or not. */
  consumeChallenge(
    challenge: string,
    purpose: ChallengePurpose,
    now: number,
  ): { userId: string | null; name: string | null } | null {
    const [row] = this.rows<{ purpose: string; user_id: string | null; expires_at: number; name: string | null }>(
      `SELECT purpose, user_id, expires_at, name FROM challenges WHERE challenge = ?`,
      challenge,
    );
    if (!row) return null;
    this.sql.exec(`DELETE FROM challenges WHERE challenge = ?`, challenge);
    if (row.purpose !== purpose || row.expires_at <= now) return null;
    return { userId: row.user_id, name: row.name };
  }

  // ---- accounts ----------------------------------------------------------

  createAccount(id: string, name: string, profile: Profile, now: number): AccountView {
    this.sql.exec(
      `INSERT INTO users (id, name, email, profile, created_at) VALUES (?, ?, NULL, ?, ?)`,
      id,
      name,
      JSON.stringify(profile),
      now,
    );
    return this.account(id)!;
  }

  account(id: string): AccountView | null {
    const [row] = this.rows<UserRow>(`SELECT id, name, email, profile FROM users WHERE id = ?`, id);
    return row ? toView(row) : null;
  }

  accountByEmail(email: string): AccountView | null {
    const [row] = this.rows<UserRow>(
      `SELECT id, name, email, profile FROM users WHERE email = ?`,
      normalizeEmail(email),
    );
    return row ? toView(row) : null;
  }

  updateAccount(id: string, patch: { name?: string; profile?: Profile }): AccountView | null {
    if (patch.name !== undefined) {
      this.sql.exec(`UPDATE users SET name = ? WHERE id = ?`, patch.name, id);
    }
    if (patch.profile !== undefined) {
      this.sql.exec(`UPDATE users SET profile = ? WHERE id = ?`, JSON.stringify(patch.profile), id);
    }
    return this.account(id);
  }

  /** Attach a verified recovery email. "taken" when another account has it —
   * an email recovers exactly one account. */
  setEmail(id: string, email: string): AccountView | "taken" | null {
    const normalized = normalizeEmail(email);
    const owner = this.accountByEmail(normalized);
    if (owner && owner.id !== id) return "taken";
    this.sql.exec(`UPDATE users SET email = ? WHERE id = ?`, normalized, id);
    // A recovery code already sent to the old address stops working with it.
    this.sql.exec(`DELETE FROM codes WHERE user_id = ? AND purpose = 'recover' AND email IS NOT ?`, id, normalized);
    return this.account(id);
  }

  /** Everything this account owns in auth state. The app's own data is the
   * caller's to remove — it lives elsewhere. */
  deleteAccount(id: string): void {
    const email = this.account(id)?.email;
    this.sql.exec(`DELETE FROM passkeys WHERE user_id = ?`, id);
    this.sql.exec(`DELETE FROM sessions WHERE user_id = ?`, id);
    this.sql.exec(`DELETE FROM codes WHERE user_id = ?`, id);
    this.sql.exec(`DELETE FROM challenges WHERE user_id = ?`, id);
    if (email) {
      this.sql.exec(`DELETE FROM code_log WHERE email = ?`, email);
      this.sql.exec(`DELETE FROM code_failures WHERE email = ?`, email);
    }
    this.sql.exec(`DELETE FROM users WHERE id = ?`, id);
  }

  // ---- passkeys ----------------------------------------------------------

  addPasskey(key: StoredPasskey, now: number): void {
    this.sql.exec(
      `INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_type, backed_up, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      key.id,
      key.userId,
      key.publicKey,
      key.counter,
      key.transports ? JSON.stringify(key.transports) : null,
      key.deviceType ?? null,
      key.backedUp === undefined ? null : Number(key.backedUp),
      now,
    );
  }

  passkey(id: string): StoredPasskey | null {
    const [row] = this.rows<PasskeyRow>(`SELECT ${PASSKEY_COLUMNS} FROM passkeys WHERE id = ?`, id);
    return row ? toPasskey(row) : null;
  }

  passkeysFor(userId: string): StoredPasskey[] {
    return this.rows<PasskeyRow>(`SELECT ${PASSKEY_COLUMNS} FROM passkeys WHERE user_id = ?`, userId).map(
      toPasskey,
    );
  }

  /** The account's passkeys as it may see them, oldest first. */
  passkeySummaries(userId: string): PasskeySummary[] {
    return this.rows<{
      id: string;
      created_at: number;
      last_used_at: number | null;
      device_type: string | null;
      backed_up: number | null;
    }>(
      `SELECT id, created_at, last_used_at, device_type, backed_up FROM passkeys
       WHERE user_id = ? ORDER BY created_at, id`,
      userId,
    ).map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at,
      deviceType: (r.device_type as PasskeySummary["deviceType"]) ?? null,
      backedUp: r.backed_up === null ? null : r.backed_up === 1,
    }));
  }

  /** Remove one passkey, only if it's this account's. */
  deletePasskey(userId: string, id: string): boolean {
    const owned = this.rows(`SELECT id FROM passkeys WHERE id = ? AND user_id = ?`, id, userId).length > 0;
    if (owned) this.sql.exec(`DELETE FROM passkeys WHERE id = ?`, id);
    return owned;
  }

  /** Recovery: the lost device may be in someone else's hands, passkey and all. */
  deletePasskeysFor(userId: string): void {
    this.sql.exec(`DELETE FROM passkeys WHERE user_id = ?`, userId);
  }

  /** After a successful assertion: the authenticator's new counter, and when. */
  passkeyUsed(id: string, counter: number, now: number): void {
    this.sql.exec(`UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?`, counter, now, id);
  }

  // ---- sessions ----------------------------------------------------------

  /** A new session has just proved its user, so it starts verified. */
  createSession(tokenHash: string, userId: string, now: number): void {
    this.sql.exec(`DELETE FROM sessions WHERE expires_at <= ?`, now);
    this.sql.exec(
      `INSERT INTO sessions (token_hash, user_id, expires_at, last_seen, verified_at) VALUES (?, ?, ?, ?, ?)`,
      tokenHash,
      userId,
      now + SESSION_TTL_MS,
      now,
      now,
    );
  }

  /** The session's account, sliding its expiry forward. A session in use
   * never expires; one left alone for SESSION_TTL_MS does. The write is at
   * most daily — an app may read a session on every request. */
  session(tokenHash: string, now: number): SessionInfo | null {
    const [row] = this.rows<{ user_id: string; expires_at: number; last_seen: number; verified_at: number }>(
      `SELECT user_id, expires_at, last_seen, verified_at FROM sessions WHERE token_hash = ?`,
      tokenHash,
    );
    if (!row) return null;
    if (row.expires_at <= now) {
      this.sql.exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash);
      return null;
    }
    if (now - row.last_seen > DAY) {
      this.sql.exec(
        `UPDATE sessions SET last_seen = ?, expires_at = ? WHERE token_hash = ?`,
        now,
        now + SESSION_TTL_MS,
        tokenHash,
      );
    }
    return { userId: row.user_id, verifiedAt: row.verified_at };
  }

  /** The user just proved themselves again (step-up). */
  markVerified(tokenHash: string, now: number): void {
    this.sql.exec(`UPDATE sessions SET verified_at = ? WHERE token_hash = ?`, now, tokenHash);
  }

  deleteSession(tokenHash: string): void {
    this.sql.exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash);
  }

  /** Sign the account out everywhere, optionally keeping one session. */
  deleteSessionsFor(userId: string, keepTokenHash: string | null = null): void {
    this.sql.exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash IS NOT ?`, userId, keepTokenHash);
  }

  // ---- one-time codes ----------------------------------------------------

  /** Store a code for `email`, replacing any outstanding one for the same
   * purpose. "rate-limited" once this email has been sent CODES_PER_HOUR codes
   * in the last hour, whoever asked for them. */
  issueCode(
    email: string,
    purpose: CodePurpose,
    userId: string,
    codeHash: string,
    now: number,
  ): "ok" | "rate-limited" {
    const normalized = normalizeEmail(email);
    this.sql.exec(`DELETE FROM codes WHERE expires_at <= ?`, now);
    if (this.noteCodeRequest(normalized, now) === "rate-limited") return "rate-limited";
    this.sql.exec(
      `INSERT OR REPLACE INTO codes (email, purpose, user_id, code_hash, expires_at, attempts) VALUES (?, ?, ?, ?, ?, 0)`,
      normalized,
      purpose,
      userId,
      codeHash,
      now + CODE_TTL_MS,
    );
    return "ok";
  }

  /** Count a request for a code to `email` against its hourly cap, sending
   * nothing. issueCode does this itself; call it alone where a code must look
   * sent but isn't (someone else's email), so the cap can't tell them apart. */
  noteCodeRequest(email: string, now: number): "ok" | "rate-limited" {
    const normalized = normalizeEmail(email);
    this.sql.exec(`DELETE FROM code_log WHERE at <= ?`, now - HOUR);
    const [{ n }] = this.rows<{ n: number }>(`SELECT COUNT(*) AS n FROM code_log WHERE email = ?`, normalized) as [
      { n: number },
    ];
    if (n >= CODES_PER_HOUR) return "rate-limited";
    this.sql.exec(`INSERT INTO code_log (email, at) VALUES (?, ?)`, normalized, now);
    return "ok";
  }

  /** Check a code. Success burns it; every failure counts, and the code dies
   * at CODE_MAX_ATTEMPTS — six digits survive five guesses, not a million.
   * Failures also count against the email across codes (MAX_CODE_FAILURES a
   * day), or reissuing would make the cap meaningless. */
  redeemCode(email: string, purpose: CodePurpose, codeHash: string, now: number): { userId: string } | null {
    const normalized = normalizeEmail(email);
    this.sql.exec(`DELETE FROM code_failures WHERE at <= ?`, now - DAY);
    const [{ failures, everyone }] = this.rows<{ failures: number; everyone: number }>(
      `SELECT SUM(email = ?) AS failures, COUNT(*) AS everyone FROM code_failures`,
      normalized,
    ) as [{ failures: number | null; everyone: number }];
    if ((failures ?? 0) >= MAX_CODE_FAILURES || everyone >= MAX_GLOBAL_CODE_FAILURES) return null;
    const [row] = this.rows<{ user_id: string; code_hash: string; expires_at: number; attempts: number }>(
      `SELECT user_id, code_hash, expires_at, attempts FROM codes WHERE email = ? AND purpose = ?`,
      normalized,
      purpose,
    );
    if (!row) return null;
    if (row.expires_at <= now || row.attempts >= CODE_MAX_ATTEMPTS) {
      this.sql.exec(`DELETE FROM codes WHERE email = ? AND purpose = ?`, normalized, purpose);
      return null;
    }
    if (row.code_hash !== codeHash) {
      this.sql.exec(`INSERT INTO code_failures (email, at) VALUES (?, ?)`, normalized, now);
      this.sql.exec(`UPDATE codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?`, normalized, purpose);
      return null;
    }
    this.sql.exec(`DELETE FROM codes WHERE email = ? AND purpose = ?`, normalized, purpose);
    return { userId: row.user_id };
  }
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function toView(row: UserRow): AccountView {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    profile: JSON.parse(row.profile) as Profile,
  };
}

function toPasskey(row: PasskeyRow): StoredPasskey {
  return {
    id: row.id,
    userId: row.user_id,
    publicKey: new Uint8Array(row.public_key),
    counter: row.counter,
    transports: row.transports ? (JSON.parse(row.transports) as string[]) : undefined,
    deviceType: (row.device_type as StoredPasskey["deviceType"]) ?? undefined,
    backedUp: row.backed_up === null ? undefined : row.backed_up === 1,
  };
}
