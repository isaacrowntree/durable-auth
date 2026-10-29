/** The Durable Object that holds every account: one instance for the whole
 * app (`idFromName("auth")`). It runs requests one at a time, which is what
 * makes AuthStore's check-then-write steps atomic.
 *
 * A single RPC method dispatches onto the store; stub.ts turns it back into
 * the store's typed interface. Extend it and export it from your Worker:
 *
 *   export class Auth extends AuthDurableObject {}
 *
 * An alarm sweeps expired rows daily; every table is also pruned as it's
 * written, so a missed alarm costs nothing but a little disk. */

import { DurableObject } from "cloudflare:workers";
import { AuthStore } from "./store";

const SWEEP_EVERY_MS = 24 * 60 * 60 * 1000;

/** The store's public methods, by name — nothing inherited, nothing private. */
const METHODS = new Set(
  Object.getOwnPropertyNames(AuthStore.prototype).filter(
    (name) => name !== "constructor" && name !== "rows" && name !== "migrate",
  ),
);

export class AuthDurableObject<Env = unknown> extends DurableObject<Env> {
  // Multi-step writes (and schema migrations) commit whole or not at all.
  private store = new AuthStore(this.ctx.storage.sql, (fn) => this.ctx.storage.transactionSync(fn));
  /** Checked once per instance, not per call: every session check comes here. */
  private sweepScheduled = false;

  async run(method: string, args: unknown[]): Promise<unknown> {
    if (!METHODS.has(method)) throw new Error(`Unknown auth method: ${method}`);
    if (!this.sweepScheduled) {
      if ((await this.ctx.storage.getAlarm()) === null) {
        await this.ctx.storage.setAlarm(Date.now() + SWEEP_EVERY_MS);
      }
      this.sweepScheduled = true;
    }
    const fn = (this.store as unknown as Record<string, (...a: unknown[]) => unknown>)[method]!;
    return fn.apply(this.store, args);
  }

  async alarm(): Promise<void> {
    this.store.prune(Date.now());
    await this.ctx.storage.setAlarm(Date.now() + SWEEP_EVERY_MS);
  }
}
