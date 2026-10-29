/** A Durable Object's `ctx.storage.sql`, played by node:sqlite — enough of
 * it for AuthStore to run in a test exactly as it runs in the DO. */

import { DatabaseSync } from "node:sqlite";
import type { Sql } from "../src/server/store";

export function memorySql(db = new DatabaseSync(":memory:")): Sql {
  return {
    exec(query: string, ...bindings: unknown[]) {
      const rows = db.prepare(query).all(...(bindings as never[])) as Record<string, unknown>[];
      return { toArray: () => rows };
    },
  };
}

/** `ctx.storage.transactionSync`, played by node:sqlite: all of `fn` or none. */
export function memoryTransaction(db: DatabaseSync) {
  return <T>(fn: () => T): T => {
    db.exec("BEGIN");
    try {
      const out = fn();
      db.exec("COMMIT");
      return out;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  };
}
