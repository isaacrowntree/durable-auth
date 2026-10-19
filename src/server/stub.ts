/** Typed access to the auth Durable Object.
 *
 * The DO exposes one RPC method, `run(method, args)`, that dispatches onto an
 * AuthStore living inside it. This file turns that back into the store's own
 * interface — every method, its real argument and return types, just async —
 * so callers can't tell a DO from a local store, and tests can hand the
 * handlers a node:sqlite-backed one. */

import type { AuthStore } from "./store";

type Methods<T> = {
  [K in keyof T as T[K] extends (...args: never[]) => unknown ? K : never]: T[K];
};

export type AuthApi = {
  [K in keyof Methods<AuthStore>]: AuthStore[K] extends (...args: infer A) => infer R
    ? (...args: A) => Promise<R>
    : never;
};

interface AuthRpc {
  run(method: string, args: unknown[]): Promise<unknown>;
}

/** The slice of a DurableObjectNamespace this needs. */
export interface AuthNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): unknown;
}

function proxy(call: (method: string, args: unknown[]) => Promise<unknown>): AuthApi {
  return new Proxy({} as AuthApi, {
    // Not `then`: the proxy must never look like a promise to `await`.
    get: (_, method) =>
      typeof method === "string" && method !== "then"
        ? (...args: unknown[]) => call(method, args)
        : undefined,
  });
}

/** Every account lives in ONE instance: sign-in is rare and tiny next to an
 * app's own traffic, and a single instance is what makes "this email belongs
 * to one account" a plain UNIQUE constraint rather than a distributed problem. */
export function authStoreFrom(ns: AuthNamespace, name = "auth"): AuthApi {
  const stub = ns.get(ns.idFromName(name)) as AuthRpc;
  return proxy((method, args) => stub.run(method, args));
}

/** A local store behind the same async interface — for tests. */
export function asyncStore(store: AuthStore): AuthApi {
  return proxy(async (method, args) => {
    const fn = (store as unknown as Record<string, (...a: unknown[]) => unknown>)[method]!;
    return fn.apply(store, args);
  });
}
