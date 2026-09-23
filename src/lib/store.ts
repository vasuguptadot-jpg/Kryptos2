import { MemoryStore } from "./store-memory";
import { PostgresStore } from "./store-postgres";
import type { Store } from "./types";

// Keep the singleton on globalThis: Next.js dev mode compiles routes in
// separate module graphs, so a module-level cache would hand each route its
// OWN store instance. globalThis is shared across the server runtime.
const GLOBAL_KEY = "__kryptos_store__";
const globalCache = globalThis as unknown as { [GLOBAL_KEY]?: Store | null };

export class StoreUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreUnavailableError";
  }
}

/**
 * Resolve the metadata store.
 *
 * - "postgres" (default): requires DATABASE_URL. If it is missing, this
 *   THROWS — callers must fail closed (never bypass authorization).
 * - "memory": allowed for tests and local development only; REFUSED when
 *   NODE_ENV=production so a misconfigured production deploy fails closed.
 */
export function getStore(): Store {
  if (globalCache[GLOBAL_KEY]) return globalCache[GLOBAL_KEY]!;
  const backend = (process.env.STORE_BACKEND ?? "postgres").toLowerCase();
  if (backend === "memory") {
    if ((process.env.NODE_ENV ?? "development") === "production") {
      throw new StoreUnavailableError(
        "memory store backend is not permitted in production (fail closed)"
      );
    }
    // Constructor pre-registers built-in metadata synchronously (dev/test).
    // Production uses the migration-002 rows instead.
    globalCache[GLOBAL_KEY] = new MemoryStore();
    return globalCache[GLOBAL_KEY]!;
  }
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new StoreUnavailableError("DATABASE_URL is not configured (fail closed)");
  }
  globalCache[GLOBAL_KEY] = new PostgresStore(url);
  return globalCache[GLOBAL_KEY]!;
}

/** Test hook: reset the cached store between test files. */
export function resetStoreForTests(store?: Store): void {
  globalCache[GLOBAL_KEY] = store ?? null;
}
