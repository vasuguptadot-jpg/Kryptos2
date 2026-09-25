// Captured at module load, before any setup replaces globalThis.fetch —
// lets the passthrough reach local test servers while providers stay mocked.
const REAL_FETCH = globalThis.fetch;

import { generateCredential } from "../src/lib/credentials";
import { MemoryStore } from "../src/lib/store-memory";
import { resetStoreForTests } from "../src/lib/store";
import type { ApplicationRecord } from "../src/lib/types";

export const SYNTHETIC_GEMINI_KEY = "synthetic-gemini-test-key-AAAABBBBCCCCDDDD-not-real";
export const SYNTHETIC_GROQ_KEY = "synthetic-groq-test-key-EEEEFFFFGGGGHHHH-not-real";

export interface TestApp {
  app: ApplicationRecord;
  key: string;
}

export interface TestContext {
  store: MemoryStore;
  fetchCalls: { url: string | URL; init?: RequestInit }[];
  makeApp(opts?: {
    appId?: string;
    permissions?: { permission: string; rateLimitPerMinute: number | null }[];
    defaultRateLimit?: number;
  }): Promise<TestApp>;
}

/** Fresh in-memory world + synthetic env for each test file. */
export async function setupTestEnvironment(): Promise<TestContext> {
  process.env.STORE_BACKEND = "memory";
  delete process.env.DATABASE_URL;
  process.env.GEMINI_API_KEY = SYNTHETIC_GEMINI_KEY;
  process.env.GROQ_API_KEY = SYNTHETIC_GROQ_KEY;
  process.env.ADMIN_USERNAME = "test-admin";
  process.env.ADMIN_PASSWORD = "test-admin-password-000111222333";
  process.env.ADMIN_SESSION_SECRET = "test-session-secret-64-chars-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  delete process.env.CREDENTIAL_PEPPER;
  delete process.env.GEMINI_MODEL_ALLOWLIST;
  delete process.env.GROQ_MODEL_ALLOWLIST;

  // MemoryStore's constructor pre-registers the built-in secrets/capabilities
  // (same rows migration 002 installs in Postgres).
  const store = new MemoryStore();
  resetStoreForTests(store);

  const fetchCalls: { url: string | URL; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    fetchCalls.push({ url, init });
    const u = String(url);
    if (u.startsWith("https://generativelanguage.googleapis.com/")) {
      return new Response(
        JSON.stringify({
          candidates: [
            { content: { parts: [{ text: "synthetic gemini reply" }] }, finishReason: "STOP" }
          ],
          usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 7 }
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (u.startsWith("https://api.groq.com/")) {
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "synthetic groq reply" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 5, completion_tokens: 7 }
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (u.startsWith("https://api.weather.example.com/")) {
      return new Response(
        JSON.stringify({ weather: [{ main: "Clear" }], main: { temp: 301.5 }, name: "Testville" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (u.startsWith("http://127.0.0.1") || u.startsWith("http://localhost")) {
      return REAL_FETCH(url, init); // local harness servers only
    }
    return new Response("unexpected url in test", { status: 500 });
  }) as typeof fetch;

  return {
    store,
    fetchCalls,
    async makeApp(opts = {}) {
      const app = await store.createApplication({
        appId: opts.appId ?? "TEST_APP",
        displayName: "Test App",
        defaultRateLimit: opts.defaultRateLimit ?? 100
      });
      if (opts.permissions) await store.setPermissions(app.id, opts.permissions);
      const cred = generateCredential();
      await store.createCredential(app.id, cred.keyHash, cred.keyPrefix);
      return { app, key: cred.rawKey };
    }
  };
}

/** Build an authenticated provider request. */
export function providerRequest(
  path: string,
  appId: string,
  key: string,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): Request {
  const raw = JSON.stringify(body);
  return new Request(`http://localhost${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(raw)),
      "x-kryptos-app-id": appId,
      "x-kryptos-app-key": key,
      ...extraHeaders
    },
    body: raw
  });
}

export async function responseText(res: Response): Promise<string> {
  return await res.clone().text();
}

/** Build an authenticated /api/v1/execute capability request. */
export function executeRequest(
  appId: string,
  key: string,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): Request {
  return providerRequest("/api/v1/execute", appId, key, body, extraHeaders);
}
