import assert from "node:assert/strict";
import { describe, it, before } from "node:test";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { handleLegacyProviderRequest } from "../src/lib/pipeline";
import { redactSecrets } from "../src/lib/secrets";
import {
  providerRequest,
  setupTestEnvironment,
  SYNTHETIC_GROQ_KEY,
  SYNTHETIC_GEMINI_KEY,
  type TestContext
} from "./helpers";

/**
 * Secret-leakage tests (spec §14 items 1, 2, 3, 12).
 */
describe("secret non-leakage", () => {
  let ctx: TestContext;
  before(async () => {
    ctx = await setupTestEnvironment();
  });

  it("uses the secret server-side but never returns it in the response body", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "LEAK_APP",
      permissions: [
        { permission: "gemini.generate", rateLimitPerMinute: null },
        { permission: "groq.generate", rateLimitPerMinute: null }
      ]
    });

    const geminiRes = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    const groqRes = await handleLegacyProviderRequest(
      providerRequest("/api/v1/groq", app.appId, key, { model: "llama-3.1-8b-instant", prompt: "hi" }),
      "groq.generate"
    );

    // The server DID present the secrets to the right providers:
    const geminiCall = ctx.fetchCalls.find((c) => String(c.url).includes("googleapis"));
    const groqCall = ctx.fetchCalls.find((c) => String(c.url).includes("groq"));
    assert.equal((geminiCall!.init!.headers as Record<string, string>)["x-goog-api-key"], SYNTHETIC_GEMINI_KEY);
    assert.equal(
      (groqCall!.init!.headers as Record<string, string>)["authorization"],
      `Bearer ${SYNTHETIC_GROQ_KEY}`
    );

    // …but the client never received them:
    for (const res of [geminiRes, groqRes]) {
      const text = await res.text();
      assert.ok(!text.includes(SYNTHETIC_GEMINI_KEY), "gemini key leaked in response");
      assert.ok(!text.includes(SYNTHETIC_GROQ_KEY), "groq key leaked in response");
      for (const [name, value] of res.headers) {
        assert.ok(!value.includes(SYNTHETIC_GEMINI_KEY), `gemini key leaked in header ${name}`);
        assert.ok(!value.includes(SYNTHETIC_GROQ_KEY), `groq key leaked in header ${name}`);
      }
    }
  });

  it("redacts secrets even when the provider echoes them back in an error", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "ERR_APP",
      permissions: [{ permission: "groq.generate", rateLimitPerMinute: null }]
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(
        // Provider "accidentally" includes the key in its 401 body (mirrors real-world leaks).
        JSON.stringify({ error: { message: `invalid api key ${SYNTHETIC_GROQ_KEY} supplied` } }),
        { status: 401, headers: { "content-type": "application/json" } }
      )) as typeof fetch;
    try {
      const res = await handleLegacyProviderRequest(
        providerRequest("/api/v1/groq", app.appId, key, { model: "llama-3.1-8b-instant", prompt: "hi" }),
        "groq.generate"
      );
      assert.equal(res.status, 502);
      const text = await res.text();
      assert.ok(!text.includes(SYNTHETIC_GROQ_KEY), "secret leaked through provider error message");
      assert.ok(text.includes("[REDACTED]"));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not include the app credential itself in responses", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "CRED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    assert.ok(!(await res.text()).includes(key), "app credential echoed back");
  });

  it("redactSecrets() strips known secret values and env assignments", () => {
    const dirty = `GEMINI_API_KEY=${SYNTHETIC_GEMINI_KEY} was used, key is ${SYNTHETIC_GEMINI_KEY}`;
    const clean = redactSecrets(dirty);
    assert.ok(!clean.includes(SYNTHETIC_GEMINI_KEY));
  });

  it("the production client bundle contains no private secrets", async (t) => {
    const staticDir = join(__dirname, "..", ".next", "static");
    if (!existsSync(staticDir)) {
      t.skip("no production build found — run `npm run build` first (verified in CI)");
      return;
    }
    // Denylist: every registered secret name in the registry (dynamic — covers
    // arbitrary names like MY_WEATHER_API_KEY), plus infra secret names, plus
    // every synthetic value used in tests.
    const registryNames = (await ctx.store.listSecrets()).map((s) => s.secretName);
    const infraNames = [
      "DATABASE_URL", "ADMIN_PASSWORD", "ADMIN_SESSION_SECRET", "CREDENTIAL_PEPPER",
      "SUPABASE_SERVICE_ROLE_KEY", "VAPID_PRIVATE_KEY"
    ];
    const denyNames = [...registryNames, ...infraNames];
    const secretValues = [SYNTHETIC_GEMINI_KEY, SYNTHETIC_GROQ_KEY];
    for (const name of denyNames) {
      const v = process.env[name];
      if (v && v.length >= 8) secretValues.push(v);
    }
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(js|css|html)$/.test(entry)) files.push(p);
      }
    };
    walk(staticDir);
    assert.ok(files.length > 0, "expected client build assets to scan");
    for (const file of files) {
      const content = readFileSync(file, "utf8");
      for (const value of secretValues) {
        assert.ok(!content.includes(value), `secret value found in client bundle: ${file}`);
      }
      for (const name of denyNames) {
        assert.ok(!content.includes(name), `secret env name "${name}" found in client bundle: ${file}`);
      }
    }
  });
});
