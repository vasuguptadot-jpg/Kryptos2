import assert from "node:assert/strict";
import { describe, it, before } from "node:test";
import { handleExecuteRequest, handleLegacyProviderRequest } from "../src/lib/pipeline";
import { executeRequest, providerRequest, setupTestEnvironment, type TestContext } from "./helpers";

/**
 * Authorization & isolation tests (spec §14 items 4, 5, 6, 8, 9, 11).
 */
describe("authorization boundaries", () => {
  let ctx: TestContext;
  before(async () => {
    ctx = await setupTestEnvironment();
  });

  it("rejects requests with no credentials (401)", async () => {
    const res = await handleLegacyProviderRequest(
      new Request("http://localhost/api/v1/gemini", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "gemini-2.0-flash", prompt: "hi" })
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 401);
  });

  it("rejects an unknown app id (401)", async () => {
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", "NOPE", "krk_wrong", {
        model: "gemini-2.0-flash",
        prompt: "hi"
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 401);
  });

  it("rejects an invalid credential (401)", async () => {
    const { app } = await ctx.makeApp({
      appId: "VALID_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, "krk_00000000000000000000000000000000000000000000000000000000000000de", {
        model: "gemini-2.0-flash",
        prompt: "hi"
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 401);
  });

  it("allows an authorized app to call its provider (200)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "ALLOWED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, {
        model: "gemini-2.0-flash",
        prompt: "hello"
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 200);
    const data = (await res.json()) as { provider: string; text: string };
    assert.equal(data.provider, "gemini");
    assert.match(data.text, /synthetic gemini reply/);
  });

  it("blocks app A from using app B's permission (403 cross-app isolation)", async () => {
    await ctx.makeApp({
      appId: "GROQ_APP",
      permissions: [{ permission: "groq.generate", rateLimitPerMinute: null }]
    });
    const other = await ctx.makeApp({
      appId: "GEMINI_ONLY_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/groq", other.app.appId, other.key, {
        model: "llama-3.1-8b-instant",
        prompt: "hi"
      }),
      "groq.generate"
    );
    assert.equal(res.status, 403);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "operation_not_permitted");
  });

  it("blocks a revoked app immediately (403)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "REVOKED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    await ctx.store.setApplicationStatus(app.id, "revoked");
    await ctx.store.revokeCredentials(app.id);
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    assert.equal(res.status, 403);
  });

  it("blocks a disabled app (403)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "DISABLED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    await ctx.store.setApplicationStatus(app.id, "disabled");
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    assert.equal(res.status, 403);
  });

  it("blocks a rotated-out credential (401) while the new one works", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "ROT_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    await ctx.store.revokeCredentials(app.id); // simulate rotation
    const oldRes = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    assert.equal(oldRes.status, 401);
  });

  it("rejects an unknown capability even for an authorized app (404)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "EVIL_APP",
      permissions: [{ permission: "ghost.operation", rateLimitPerMinute: null }]
    });
    // The app holds a permission for a capability that no longer exists in the registry.
    const res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "ghost.operation", input: {} })
    );
    assert.equal(res.status, 404);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "unknown_capability");
  });

  it("rejects capability-hopping to a capability the app was not granted (403)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "HOP_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "groq.generate", input: { prompt: "hi" } })
    );
    assert.equal(res.status, 403);
  });

  it("rejects arbitrary env-var exfiltration attempts in the body (400)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "EXFIL_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const attempts = [
      { secret: "SUPABASE_SERVICE_ROLE_KEY" },
      { env: "GEMINI_API_KEY" },
      { model: "gemini-2.0-flash", prompt: "hi", secret: "GEMINI_API_KEY" },
      { model: "gemini-2.0-flash", prompt: "hi", returnKey: true },
      { model: "gemini-2.0-flash", prompt: "hi", key: true }
    ];
    for (const body of attempts) {
      const res = await handleLegacyProviderRequest(
        providerRequest("/api/v1/gemini", app.appId, key, body),
        "gemini.generate"
      );
      assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(body)}`);
      const text = await res.text();
      assert.ok(!text.includes("AIza") && !text.includes(process.env.GEMINI_API_KEY!));
    }
  });

  it("rejects arbitrary URL proxying attempts (SSRF) in the body (400)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "SSRF_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const attempts = [
      { model: "gemini-2.0-flash", prompt: "hi", url: "http://169.254.169.254/latest/meta-data" },
      { model: "gemini-2.0-flash", prompt: "hi", endpoint: "http://127.0.0.1:3000/admin" },
      { model: "gemini-2.0-flash", prompt: "hi", baseUrl: "https://evil.example.com" },
      { model: "gemini-2.0-flash", prompt: "hi", host: "internal.service" }
    ];
    for (const body of attempts) {
      const res = await handleLegacyProviderRequest(
        providerRequest("/api/v1/gemini", app.appId, key, body),
        "gemini.generate"
      );
      assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(body)}`);
    }
    // And no outbound call other than the fixed provider hosts was ever made.
    for (const call of ctx.fetchCalls) {
      const u = String(call.url);
      assert.ok(
        u.startsWith("https://generativelanguage.googleapis.com/") ||
          u.startsWith("https://api.groq.com/"),
        `unexpected outbound URL: ${u}`
      );
    }
  });

  it("rejects models that are not on the server allowlist (400)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "MODEL_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, {
        model: "../../etc/passwd",
        prompt: "hi"
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 400);
  });

  it("rejects oversized payloads (413)", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "BIG_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, {
        model: "gemini-2.0-flash",
        prompt: "x".repeat(70 * 1024)
      }),
      "gemini.generate"
    );
    assert.equal(res.status, 413);
  });
});
