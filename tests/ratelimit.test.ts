import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { handleLegacyProviderRequest } from "../src/lib/pipeline";
import { providerRequest, setupTestEnvironment } from "./helpers";

/**
 * Rate-limit test (spec §14 item 10) — per app AND per operation,
 * fail-closed semantics verified in store-errors test below.
 */
describe("per-application rate limiting", () => {
  it("bounds requests per app per operation and returns 429 with Retry-After", async () => {
    const ctx = await setupTestEnvironment();
    const { app, key } = await ctx.makeApp({
      appId: "LIMITED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: 3 }]
    });
    const statuses: number[] = [];
    let last: Response | null = null;
    for (let i = 0; i < 5; i++) {
      const res = await handleLegacyProviderRequest(
        providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: `q${i}` }),
        "gemini.generate"
      );
      statuses.push(res.status);
      last = res;
    }
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
    assert.ok(last!.headers.get("retry-after"), "429 must carry Retry-After");
    assert.equal(last!.headers.get("x-ratelimit-limit"), "3");
    const body = (await last!.json()) as { error: { code: string } };
    assert.equal(body.error.code, "rate_limited");
  });

  it("limits are independent per application", async () => {
    const ctx = await setupTestEnvironment();
    const a = await ctx.makeApp({
      appId: "APP_A",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: 1 }]
    });
    const b = await ctx.makeApp({
      appId: "APP_B",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: 1 }]
    });
    const mk = (t: { app: { appId: string }; key: string }) =>
      providerRequest("/api/v1/gemini", t.app.appId, t.key, { model: "gemini-2.0-flash", prompt: "hi" });

    assert.equal((await handleLegacyProviderRequest(mk(a), "gemini.generate")).status, 200);
    assert.equal((await handleLegacyProviderRequest(mk(b), "gemini.generate")).status, 200, "app B must not consume app A's budget");
    assert.equal((await handleLegacyProviderRequest(mk(a), "gemini.generate")).status, 429);
    assert.equal((await handleLegacyProviderRequest(mk(b), "gemini.generate")).status, 429);
  });

  it("limits are independent per operation", async () => {
    const ctx = await setupTestEnvironment();
    const { app, key } = await ctx.makeApp({
      appId: "MULTI_OP_APP",
      permissions: [
        { permission: "gemini.generate", rateLimitPerMinute: 1 },
        { permission: "groq.generate", rateLimitPerMinute: 1 }
      ]
    });
    const gem = () =>
      handleLegacyProviderRequest(
        providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
        "gemini.generate"
      );
    const groq = () =>
      handleLegacyProviderRequest(
        providerRequest("/api/v1/groq", app.appId, key, { model: "llama-3.1-8b-instant", prompt: "hi" }),
        "groq.generate"
      );
    assert.equal((await gem()).status, 200);
    assert.equal((await gem()).status, 429, "gemini budget exhausted");
    assert.equal((await groq()).status, 200, "groq has its own budget");
  });

  it("fails closed when the store cannot authorize (503, never a bypass)", async () => {
    const ctx = await setupTestEnvironment();
    const { app, key } = await ctx.makeApp({
      appId: "CLOSED_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    // Simulate a DB outage mid-request.
    ctx.store.getApplicationByAppId = async () => {
      throw new Error("connection reset");
    };
    const res = await handleLegacyProviderRequest(
      providerRequest("/api/v1/gemini", app.appId, key, { model: "gemini-2.0-flash", prompt: "hi" }),
      "gemini.generate"
    );
    assert.equal(res.status, 503, "authorization outage must deny, not bypass");
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "authorization_unavailable");
  });
});
