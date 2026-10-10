import assert from "node:assert/strict";
import { describe, it, before } from "node:test";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { httpGenericAdapter } from "../src/lib/adapters/http-generic";
import { handleExecuteRequest } from "../src/lib/pipeline";
import { redactSecrets } from "../src/lib/secrets";
import {
  executeRequest,
  setupTestEnvironment,
  SYNTHETIC_GEMINI_KEY,
  type TestContext
} from "./helpers";

const WEATHER_KEY = "synthetic-weather-key-ZZZZYYYYXXXX-not-real";
const WEATHER_CONFIG = {
  baseUrl: "https://api.weather.example.com",
  path: "/v1/current",
  method: "GET",
  auth: { placement: "query", name: "appid" }
};

async function registerWeatherCapability(ctx: TestContext): Promise<void> {
  process.env.MY_WEATHER_API_KEY = WEATHER_KEY;
  await ctx.store.createSecret({
    secretName: "MY_WEATHER_API_KEY",
    providerId: "http-generic",
    notes: "weather provider key"
  });
  await ctx.store.upsertCapability({
    capability: "weather.current",
    providerId: "http-generic",
    secretName: "MY_WEATHER_API_KEY",
    operation: "request",
    config: WEATHER_CONFIG,
    enabled: true
  });
}

describe("generic capability architecture", () => {
  let ctx: TestContext;
  before(async () => {
    ctx = await setupTestEnvironment();
    await registerWeatherCapability(ctx);
  });

  it("serves an arbitrary new secret through its capability without code changes", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "WEATHER_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "weather.current", input: { q: "Moradabad" } })
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as { capability: string; provider: string; result: unknown };
    assert.equal(body.capability, "weather.current");
    assert.equal(body.provider, "http-generic");
    assert.ok(body.result && typeof body.result === "object");

    // The secret went ONLY to the approved origin, as the configured query param.
    const call = ctx.fetchCalls[ctx.fetchCalls.length - 1];
    const url = new URL(String(call.url));
    assert.equal(url.origin, "https://api.weather.example.com");
    assert.equal(url.pathname, "/v1/current");
    assert.equal(url.searchParams.get("appid"), WEATHER_KEY);
    assert.equal(url.searchParams.get("q"), "Moradabad");

    // …and never came back.
    const text = JSON.stringify(body);
    assert.ok(!text.includes(WEATHER_KEY), "secret leaked in execute response");
    assert.ok(!text.includes("MY_WEATHER_API_KEY"), "secret reference leaked in response");
  });

  it("envelope is strict: attempts to steer secret/provider selection are rejected", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "STEER_APP",
      permissions: [
        { permission: "weather.current", rateLimitPerMinute: null },
        { permission: "ai.generate", rateLimitPerMinute: null }
      ]
    });
    const attempts = [
      { capability: "weather.current", input: {}, secret_name: "GEMINI_API_KEY" },
      { capability: "weather.current", input: {}, env: "SUPABASE_SERVICE_ROLE_KEY" },
      { capability: "weather.current", input: {}, secret: "process.env.GEMINI_API_KEY" },
      { capability: "weather.current", input: {}, provider: "gemini" },
      { capability: "weather.current", input: {}, baseUrl: "http://evil.example.com" },
      { capability: "weather.current", input: {}, operation: "rawSecret" }
    ];
    for (const body of attempts) {
      const res = await handleExecuteRequest(executeRequest(app.appId, key, body));
      assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(body)}`);
      const text = await res.text();
      assert.ok(!text.includes(SYNTHETIC_GEMINI_KEY));
      assert.ok(!text.includes(WEATHER_KEY));
    }
  });

  it("rejects attempts to steer resolution through input fields", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "INPUT_STEER_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const attempts = [
      { url: "http://169.254.169.254/latest" },
      { baseUrl: "http://evil.example.com" },
      { host: "internal" },
      { appid: "override-the-secret" }, // would override the auth query param
      { headers: { authorization: "x" } },
      { secret_name: "GEMINI_API_KEY" }
    ];
    for (const input of attempts) {
      const res = await handleExecuteRequest(
        executeRequest(app.appId, key, { capability: "weather.current", input })
      );
      assert.equal(res.status, 400, `expected 400 for input ${JSON.stringify(input)}`);
    }
  });

  it("unknown capability → 404; disabled capability → 403; disabled secret → 403", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "STATE_APP",
      permissions: [
        { permission: "ghost.cap", rateLimitPerMinute: null },
        { permission: "weather.current", rateLimitPerMinute: null }
      ]
    });
    assert.equal(
      (await handleExecuteRequest(executeRequest(app.appId, key, { capability: "ghost.cap", input: {} }))).status,
      404
    );

    // Disable the capability.
    const cap = await ctx.store.getCapability("weather.current");
    await ctx.store.upsertCapability({ ...cap!, enabled: false });
    let res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "weather.current", input: {} })
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error.code, "capability_disabled");
    await ctx.store.upsertCapability({ ...cap!, enabled: true });

    // Disable the underlying secret.
    const secret = await ctx.store.getSecretByName("MY_WEATHER_API_KEY");
    await ctx.store.setSecretEnabled(secret!.id, false);
    res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "weather.current", input: {} })
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error.code, "secret_disabled");
    await ctx.store.setSecretEnabled(secret!.id, true);
  });

  it("registered-but-missing env var → 503 provider_not_configured (no value, no hint of content)", async () => {
    await ctx.store.createSecret({ secretName: "MISSING_KEY", providerId: "gemini", notes: "" });
    await ctx.store.upsertCapability({
      capability: "ai.missing",
      providerId: "gemini",
      secretName: "MISSING_KEY",
      operation: "generateText",
      config: {},
      enabled: true
    });
    delete process.env.MISSING_KEY;
    const { app, key } = await ctx.makeApp({
      appId: "MISSING_APP",
      permissions: [{ permission: "ai.missing", rateLimitPerMinute: null }]
    });
    const res = await handleExecuteRequest(
      executeRequest(app.appId, key, { capability: "ai.missing", input: { prompt: "hi" } })
    );
    assert.equal(res.status, 503);
    const text = await res.text();
    assert.ok(!text.includes("MISSING_KEY="));
  });

  it("redaction covers arbitrary dynamically-registered secrets in provider errors", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "REDACT_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: `bad key ${WEATHER_KEY}` }), { status: 401 })) as typeof fetch;
    try {
      const res = await handleExecuteRequest(
        executeRequest(app.appId, key, { capability: "weather.current", input: {} })
      );
      assert.equal(res.status, 502);
      const text = await res.text();
      assert.ok(!text.includes(WEATHER_KEY), "arbitrary secret leaked via provider error");
      const body = JSON.parse(text);
      assert.equal(body.error.message, "Provider request failed");
    } finally {
      globalThis.fetch = originalFetch;
    }
    assert.ok(!redactSecrets(`key=${WEATHER_KEY}`).includes(WEATHER_KEY));
  });

  it("fails closed when successful JSON contains a configured credential", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "JSON_ECHO_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response(JSON.stringify({ data: { nested: [{ token: WEATHER_KEY }], [WEATHER_KEY]: "echo" } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;
    try {
      const res = await handleExecuteRequest(
        executeRequest(app.appId, key, { capability: "weather.current", input: {} })
      );
      assert.equal(res.status, 502);
      const text = await res.text();
      assert.ok(!text.includes(WEATHER_KEY));
      assert.equal(calls, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fails closed when successful text contains a configured credential", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "TEXT_ECHO_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response(`upstream echoed ${WEATHER_KEY}`, {
        status: 200,
        headers: { "content-type": "text/plain" }
      });
    }) as typeof fetch;
    try {
      const res = await handleExecuteRequest(
        executeRequest(app.appId, key, { capability: "weather.current", input: {} })
      );
      assert.equal(res.status, 502);
      const text = await res.text();
      assert.ok(!text.includes(WEATHER_KEY));
      assert.equal(calls, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not reflect static-header credentials in provider errors", async () => {
    const staticHeaderCredential = "synthetic-static-header-error-credential-not-real";
    await ctx.store.upsertCapability({
      capability: "weather.current",
      providerId: "http-generic",
      secretName: "MY_WEATHER_API_KEY",
      operation: "request",
      config: { ...WEATHER_CONFIG, staticHeaders: { "X-Partner-Key": staticHeaderCredential } },
      enabled: true
    });
    const { app, key } = await ctx.makeApp({
      appId: "ERROR_ECHO_APP",
      permissions: [{ permission: "weather.current", rateLimitPerMinute: null }]
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: `bad credential ${staticHeaderCredential}` }), { status: 401 })) as typeof fetch;
    try {
      const res = await handleExecuteRequest(
        executeRequest(app.appId, key, { capability: "weather.current", input: {} })
      );
      assert.equal(res.status, 502);
      const body = await res.json();
      assert.equal(body.error.message, "Provider request failed");
      assert.ok(!JSON.stringify(body).includes(staticHeaderCredential));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("http-generic adapter SSRF protection", () => {
  it("rejects unsafe destinations at configuration time", () => {
    const bad = [
      { baseUrl: "http://api.example.com" }, // non-https
      { baseUrl: "https://127.0.0.1" },
      { baseUrl: "https://10.0.0.4" },
      { baseUrl: "https://192.168.1.1" },
      { baseUrl: "https://172.16.0.9" },
      { baseUrl: "https://169.254.169.254" }, // cloud metadata
      { baseUrl: "https://metadata.google.internal" },
      { baseUrl: "https://localhost" },
      { baseUrl: "https://backend.internal" },
      { baseUrl: "https://user:pass@api.example.com" }, // userinfo
      { baseUrl: "https://api.example.com:8443" }, // non-default port
      { baseUrl: "https://api.example.com/path" }, // path in baseUrl
      { baseUrl: "not a url" }
    ];
    for (const config of bad) {
      const res = httpGenericAdapter.validateConfig({
        ...config,
        method: "GET",
        auth: { placement: "query", name: "appid" }
      });
      assert.equal(res.ok, false, `expected rejection for ${JSON.stringify(config)}`);
    }
  });

  it("rejects malicious paths and auth overrides", () => {
    const base = { baseUrl: "https://api.example.com", method: "GET", auth: { placement: "query", name: "appid" } };
    const badPaths = ["//evil.com", "/v1/../admin", "/v1/://x", "no-leading-slash"];
    for (const path of badPaths) {
      assert.equal(httpGenericAdapter.validateConfig({ ...base, path }).ok, false, `path ${path}`);
    }
    assert.equal(
      httpGenericAdapter.validateConfig({
        ...base,
        path: "/ok",
        staticHeaders: { Authorization: "Bearer x" }
      }).ok,
      false
    );
    assert.equal(
      httpGenericAdapter.validateConfig({ ...base, path: "/ok", auth: { placement: "header", name: "x-api-key" }, staticHeaders: { "X-Api-Key": "override" } }).ok,
      false
    );
  });

  it("accepts a legitimate config and normalizes the origin", () => {
    const res = httpGenericAdapter.validateConfig(WEATHER_CONFIG);
    assert.equal(res.ok, true);
    if (res.ok) assert.equal(res.config.baseUrl, "https://api.weather.example.com");
  });

  it("has no client-reachable secret/env enumeration endpoints", () => {
    // Static guarantee: no route may exist for raw secret retrieval or env exposure.
    const apiRoot = join(__dirname, "..", "src", "app", "api");
    const collected: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walk(p);
        else collected.push(p);
      }
    };
    walk(apiRoot);
    const routePaths = collected.map((p) => p.replace(apiRoot, ""));
    const forbidden = [/secrets/i, /secret\b/i, /\benv\b/i, /config/i, /get-secret/i, /debug/i, /resolver/i];
    for (const route of routePaths) {
      if (route.includes("/admin/")) continue; // admin metadata routes are auth-gated and value-free
      for (const pattern of forbidden) {
        assert.ok(!pattern.test(route), `forbidden client route exists: ${route}`);
      }
    }
    // Explicitly assert the classic exfiltration endpoints are absent.
    for (const p of ["api/secrets", "api/env", "api/config", "api/debug/env", "api/get-secret"]) {
      assert.ok(!collected.some((f) => f.includes(p)), `${p} must not exist`);
    }
  });
});
