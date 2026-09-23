import assert from "node:assert/strict";
import { describe, it, before } from "node:test";
import { GET as healthGET } from "../src/app/api/health/route";
import { POST as loginPOST } from "../src/app/api/admin/login/route";
import { GET as appsGET, POST as appsPOST } from "../src/app/api/admin/apps/route";
import { POST as rotatePOST } from "../src/app/api/admin/apps/[id]/rotate/route";
import { PATCH as appPATCH } from "../src/app/api/admin/apps/[id]/route";
import { GET as statsGET } from "../src/app/api/admin/stats/route";
import { GET as auditGET } from "../src/app/api/admin/audit/route";
import { GET as secretsGET, POST as secretsPOST } from "../src/app/api/admin/secrets/route";
import { GET as capsGET, POST as capsPOST } from "../src/app/api/admin/capabilities/route";
import { setupTestEnvironment, SYNTHETIC_GEMINI_KEY } from "./helpers";
import type { TestContext } from "./helpers";

const BASE = "http://localhost";

function adminReq(path: string, init: RequestInit = {}, cookie?: string): Request {
  return new Request(`${BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(cookie ? { cookie } : {}),
      ...(init.headers ?? {})
    }
  });
}

describe("admin surface & health", () => {
  let ctx: TestContext;
  before(async () => {
    ctx = await setupTestEnvironment();
  });

  it("health returns only safe metadata (no secrets, no fingerprints, no creds)", async () => {
    const res = await healthGET();
    assert.equal(res.status, 200);
    const text = await res.text();
    const body = JSON.parse(text);
    assert.equal(body.status, "ok");
    assert.equal(body.service, "kryptos");
    assert.equal(body.providers.gemini, "configured");
    assert.equal(body.providers.groq, "configured");
    assert.ok(!text.includes(SYNTHETIC_GEMINI_KEY));
    assert.ok(!text.includes("keyFingerprint"), "public health must not leak fingerprints");
  });

  it("admin API rejects unauthenticated access (401) on every route", async () => {
    const routes: Promise<Response>[] = [
      statsGET(adminReq("/api/admin/stats")),
      auditGET(adminReq("/api/admin/audit")),
      appsGET(adminReq("/api/admin/apps")),
      appsPOST(adminReq("/api/admin/apps", { method: "POST", body: "{}" })),
      rotatePOST(adminReq("/api/admin/apps/x/rotate", { method: "POST", body: "{}" }), {
        params: Promise.resolve({ id: "x" })
      }),
      appPATCH(adminReq("/api/admin/apps/x", { method: "PATCH", body: '{"status":"disabled"}' }), {
        params: Promise.resolve({ id: "x" })
      })
    ];
    for (const res of await Promise.all(routes)) {
      assert.equal(res.status, 401);
    }
  });

  it("login rejects wrong credentials (401) and issues a session cookie for the right ones", async () => {
    const bad = await loginPOST(
      adminReq("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ username: "test-admin", password: "wrong-password" })
      })
    );
    assert.equal(bad.status, 401);
    assert.ok(!bad.headers.get("set-cookie"));

    const good = await loginPOST(
      adminReq("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({
          username: "test-admin",
          password: "test-admin-password-000111222333"
        })
      })
    );
    assert.equal(good.status, 200);
    const cookie = good.headers.get("set-cookie") ?? "";
    assert.match(cookie, /kryptos_admin=/);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);

    // Full lifecycle with the session: create → rotate → revoke.
    const created = await appsPOST(
      adminReq("/api/admin/apps", {
        method: "POST",
        body: JSON.stringify({
          appId: "LIFECYCLE_APP",
          displayName: "Lifecycle",
          permissions: [{ permission: "gemini.generate", rateLimitPerMinute: 50 }]
        })
      }, cookie)
    );
    assert.equal(created.status, 201);
    const createdBody = (await created.json()) as {
      application: { id: string; appId: string };
      credential: string;
    };
    assert.match(createdBody.credential, /^krk_[0-9a-f]{64}$/);

    // The hash stored is NOT the raw credential.
    const creds = await ctx.store.getActiveCredentials(createdBody.application.id);
    assert.ok(creds.length > 0);
    for (const c of creds) assert.notEqual(c.keyHash, createdBody.credential);

    const rotated = await rotatePOST(adminReq(`/api/admin/apps/${createdBody.application.id}/rotate`, { method: "POST", body: "{}" }, cookie), {
      params: Promise.resolve({ id: createdBody.application.id })
    });
    assert.equal(rotated.status, 200);
    const rotatedBody = (await rotated.json()) as { credential: string };
    assert.notEqual(rotatedBody.credential, createdBody.credential);

    const revoked = await appPATCH(
      adminReq(`/api/admin/apps/${createdBody.application.id}`, { method: "PATCH", body: '{"status":"revoked"}' }, cookie),
      { params: Promise.resolve({ id: createdBody.application.id }) }
    );
    assert.equal(revoked.status, 200);

    // Admin listing never contains hashes or raw credentials.
    const list = await appsGET(adminReq("/api/admin/apps", {}, cookie));
    const listText = await list.text();
    assert.ok(!listText.includes("keyHash"));
    assert.ok(!listText.includes(createdBody.credential));
  });

  it("app creation rejects bad input (unknown permission, bad appId)", async () => {
    const good = await loginPOST(
      adminReq("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ username: "test-admin", password: "test-admin-password-000111222333" })
      })
    );
    const cookie = good.headers.get("set-cookie") ?? "";
    const badPerm = await appsPOST(
      adminReq("/api/admin/apps", {
        method: "POST",
        body: JSON.stringify({ appId: "HACK_APP", displayName: "x", permissions: [{ permission: "secret.read" }] })
      }, cookie)
    );
    assert.equal(badPerm.status, 400);
    const badId = await appsPOST(
      adminReq("/api/admin/apps", { method: "POST", body: JSON.stringify({ appId: "lower case!", displayName: "x", permissions: [] }) }, cookie)
    );
    assert.equal(badId.status, 400);
  });

  it("admin can register secret metadata + capability, values never involved", async () => {
    const good = await loginPOST(
      adminReq("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ username: "test-admin", password: "test-admin-password-000111222333" })
      })
    );
    const cookie = good.headers.get("set-cookie") ?? "";

    process.env.MY_WEATHER_API_KEY = "synthetic-weather-admin-test-key-value";
    const secretRes = await secretsPOST(
      adminReq("/api/admin/secrets", {
        method: "POST",
        body: JSON.stringify({ secretName: "MY_WEATHER_API_KEY", providerId: "http-generic", notes: "weather" })
      }, cookie)
    );
    assert.equal(secretRes.status, 201);
    const secretBody = (await secretRes.json()) as { secret: { secretName: string; status: string } };
    assert.equal(secretBody.secret.status, "CONFIGURED");

    // Attempts to sneak a value/content field in are rejected.
    const sneak = await secretsPOST(
      adminReq("/api/admin/secrets", {
        method: "POST",
        body: JSON.stringify({ secretName: "SNEAK_KEY", providerId: "gemini", value: "sekrit", notes: "" })
      }, cookie)
    );
    assert.equal(sneak.status, 400);

    const capRes = await capsPOST(
      adminReq("/api/admin/capabilities", {
        method: "POST",
        body: JSON.stringify({
          capability: "weather.current",
          providerId: "http-generic",
          secretName: "my_weather_api_key", // normalized to uppercase
          operation: "request",
          config: {
            baseUrl: "https://api.weather.example.com",
            path: "/v1/current",
            method: "GET",
            auth: { placement: "query", name: "appid" }
          }
        })
      }, cookie)
    );
    assert.equal(capRes.status, 200, await capRes.clone().text());

    // SSRF config is refused at registration time.
    const ssrf = await capsPOST(
      adminReq("/api/admin/capabilities", {
        method: "POST",
        body: JSON.stringify({
          capability: "evil.cap",
          providerId: "http-generic",
          secretName: "MY_WEATHER_API_KEY",
          operation: "request",
          config: { baseUrl: "https://169.254.169.254", method: "GET", auth: { placement: "query", name: "appid" } }
        })
      }, cookie)
    );
    assert.equal(ssrf.status, 400);

    // Capability referencing an unregistered secret is refused.
    const noSecret = await capsPOST(
      adminReq("/api/admin/capabilities", {
        method: "POST",
        body: JSON.stringify({
          capability: "bad.cap",
          providerId: "gemini",
          secretName: "UNREGISTERED_KEY",
          operation: "generateText",
          config: {}
        })
      }, cookie)
    );
    assert.equal(noSecret.status, 400);

    // Admin listings expose metadata only.
    const secretsList = await secretsGET(adminReq("/api/admin/secrets", {}, cookie));
    const secretsText = await secretsList.text();
    assert.ok(secretsText.includes("MY_WEATHER_API_KEY"));
    assert.ok(secretsText.includes("CONFIGURED"));
    assert.ok(!secretsText.includes("synthetic-weather-admin-test-key-value"), "secret VALUE leaked to admin listing");

    const capsList = await capsGET(adminReq("/api/admin/capabilities", {}, cookie));
    const capsBody = (await capsList.json()) as { capabilities: { capability: string }[]; adapters: unknown[] };
    assert.ok(capsBody.capabilities.some((x) => x.capability === "weather.current"));
    assert.ok(capsBody.adapters.length >= 3);
  });

  it("admin login brute-forcing gets throttled with 429", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await loginPOST(
        adminReq("/api/admin/login", {
          method: "POST",
          body: JSON.stringify({ username: "test-admin", password: `wrong-${i}` }),
          headers: { "x-forwarded-for": "203.0.113.9" }
        })
      );
      assert.equal(res.status, 401);
    }
    const blocked = await loginPOST(
      adminReq("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ username: "test-admin", password: "wrong-again" }),
        headers: { "x-forwarded-for": "203.0.113.9" }
      })
    );
    assert.equal(blocked.status, 429);
  });
});
