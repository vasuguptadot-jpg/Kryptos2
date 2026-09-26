import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { handleExecuteRequest } from "../src/lib/pipeline";
import { setupTestEnvironment, type TestContext } from "./helpers";
import { KryptosClient } from "../sdk/kryptos-client";

/**
 * Contract test for the optional TS client against the real execute pipeline
 * (wrapped by a throwaway local HTTP server — no provider secrets involved;
 * the stubbed fetch answers as Gemini).
 */
describe("KryptosClient SDK", () => {
  let ctx: TestContext;
  let server: Server;
  let baseUrl: string;

  before(async () => {
    ctx = await setupTestEnvironment();
    server = createServer((req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === "string") headers[k] = v;
        }
        const webReq = new Request(`http://localhost${req.url}`, {
          method: req.method,
          headers,
          body: chunks.length ? Buffer.concat(chunks) : undefined
        });
        const out = await handleExecuteRequest(webReq);
        res.statusCode = out.status;
        out.headers.forEach((value, key) => res.setHeader(key, value));
        res.end(Buffer.from(await out.arrayBuffer()));
      })();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("executes a capability and returns only the provider result", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "SDK_APP",
      permissions: [{ permission: "gemini.generate", rateLimitPerMinute: null }]
    });
    const client = new KryptosClient({ baseUrl, appId: app.appId, appKey: key });
    const res = await client.execute<{ text: string }>("gemini.generate", {
      model: "gemini-2.0-flash",
      prompt: "hello from sdk"
    });
    assert.ok(res.ok, JSON.stringify(res));
    if (res.ok) {
      assert.equal(res.capability, "gemini.generate");
      assert.equal(res.provider, "gemini");
      assert.match(res.result.text, /synthetic gemini reply/);
      // The SDK contract: nothing about secrets comes back.
      const text = JSON.stringify(res);
      assert.ok(!text.includes("synthetic-gemini"));
      assert.ok(!text.includes("GEMINI_API_KEY"));
      assert.ok(!text.includes("secretName"));
    }
  });

  it("surfaces authorization failures as structured errors", async () => {
    const client = new KryptosClient({ baseUrl, appId: "SDK_APP", appKey: "krk_deadbeef" });
    const res = await client.execute("gemini.generate", { prompt: "hi" });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.status, 401);
      assert.equal(res.code, "invalid_credentials");
      assert.ok(res.requestId);
    }
  });

  it("surfaces unknown capabilities", async () => {
    const { app, key } = await ctx.makeApp({
      appId: "SDK_APP2",
      permissions: [{ permission: "nope.cap", rateLimitPerMinute: null }]
    });
    const client = new KryptosClient({ baseUrl, appId: app.appId, appKey: key });
    const res = await client.execute("nope.cap", {});
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.status, 404);
  });
});
