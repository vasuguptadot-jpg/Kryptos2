import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { handleExecuteRequest } from "../src/lib/pipeline";
import { executeRequest, setupTestEnvironment, type TestContext } from "./helpers";

const GPT_OSS_MODEL = "openai/gpt-oss-20b";
const GROQ_INPUT = {
  prompt: "Reply with exactly: KRYPTOS generation test passed.",
  maxOutputTokens: 32,
  temperature: 0
};

function mockGroqResponse(payload: unknown) {
  const originalFetch = globalThis.fetch;
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = originalFetch; } };
}

async function requestGroq(ctx: TestContext, appId: string): Promise<Response> {
  const { app, key } = await ctx.makeApp({
    appId,
    permissions: [{ permission: "groq.generate", rateLimitPerMinute: null }]
  });
  return handleExecuteRequest(
    executeRequest(app.appId, key, { capability: "groq.generate", input: GROQ_INPUT })
  );
}

describe("Groq generation adapter", () => {
  let ctx: TestContext;
  before(async () => {
    ctx = await setupTestEnvironment();
  });

  it("returns normal text and sends GPT-OSS reasoning controls without exposing reasoning", async () => {
    const mock = mockGroqResponse({
      choices: [{ message: { content: "KRYPTOS generation test passed.", reasoning: "private reasoning" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 5, completion_tokens: 9 }
    });
    try {
      const res = await requestGroq(ctx, "GROQ_TEXT_APP");
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.result.text, "KRYPTOS generation test passed.");
      assert.equal(body.result.finishReason, "stop");
      assert.ok(!JSON.stringify(body).includes("private reasoning"));
      assert.equal(mock.calls.length, 1);
      assert.equal(mock.calls[0].url, "https://api.groq.com/openai/v1/chat/completions");
      const upstream = JSON.parse(String(mock.calls[0].init?.body));
      assert.equal(upstream.model, GPT_OSS_MODEL);
      assert.equal(upstream.max_completion_tokens, 32);
      assert.equal("max_tokens" in upstream, false);
      assert.equal(upstream.reasoning_effort, "low");
      assert.equal(upstream.include_reasoning, false);
    } finally {
      mock.restore();
    }
  });

  it("rejects empty text without returning provider reasoning", async () => {
    const mock = mockGroqResponse({
      choices: [{ message: { content: " \n ", reasoning: "private reasoning" }, finish_reason: "length" }],
      usage: { prompt_tokens: 5, completion_tokens: 32 }
    });
    try {
      const res = await requestGroq(ctx, "GROQ_EMPTY_APP");
      assert.equal(res.status, 502);
      const body = await res.json();
      assert.deepEqual(body.error, { code: "provider_error", message: "Groq returned an empty completion" });
      assert.ok(!JSON.stringify(body).includes("private reasoning"));
      assert.equal(mock.calls.length, 1);
    } finally {
      mock.restore();
    }
  });

  it("returns available text with the provider truncation reason and does not retry", async () => {
    const mock = mockGroqResponse({
      choices: [{ message: { content: "Partial response" }, finish_reason: "length" }],
      usage: { prompt_tokens: 5, completion_tokens: 32 }
    });
    try {
      const res = await requestGroq(ctx, "GROQ_TRUNCATED_APP");
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.result.text, "Partial response");
      assert.equal(body.result.finishReason, "length");
      assert.equal(mock.calls.length, 1);
    } finally {
      mock.restore();
    }
  });
});
