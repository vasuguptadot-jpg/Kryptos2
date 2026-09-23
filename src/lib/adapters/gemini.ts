import { httpJson, modelAllowlist, providerTimeoutMs } from "./types";
import type { Adapter, AdapterResult, CapabilityContext, ConfigValidation } from "./types";

const BASE_URL = "https://generativelanguage.googleapis.com"; // fixed, never client-controlled
const MAX_PROMPT_CHARS = 16_000;
const MAX_OUTPUT_TOKENS = 2048;
const MAX_RESPONSE_CHARS = 20_000;
const INPUT_KEYS = new Set(["model", "prompt", "maxOutputTokens", "temperature", "systemInstruction"]);

interface GeminiInput {
  model: string;
  prompt: string;
  maxOutputTokens: number;
  temperature?: number;
  systemInstruction?: string;
}

function validateInput(input: unknown, config: Record<string, unknown>): { ok: true; value: GeminiInput } | { ok: false; error: string } {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, error: "input must be a JSON object" };
  }
  const b = input as Record<string, unknown>;
  for (const key of Object.keys(b)) {
    if (!INPUT_KEYS.has(key)) return { ok: false, error: `unsupported input field: ${key}` };
  }
  const allowed = modelAllowlist("GEMINI_MODEL_ALLOWLIST", config, [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b"
  ]);
  let model = allowed[0];
  if (b.model !== undefined) {
    if (typeof b.model !== "string" || b.model.length === 0 || b.model.length > 100) {
      return { ok: false, error: "model must be a non-empty string" };
    }
    if (!allowed.includes(b.model)) return { ok: false, error: "model is not on the server allowlist" };
    model = b.model;
  }
  if (typeof b.prompt !== "string" || b.prompt.length === 0 || b.prompt.length > MAX_PROMPT_CHARS) {
    return { ok: false, error: `prompt must be 1..${MAX_PROMPT_CHARS} characters` };
  }
  let maxOutputTokens = 1024;
  if (b.maxOutputTokens !== undefined) {
    if (
      typeof b.maxOutputTokens !== "number" ||
      !Number.isInteger(b.maxOutputTokens) ||
      b.maxOutputTokens < 1 ||
      b.maxOutputTokens > MAX_OUTPUT_TOKENS
    ) {
      return { ok: false, error: `maxOutputTokens must be an integer 1..${MAX_OUTPUT_TOKENS}` };
    }
    maxOutputTokens = b.maxOutputTokens;
  }
  let temperature: number | undefined;
  if (b.temperature !== undefined) {
    if (typeof b.temperature !== "number" || b.temperature < 0 || b.temperature > 2) {
      return { ok: false, error: "temperature must be a number 0..2" };
    }
    temperature = b.temperature;
  }
  let systemInstruction: string | undefined;
  if (b.systemInstruction !== undefined) {
    if (typeof b.systemInstruction !== "string" || b.systemInstruction.length > 4_000) {
      return { ok: false, error: "systemInstruction must be a string up to 4000 characters" };
    }
    systemInstruction = b.systemInstruction;
  }
  return { ok: true, value: { model, prompt: b.prompt, maxOutputTokens, temperature, systemInstruction } };
}

function buildBody(p: GeminiInput): unknown {
  return {
    contents: [{ role: "user", parts: [{ text: p.prompt }] }],
    ...(p.systemInstruction ? { systemInstruction: { parts: [{ text: p.systemInstruction }] } } : {}),
    generationConfig: {
      maxOutputTokens: p.maxOutputTokens,
      ...(p.temperature !== undefined ? { temperature: p.temperature } : {})
    }
  };
}

function extractText(json: unknown): string {
  const candidates = (json as { candidates?: { content?: { parts?: { text?: string }[] } }[] })?.candidates;
  const parts = candidates?.[0]?.content?.parts ?? [];
  return parts.map((p) => p.text ?? "").join("");
}

export const geminiAdapter: Adapter = {
  providerId: "gemini",
  supportedOperations: ["generateText", "test"],

  validateConfig(config: unknown): ConfigValidation {
    if (config === undefined || config === null) return { ok: true, config: {} };
    if (typeof config !== "object" || Array.isArray(config)) {
      return { ok: false, error: "config must be an object" };
    }
    const c = config as Record<string, unknown>;
    for (const key of Object.keys(c)) {
      if (key !== "modelAllowlist") return { ok: false, error: `unsupported config field: ${key}` };
    }
    if (c.modelAllowlist !== undefined) {
      if (
        !Array.isArray(c.modelAllowlist) ||
        c.modelAllowlist.length === 0 ||
        !c.modelAllowlist.every((m) => typeof m === "string" && m.length <= 100)
      ) {
        return { ok: false, error: "modelAllowlist must be a non-empty array of short strings" };
      }
    }
    return { ok: true, config: c };
  },

  async execute(ctx: CapabilityContext): Promise<AdapterResult> {
    if (ctx.capability.operation === "test") {
      const model = modelAllowlist("GEMINI_MODEL_ALLOWLIST", ctx.capability.config, ["gemini-2.0-flash"])[0];
      const started = Date.now();
      await httpJson(
        `${BASE_URL}/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        {
          method: "POST",
          headers: { "x-goog-api-key": ctx.secret }, // to Google only; never returned
          body: { contents: [{ role: "user", parts: [{ text: "ping" }] }], generationConfig: { maxOutputTokens: 4 } }
        },
        providerTimeoutMs()
      );
      return { ok: true, status: 200, data: { status: "ok", model, latencyMs: Date.now() - started } };
    }

    const validation = validateInput(ctx.input, ctx.capability.config);
    if (!validation.ok) {
      return { ok: false, status: 400, data: null, errorCode: `invalid_request: ${validation.error}` };
    }
    const p = validation.value;
    const { json } = await httpJson(
      `${BASE_URL}/v1beta/models/${encodeURIComponent(p.model)}:generateContent`,
      { method: "POST", headers: { "x-goog-api-key": ctx.secret }, body: buildBody(p) },
      providerTimeoutMs()
    );
    const usage = (json as { usageMetadata?: Record<string, number> })?.usageMetadata ?? {};
    return {
      ok: true,
      status: 200,
      data: {
        model: p.model,
        text: extractText(json).slice(0, MAX_RESPONSE_CHARS),
        usage: { promptTokenCount: usage.promptTokenCount ?? null, candidatesTokenCount: usage.candidatesTokenCount ?? null },
        finishReason: (json as { candidates?: { finishReason?: string }[] })?.candidates?.[0]?.finishReason ?? null
      }
    };
  }
};
