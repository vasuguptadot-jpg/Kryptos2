import { randomUUID } from "node:crypto";
import { getAdapter } from "./adapters/registry";
import { ProviderHttpError } from "./adapters/types";
import { authenticateRequest, findPermission, hashClientIp } from "./auth";
import { diagnosticFromCaught } from "./db-diagnostics";
import { json, jsonError } from "./http";
import { recordFailureAndCheck } from "./limiter";
import { logger } from "./logger";
import { resolveSecretForCapability } from "./resolver";
import { getStore } from "./store";
import type { AuditEvent } from "./types";

function logStoreFailure(event: string, requestId: string, err: unknown): void {
  const diag = diagnosticFromCaught(err);
  logger.error(event, {
    requestId,
    diagnostic: diag.code,
    reason: diag.reason,
    tlsVerification: diag.tlsVerification
  });
}

export const MAX_BODY_BYTES = 64 * 1024; // 64 KiB hard cap

interface FailureCtx {
  applicationId?: string | null;
  appId?: string | null;
  remaining?: number | null;
  provider?: string | null;
}

async function record(
  event: Omit<AuditEvent, "actor" | "applicationId" | "appId" | "ipHash"> & Partial<AuditEvent>
): Promise<void> {
  try {
    const store = getStore();
    await store.insertAudit({
      actor: "app",
      applicationId: null,
      appId: null,
      ipHash: null,
      ...event
    } as AuditEvent);
    logger.info("request", event as Record<string, unknown>);
  } catch (err) {
    logStoreFailure("audit_write_failed", event.requestId, err);
  }
}

async function parseBody(req: Request): Promise<
  | { ok: true; value: unknown }
  | { ok: false; status: 400 | 413; code: string; message: string }
> {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (contentLength > MAX_BODY_BYTES) {
    return { ok: false, status: 413, code: "payload_too_large", message: "Request body exceeds the 64 KiB limit" };
  }
  let raw = "";
  try {
    raw = await req.text();
  } catch {
    return { ok: false, status: 400, code: "invalid_body", message: "Unable to read request body" };
  }
  if (raw.length > MAX_BODY_BYTES) {
    return { ok: false, status: 413, code: "payload_too_large", message: "Request body exceeds the 64 KiB limit" };
  }
  if (raw.trim().length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch {
    return { ok: false, status: 400, code: "invalid_json", message: "Request body must be valid JSON" };
  }
}

/**
 * THE guarded capability pipeline:
 *   authenticate → brute-force guard → authorize (capability permission) →
 *   brute/… rate-limit → resolve capability config → resolve provider adapter →
 *   resolve server-side secret → execute → sanitize → audit.
 *
 * The client names ONLY the capability. Secret selection, provider selection
 * and provider config are derived exclusively from server-side registry data.
 * Authorization ALWAYS precedes secret resolution.
 */
async function runCapability(
  req: Request,
  capability: string,
  input: unknown,
  responseShape: "wrapped" | "legacy"
): Promise<Response> {
  const started = Date.now();
  const requestId = randomUUID();
  const endpoint = new URL(req.url).pathname;
  const ipHash = hashClientIp(req);
  const base = { requestId, endpoint, operation: capability, ipHash };

  const finish = async (
    res: Response,
    outcome: "success" | "failure",
    errorCode: string | null,
    ctx: FailureCtx = {}
  ): Promise<Response> => {
    await record({
      ...base,
      provider: ctx.provider ?? null,
      actor: "app",
      applicationId: ctx.applicationId ?? null,
      appId: ctx.appId ?? null,
      outcome,
      httpStatus: res.status,
      latencyMs: Date.now() - started,
      rateLimitRemaining: ctx.remaining ?? null,
      errorCode
    });
    res.headers.set("x-request-id", requestId);
    return res;
  };

  if (req.method !== "POST") {
    return finish(jsonError(405, "method_not_allowed", "Method not allowed", requestId), "failure", "method_not_allowed");
  }

  // --- 1. Authentication (fail closed) -------------------------------------
  const auth = await authenticateRequest(req);
  if (!auth.ok) {
    // Blunt credential stuffing: ~30 failed attempts/min per (ip, appId) pair.
    const throttled = recordFailureAndCheck(`auth:${ipHash ?? "unknown"}:${auth.appId ?? "?"}`, 30, 60_000);
    const res = throttled
      ? jsonError(429, "rate_limited", "Too many failed attempts", requestId, { "retry-after": "60" })
      : jsonError(auth.status, auth.code, "Request is not authorized", requestId);
    return finish(res, "failure", throttled ? "rate_limited" : auth.code, { appId: auth.appId });
  }
  const { app, permissions } = auth;

  // --- 2. Capability permission (server decides the secret, not the client) --
  const perm = findPermission(permissions, capability);
  if (!perm) {
    return finish(
      jsonError(403, "operation_not_permitted", "This application is not permitted to use this capability", requestId),
      "failure",
      "operation_not_permitted",
      { applicationId: app.id, appId: app.appId }
    );
  }

  // --- 3. Per-app, per-capability rate limiting (fail closed) ---------------
  let store;
  try {
    store = getStore();
  } catch (err) {
    logStoreFailure("rate_limit_store_unavailable", requestId, err);
    return finish(
      jsonError(503, "rate_limit_unavailable", "Service unavailable", requestId),
      "failure",
      "rate_limit_unavailable",
      { applicationId: app.id, appId: app.appId }
    );
  }
  const limit = perm.rateLimitPerMinute ?? app.defaultRateLimit ?? 60;
  const now = new Date();
  const windowStart = new Date(now);
  windowStart.setSeconds(0, 0);
  let count: number;
  try {
    count = await store.incrementRateLimit(app.id, capability, windowStart);
    if (Math.random() < 0.05) {
      store.pruneRateLimits(new Date(now.getTime() - 10 * 60 * 1000)).catch(() => undefined);
    }
  } catch (err) {
    logStoreFailure("rate_limit_increment_failed", requestId, err);
    return finish(
      jsonError(503, "rate_limit_unavailable", "Service unavailable", requestId),
      "failure",
      "rate_limit_unavailable",
      { applicationId: app.id, appId: app.appId }
    );
  }
  const remaining = Math.max(0, limit - count);
  const rateHeaders = {
    "x-ratelimit-limit": String(limit),
    "x-ratelimit-remaining": String(remaining),
    "x-ratelimit-reset": String(Math.ceil(windowStart.getTime() / 1000) + 60)
  };
  if (count > limit) {
    const retryAfter = 60 - now.getSeconds();
    return finish(
      jsonError(429, "rate_limited", "Rate limit exceeded for this capability", requestId, {
        ...rateHeaders,
        "retry-after": String(retryAfter)
      }),
      "failure",
      "rate_limited",
      { applicationId: app.id, appId: app.appId, remaining: 0 }
    );
  }

  // --- 4. Resolve capability configuration (server-side registry) -----------
  let cap;
  try {
    cap = await store.getCapability(capability);
  } catch (err) {
    logStoreFailure("capability_lookup_failed", requestId, err);
    return finish(
      jsonError(503, "configuration_unavailable", "Service unavailable", requestId, rateHeaders),
      "failure",
      "configuration_unavailable",
      { applicationId: app.id, appId: app.appId, remaining }
    );
  }
  if (!cap) {
    return finish(
      jsonError(404, "unknown_capability", "Unknown capability", requestId, rateHeaders),
      "failure",
      "unknown_capability",
      { applicationId: app.id, appId: app.appId, remaining }
    );
  }
  if (!cap.enabled) {
    return finish(
      jsonError(403, "capability_disabled", "This capability is currently disabled", requestId, rateHeaders),
      "failure",
      "capability_disabled",
      { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
    );
  }
  const adapter = getAdapter(cap.providerId);
  if (!adapter || !adapter.supportedOperations.includes(cap.operation)) {
    return finish(
      jsonError(503, "capability_misconfigured", "Capability configuration error", requestId, rateHeaders),
      "failure",
      "capability_misconfigured",
      { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
    );
  }

  // --- 5. Resolve the server-side secret (server-only resolver) -------------
  const resolution = await resolveSecretForCapability(store, cap);
  if (!resolution.ok) {
    return finish(
      jsonError(resolution.status, resolution.code, "This capability is not available", requestId, rateHeaders),
      "failure",
      resolution.code,
      { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
    );
  }

  // --- 6. Execute through the provider adapter ------------------------------
  try {
    const result = await adapter.execute({ capability: cap, input, secret: resolution.secret });
    if (!result.ok && result.status === 400) {
      const [, message] = (result.errorCode ?? "invalid_request").split(/invalid_request: ?/);
      return finish(
        jsonError(400, "invalid_request", message ?? "Invalid input", requestId, rateHeaders),
        "failure",
        "invalid_request",
        { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
      );
    }
    if (!result.ok) {
      return finish(
        jsonError(result.status === 400 ? 400 : 502, "provider_error", "The provider request failed", requestId, rateHeaders),
        "failure",
        "provider_error",
        { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
      );
    }
    const payload =
      responseShape === "legacy"
        ? { provider: cap.providerId, ...(typeof result.data === "object" && result.data !== null ? result.data : { data: result.data }) }
        : { capability: cap.capability, provider: cap.providerId, result: result.data };
    return finish(json(payload, 200, rateHeaders), "success", null, {
      applicationId: app.id,
      appId: app.appId,
      remaining,
      provider: cap.providerId
    });
  } catch (err) {
    if (err instanceof ProviderHttpError) {
      return finish(
        jsonError(err.status, "provider_error", err.message, requestId, rateHeaders),
        "failure",
        "provider_error",
        { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
      );
    }
    logger.error("provider_unexpected_error", {
      requestId,
      capability,
      error: err instanceof Error ? err.message : "unknown"
    });
    return finish(
      jsonError(502, "provider_error", "The provider request failed", requestId, rateHeaders),
      "failure",
      "provider_error",
      { applicationId: app.id, appId: app.appId, remaining, provider: cap.providerId }
    );
  }
}

/**
 * Public capability endpoint:  POST /api/v1/execute
 * Body: { "capability": "ai.generate", "input": { … } }  — strictly these keys.
 */
export async function handleExecuteRequest(req: Request): Promise<Response> {
  const parsed = await parseBody(req);
  if (!parsed.ok) {
    return jsonError(parsed.status, parsed.code, parsed.message, randomUUID());
  }
  const body = parsed.value;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return jsonError(400, "invalid_request", "Body must be a JSON object {capability, input}");
  }
  const b = body as Record<string, unknown>;
  for (const key of Object.keys(b)) {
    // Envelope keys only — clients may never steer secret/provider selection.
    if (key !== "capability" && key !== "input") {
      return jsonError(400, "invalid_request", `unsupported field: ${key}`);
    }
  }
  if (typeof b.capability !== "string" || b.capability.length === 0 || b.capability.length > 120) {
    return jsonError(400, "invalid_request", "capability must be a non-empty string");
  }
  return runCapability(req, b.capability, b.input, "wrapped");
}

/**
 * Legacy provider-specific routes (/api/v1/gemini, /api/v1/groq[/test]).
 * Kept as thin aliases: the body IS the input; the capability name comes from
 * the route, not the request. New clients should use /api/v1/execute.
 */
export async function handleLegacyProviderRequest(
  req: Request,
  capability: string
): Promise<Response> {
  const parsed = await parseBody(req);
  if (!parsed.ok) {
    return jsonError(parsed.status, parsed.code, parsed.message, randomUUID());
  }
  return runCapability(req, capability, parsed.value, "legacy");
}
