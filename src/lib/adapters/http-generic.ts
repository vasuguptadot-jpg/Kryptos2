import { httpJson, providerTimeoutMs } from "./types";
import type { Adapter, AdapterResult, CapabilityContext, ConfigValidation } from "./types";

/**
 * Custom HTTPS provider adapter ("http-generic").
 *
 * Lets the operator expose arbitrary providers (weather, maps, internal SaaS…)
 * WITHOUT code changes, while remaining SSRF-safe:
 *  - the destination origin is fixed in admin-approved capability config,
 *    never by the client;
 *  - HTTPS only, no userinfo, no non-default ports, no redirects;
 *  - private / loopback / link-local / metadata hosts are rejected both at
 *    registration time and again at execution time (defense in depth);
 *  - the secret is injected only as the configured header/query parameter and
 *    is sent only to the approved origin;
 *  - client input is validated and can never override the URL or auth.
 *
 * Note: hostname checks are string-level. DNS rebinding is out of scope for V1
 * (documented); keep pinned vendor domains for high-value secrets.
 */

const HEADER_NAME_RE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
const FIELD_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const STATIC_VALUE_MAX = 500;
const MAX_RESPONSE_CHARS = 20_000;

/** Input fields that could attempt to steer resolution — always rejected. */
const FORBIDDEN_INPUT_KEYS = new Set([
  "url", "baseurl", "host", "hostname", "domain", "endpoint", "path",
  "secret", "secretname", "secret_name", "env", "key", "apikey", "api_key",
  "token", "authorization", "auth", "header", "headers", "capability"
]);

export interface HttpGenericConfig {
  baseUrl: string; // approved origin, e.g. "https://api.openweathermap.org"
  path: string; // fixed path prefix (client input may only add query/body)
  method: "GET" | "POST";
  auth: { placement: "header" | "query"; name: string };
  staticHeaders: Record<string, string>;
  inputFields: string[] | null; // null = allow all non-forbidden scalar fields
  responseField: string | null; // optional dot-path to extract from JSON response
}

function isDisallowedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".corp") ||
    h.endsWith(".lan") ||
    h === "metadata.google.internal"
  ) {
    return true;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    const [a, b] = h.split(".").map((n) => Number(n));
    if (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) || // link-local / cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      a >= 224 // multicast/reserved
    ) {
      return true;
    }
  }
  if (h.includes(":")) return true; // IPv6 literals blocked in V1
  return false;
}

/** Validate an approved base URL. Returns the normalized origin. */
export function approveBaseUrl(raw: unknown): { ok: true; origin: string } | { ok: false; error: string } {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 300) {
    return { ok: false, error: "baseUrl must be a non-empty string" };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "baseUrl is not a valid URL" };
  }
  if (url.protocol !== "https:") return { ok: false, error: "baseUrl must use https" };
  if (url.username || url.password) return { ok: false, error: "baseUrl must not contain credentials" };
  if (url.port && url.port !== "443") return { ok: false, error: "baseUrl must use the default https port" };
  if (url.pathname !== "/" || url.search || url.hash) {
    return { ok: false, error: "baseUrl must be an origin only (no path/query)" };
  }
  if (isDisallowedHost(url.hostname)) {
    return { ok: false, error: "baseUrl host is not allowed (private/reserved/metadata hosts rejected)" };
  }
  return { ok: true, origin: url.origin };
}

function validatePath(raw: unknown): { ok: true; path: string } | { ok: false; error: string } {
  if (raw === undefined || raw === "" || raw === "/") return { ok: true, path: "" };
  if (typeof raw !== "string" || raw.length > 200) return { ok: false, error: "path must be a string up to 200 chars" };
  if (!raw.startsWith("/")) return { ok: false, error: "path must start with /" };
  if (raw.includes("..") || raw.includes("//") || raw.includes("://")) {
    return { ok: false, error: "path must not contain .., //, or a scheme" };
  }
  if (!/^\/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*$/.test(raw)) return { ok: false, error: "path contains invalid characters" };
  return { ok: true, path: raw };
}

export const httpGenericAdapter: Adapter = {
  providerId: "http-generic",
  supportedOperations: ["request"],

  validateConfig(config: unknown): ConfigValidation {
    if (typeof config !== "object" || config === null || Array.isArray(config)) {
      return { ok: false, error: "http-generic config must be an object" };
    }
    const c = config as Record<string, unknown>;
    const ALLOWED = new Set(["baseUrl", "path", "method", "auth", "staticHeaders", "inputFields", "responseField"]);
    for (const key of Object.keys(c)) {
      if (!ALLOWED.has(key)) return { ok: false, error: `unsupported config field: ${key}` };
    }
    const origin = approveBaseUrl(c.baseUrl);
    if (!origin.ok) return origin;
    const path = validatePath(c.path);
    if (!path.ok) return path;

    const method = c.method === undefined ? "GET" : (typeof c.method === "string" ? c.method.toUpperCase() : "");
    if (method !== "GET" && method !== "POST") return { ok: false, error: "method must be GET or POST" };

    if (typeof c.auth !== "object" || c.auth === null || Array.isArray(c.auth)) {
      return { ok: false, error: "auth must be an object {placement, name}" };
    }
    const auth = c.auth as Record<string, unknown>;
    if (auth.placement !== "header" && auth.placement !== "query") {
      return { ok: false, error: "auth.placement must be 'header' or 'query'" };
    }
    if (typeof auth.name !== "string" || !HEADER_NAME_RE.test(auth.name) || !FIELD_NAME_RE.test(auth.name)) {
      return { ok: false, error: "auth.name must be a valid header/parameter name" };
    }
    const authName = auth.name;

    let staticHeaders: Record<string, string> = {};
    if (c.staticHeaders !== undefined) {
      if (typeof c.staticHeaders !== "object" || c.staticHeaders === null || Array.isArray(c.staticHeaders)) {
        return { ok: false, error: "staticHeaders must be an object" };
      }
      for (const [k, v] of Object.entries(c.staticHeaders as Record<string, unknown>)) {
        if (!HEADER_NAME_RE.test(k)) return { ok: false, error: `invalid header name: ${k}` };
        if (auth.placement === "header" && k.toLowerCase() === authName.toLowerCase()) {
          return { ok: false, error: "staticHeaders must not override the auth header" };
        }
        if (k.toLowerCase() === "authorization" || k.toLowerCase() === "host" || k.toLowerCase() === "content-length") {
          return { ok: false, error: `header not allowed in staticHeaders: ${k}` };
        }
        if (typeof v !== "string" || v.length > STATIC_VALUE_MAX) {
          return { ok: false, error: `invalid value for header ${k}` };
        }
        staticHeaders[k] = v;
      }
    }

    let inputFields: string[] | null = null;
    if (c.inputFields !== undefined && c.inputFields !== null) {
      if (!Array.isArray(c.inputFields) || !c.inputFields.every((f) => typeof f === "string" && FIELD_NAME_RE.test(f as string))) {
        return { ok: false, error: "inputFields must be an array of field names" };
      }
      inputFields = (c.inputFields as string[]).map(String);
    }

    let responseField: string | null = null;
    if (c.responseField !== undefined && c.responseField !== null) {
      if (typeof c.responseField !== "string" || !/^[A-Za-z0-9_.-]{1,100}$/.test(c.responseField)) {
        return { ok: false, error: "responseField must be a dotted field path" };
      }
      responseField = c.responseField;
    }

    const clean: HttpGenericConfig = {
      baseUrl: origin.origin,
      path: path.path,
      method: method as "GET" | "POST",
      auth: { placement: auth.placement as "header" | "query", name: authName },
      staticHeaders,
      inputFields,
      responseField
    };
    return { ok: true, config: clean as unknown as Record<string, unknown> };
  },

  async execute(ctx: CapabilityContext): Promise<AdapterResult> {
    const config = ctx.capability.config as unknown as HttpGenericConfig;

    // Defense in depth: re-verify the destination at execution time.
    const origin = approveBaseUrl(config.baseUrl);
    if (!origin.ok) {
      return { ok: false, status: 502, data: null, errorCode: "destination_rejected" };
    }

    // --- Client input → safe query/body parameters -------------------------
    const params: Record<string, string> = {};
    if (ctx.input !== undefined && ctx.input !== null) {
      if (typeof ctx.input !== "object" || Array.isArray(ctx.input)) {
        return { ok: false, status: 400, data: null, errorCode: "invalid_request: input must be an object" };
      }
      for (const [k, v] of Object.entries(ctx.input as Record<string, unknown>)) {
        const key = k.toLowerCase();
        if (FORBIDDEN_INPUT_KEYS.has(key)) {
          return { ok: false, status: 400, data: null, errorCode: `invalid_request: forbidden input field ${k}` };
        }
        if (!FIELD_NAME_RE.test(k)) {
          return { ok: false, status: 400, data: null, errorCode: `invalid_request: invalid field name ${k}` };
        }
        if (config.inputFields && !config.inputFields.includes(k)) {
          return { ok: false, status: 400, data: null, errorCode: `invalid_request: field not allowed ${k}` };
        }
        if (config.auth.placement === "query" && key === config.auth.name.toLowerCase()) {
          return { ok: false, status: 400, data: null, errorCode: "invalid_request: cannot override auth parameter" };
        }
        if (typeof v === "string" && v.length <= 500) params[k] = v;
        else if (typeof v === "number" && Number.isFinite(v)) params[k] = String(v);
        else if (typeof v === "boolean") params[k] = String(v);
        else return { ok: false, status: 400, data: null, errorCode: `invalid_request: unsupported value for ${k}` };
      }
    }

    const url = new URL(origin.origin + (config.path || "/"));
    if (config.auth.placement === "query") {
      url.searchParams.set(config.auth.name, ctx.secret); // secret only to the approved origin
    }
    // GET also uses query for client params; POST uses a JSON body.
    let body: unknown;
    if (config.method === "GET") {
      for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    } else {
      body = params;
    }

    const headers: Record<string, string> = { ...config.staticHeaders };
    if (config.auth.placement === "header") {
      headers[config.auth.name] = ctx.secret; // secret only to the approved origin
    }

    const upstream = await httpJson(url.toString(), { method: config.method, headers, body }, providerTimeoutMs());

    // --- Sanitize the response ----------------------------------------------
    let payload: unknown = upstream.json !== null ? upstream.json : upstream.text;
    if (config.responseField && upstream.json !== null) {
      payload = config.responseField.split(".").reduce<unknown>((acc, part) => {
        if (acc && typeof acc === "object" && !Array.isArray(acc)) {
          return (acc as Record<string, unknown>)[part];
        }
        return undefined;
      }, upstream.json);
    }
    const serialized = JSON.stringify({ data: payload });
    const bounded = serialized.length > MAX_RESPONSE_CHARS * 2 ? { data: "response truncated", truncated: true } : null;
    return {
      ok: true,
      status: 200,
      data: bounded ?? { data: payload }
    };
  }
};
