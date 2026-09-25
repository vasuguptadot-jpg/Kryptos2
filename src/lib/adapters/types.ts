import { redactSecrets } from "../secrets";
import type { CapabilityRecord } from "../types";

export interface AdapterResult {
  ok: boolean;
  status: number;
  /** Safe, provider-derived payload only — adapter code must never include the secret. */
  data: unknown;
  errorCode?: string;
}

export interface CapabilityContext {
  capability: CapabilityRecord;
  /** Client-supplied operation input (NOT the request envelope). */
  input: unknown;
  /** Server-resolved secret value. Exists only inside execute(). */
  secret: string;
}

export type ConfigValidation =
  | { ok: true; config: Record<string, unknown> }
  | { ok: false; error: string };

/**
 * A provider adapter. Separates: application capability → provider adapter →
 * secret reference → external provider. Adapters are modular; the
 * `http-generic` adapter covers arbitrary HTTPS providers via admin-approved
 * configuration (explicit destination, never client-chosen URLs).
 */
export interface Adapter {
  providerId: string;
  /** Operations this adapter implements (stored on the capability record). */
  supportedOperations: string[];
  /** Strictly validate adapter config at registration time. */
  validateConfig(config: unknown): ConfigValidation;
  execute(ctx: CapabilityContext): Promise<AdapterResult>;
}

export class ProviderHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const MAX_UPSTREAM_BODY = 256 * 1024;

export async function httpJson(
  url: string,
  init: { method: string; headers?: Record<string, string>; body?: unknown },
  timeoutMs: number
): Promise<{ status: number; json: unknown; text: string }> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      headers: { ...(init.body !== undefined ? { "content-type": "application/json" } : {}), ...(init.headers ?? {}) },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error"
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "network error";
    throw new ProviderHttpError(502, redactSecrets(`provider request failed: ${msg}`));
  }
  const text = await res.text();
  if (text.length > MAX_UPSTREAM_BODY) {
    throw new ProviderHttpError(502, "provider response too large");
  }
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null; // non-JSON upstream; keep raw text
  }
  if (!res.ok) {
    const excerpt = redactSecrets(text.slice(0, 300));
    throw new ProviderHttpError(502, `provider error (${res.status}): ${excerpt}`);
  }
  return { status: res.status, json, text };
}

export function providerTimeoutMs(): number {
  const v = Number(process.env.PROVIDER_TIMEOUT_MS ?? "30000");
  return Number.isFinite(v) && v >= 1000 ? v : 30_000;
}

export function modelAllowlist(
  envName: string,
  config: Record<string, unknown> | undefined,
  fallback: string[]
): string[] {
  const fromConfig = config?.modelAllowlist;
  if (
    Array.isArray(fromConfig) &&
    fromConfig.length > 0 &&
    fromConfig.every((m) => typeof m === "string" && m.length <= 100)
  ) {
    return fromConfig as string[];
  }
  const raw = process.env[envName];
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.every((m) => typeof m === "string") && parsed.length > 0) {
      return parsed as string[];
    }
  } catch {
    /* fall through */
  }
  return fallback;
}
