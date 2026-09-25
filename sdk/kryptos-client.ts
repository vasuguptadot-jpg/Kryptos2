/**
 * KryptosClient — minimal capability client for applications using Kryptos.
 *
 * The SDK knows ONLY:
 *   - the broker base URL
 *   - the application's own credential (appId + appKey)
 *   - capability names (e.g. "ai.generate")
 *
 * It contains NO provider secrets and must never be given one. Keep appKey
 * in your own app's secure config (server env / keystore), not in shipped
 * client binaries where practical, and rotate it if compromised.
 */

export interface KryptosClientOptions {
  /** e.g. "https://kryptos.example.com" — no trailing slash needed. */
  baseUrl: string;
  appId: string;
  appKey: string;
  timeoutMs?: number;
  /** Inject for tests (defaults to globalThis.fetch). */
  fetchImpl?: typeof fetch;
}

export interface KryptosSuccess<T = unknown> {
  ok: true;
  capability: string;
  provider: string;
  result: T;
}

export interface KryptosFailure {
  ok: false;
  status: number;
  code: string;
  message: string;
  requestId?: string;
}

export type KryptosResponse<T = unknown> = KryptosSuccess<T> | KryptosFailure;

export class KryptosClient {
  private readonly baseUrl: string;
  private readonly appId: string;
  private readonly appKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: KryptosClientOptions) {
    if (!options.baseUrl || !options.appId || !options.appKey) {
      throw new Error("KryptosClient requires baseUrl, appId and appKey");
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.appId = options.appId;
    this.appKey = options.appKey;
    this.timeoutMs = options.timeoutMs ?? 45_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /** Execute a registered capability. Only the provider result comes back. */
  async execute<T = unknown>(capability: string, input: unknown): Promise<KryptosResponse<T>> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/api/v1/execute`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-kryptos-app-id": this.appId,
          "x-kryptos-app-key": this.appKey
        },
        body: JSON.stringify({ capability, input }),
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch (err) {
      return {
        ok: false,
        status: 0,
        code: "network_error",
        message: err instanceof Error ? err.message : "request failed"
      };
    }
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      return { ok: false, status: res.status, code: "invalid_response", message: "non-JSON response" };
    }
    if (!res.ok) {
      const error = (body.error ?? {}) as { code?: unknown; message?: unknown };
      return {
        ok: false,
        status: res.status,
        code: typeof error.code === "string" ? error.code : "unknown_error",
        message: typeof error.message === "string" ? error.message : `HTTP ${res.status}`,
        requestId: typeof body.requestId === "string" ? body.requestId : undefined
      };
    }
    return {
      ok: true,
      capability: String(body.capability ?? capability),
      provider: String(body.provider ?? ""),
      result: body.result as T
    };
  }

  /** Public broker health (no secrets involved). */
  async health(): Promise<Record<string, unknown>> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/health`, {
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    return (await res.json()) as Record<string, unknown>;
  }
}

export default KryptosClient;
