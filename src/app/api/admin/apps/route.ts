import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { generateCredential } from "@/lib/credentials";
import { json, jsonError } from "@/lib/http";

import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const APP_ID_RE = /^[A-Z][A-Z0-9_]{1,39}$/;

export async function GET(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  try {
    const store = getStore();
    const [apps, stats] = await Promise.all([store.listApplications(), store.stats()]);
    const perApp = new Map(stats.perApplication.map((a) => [a.appId, a]));
    return json({
      applications: apps.map((a) => ({
        id: a.id,
        appId: a.appId,
        displayName: a.displayName,
        status: a.status,
        defaultRateLimit: a.defaultRateLimit,
        createdAt: a.createdAt,
        lastUsedAt: a.lastUsedAt,
        usage: perApp.get(a.appId) ?? { total: 0, failures: 0 }
      }))
    });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

/**
 * Create a new client application. The generated credential is returned
 * exactly once in this response and is stored only as a hash.
 */
export async function POST(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError(400, "invalid_json", "Request body must be valid JSON");
  }
  const b = (body ?? {}) as Record<string, unknown>;
  const appId = typeof b.appId === "string" ? b.appId.trim().toUpperCase() : "";
  const displayName = typeof b.displayName === "string" ? b.displayName.trim() : "";
  if (!APP_ID_RE.test(appId)) {
    return jsonError(
      400,
      "invalid_request",
      "appId must be 2-40 chars: A-Z, 0-9, _ (e.g. MAHOLLA)"
    );
  }
  if (displayName.length < 2 || displayName.length > 80) {
    return jsonError(400, "invalid_request", "displayName must be 2-80 characters");
  }
  let defaultRateLimit = Number(process.env.APP_DEFAULT_RATE_LIMIT ?? "60");
  if (b.defaultRateLimit !== undefined) {
    if (
      typeof b.defaultRateLimit !== "number" ||
      !Number.isInteger(b.defaultRateLimit) ||
      b.defaultRateLimit < 1 ||
      b.defaultRateLimit > 100_000
    ) {
      return jsonError(400, "invalid_request", "defaultRateLimit must be an integer 1..100000");
    }
    defaultRateLimit = b.defaultRateLimit;
  }
  let validPermissions: Set<string>;
  try {
    validPermissions = new Set((await getStore().listCapabilities()).map((c) => c.capability));
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
  const permissions: { permission: string; rateLimitPerMinute: number | null }[] = [];
  if (b.permissions !== undefined) {
    if (!Array.isArray(b.permissions)) {
      return jsonError(400, "invalid_request", "permissions must be an array");
    }
    for (const p of b.permissions as Record<string, unknown>[]) {
      const permission = typeof p.permission === "string" ? p.permission : "";
      if (!validPermissions.has(permission)) {
        return jsonError(400, "invalid_request", `unknown permission: ${permission || "(empty)"}`);
      }
      let rateLimitPerMinute: number | null = null;
      if (p.rateLimitPerMinute !== undefined && p.rateLimitPerMinute !== null) {
        if (
          typeof p.rateLimitPerMinute !== "number" ||
          !Number.isInteger(p.rateLimitPerMinute) ||
          p.rateLimitPerMinute < 1 ||
          p.rateLimitPerMinute > 100_000
        ) {
          return jsonError(400, "invalid_request", "rateLimitPerMinute must be an integer 1..100000");
        }
        rateLimitPerMinute = p.rateLimitPerMinute;
      }
      permissions.push({ permission, rateLimitPerMinute });
    }
  }

  try {
    const store = getStore();
    const app = await store.createApplication({ appId, displayName, defaultRateLimit });
    if (permissions.length > 0) await store.setPermissions(app.id, permissions);
    const cred = generateCredential();
    await store.createCredential(app.id, cred.keyHash, cred.keyPrefix);
    await auditAdmin(req, "app.create", "success", 201);
    return json(
      {
        application: {
          id: app.id,
          appId: app.appId,
          displayName: app.displayName,
          status: app.status,
          defaultRateLimit: app.defaultRateLimit
        },
        // Shown ONCE. Only its sha256 hash is stored. Treat it as a secret.
        credential: cred.rawKey,
        credentialPrefix: cred.keyPrefix,
        instructions:
          "Store this credential in the client application's own server/config now. It cannot be retrieved again."
      },
      201
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    await auditAdmin(req, "app.create", "failure", 400, message);
    if (message === "app_id_exists") {
      return jsonError(409, "app_id_exists", "An application with this appId already exists");
    }
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

export async function OPTIONS(): Promise<Response> {
  return jsonError(405, "method_not_allowed", "Method not allowed");
}
