import { createHash } from "node:crypto";
import { verifyCredential } from "./credentials";
import { getStore } from "./store";
import type { ApplicationRecord, PermissionRecord } from "./types";

export const APP_ID_HEADER = "x-kryptos-app-id";
export const APP_KEY_HEADER = "x-kryptos-app-key";

export type AuthResult =
  | { ok: true; app: ApplicationRecord; permissions: PermissionRecord[] }
  | { ok: false; status: 401 | 403 | 503; code: string; appId: string | null };

/**
 * Authenticate an application request using X-Kryptos-App-Id / X-Kryptos-App-Key.
 * Fails closed: any store outage or missing data results in a denial,
 * never a bypass.
 */
export async function authenticateRequest(req: Request): Promise<AuthResult> {
  const appId = req.headers.get(APP_ID_HEADER)?.trim() ?? "";
  const appKey = req.headers.get(APP_KEY_HEADER) ?? "";
  if (!appId || !appKey) {
    return { ok: false, status: 401, code: "missing_credentials", appId: appId || null };
  }

  let store;
  try {
    store = getStore();
  } catch {
    return { ok: false, status: 503, code: "authorization_unavailable", appId };
  }

  let app: ApplicationRecord | null;
  let permissions: PermissionRecord[];
  try {
    app = await store.getApplicationByAppId(appId);
    if (!app) return { ok: false, status: 401, code: "invalid_credentials", appId };
    if (app.status === "revoked") return { ok: false, status: 403, code: "app_revoked", appId };
    if (app.status === "disabled") return { ok: false, status: 403, code: "app_disabled", appId };

    const credentials = await store.getActiveCredentials(app.id);
    const now = new Date();
    for (const cred of credentials) {
      if (verifyCredential(appKey, cred.keyHash)) {
        permissions = await store.getPermissions(app.id);
        // Best-effort bookkeeping; must not jeopardize the request.
        store.touchCredential(cred.id, app.id, now).catch(() => undefined);
        return { ok: true, app, permissions };
      }
    }
    return { ok: false, status: 401, code: "invalid_credentials", appId };
  } catch {
    return { ok: false, status: 503, code: "authorization_unavailable", appId };
  }
}

export function findPermission(
  permissions: PermissionRecord[],
  operation: string
): PermissionRecord | null {
  return permissions.find((p) => p.permission === operation) ?? null;
}

/** sha256 of caller IP for audit correlation without storing raw PII. */
export function hashClientIp(req: Request): string | null {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    req.headers.get("x-real-ip") ??
    null;
  if (!ip) return null;
  return createHash("sha256").update(ip).digest("hex").slice(0, 24);
}
