import { randomUUID } from "node:crypto";
import { isAdminRequest } from "./admin-session";
import { jsonError } from "./http";
import { logger } from "./logger";
import { getStore } from "./store";
import type { AuditEvent } from "./types";

/** Returns null when authorized, otherwise the 401/503 Response to send. */
export function requireAdmin(req: Request): Response | null {
  if (!isAdminRequest(req)) {
    return jsonError(401, "admin_auth_required", "Administrator authentication required");
  }
  return null;
}

/** Audit an administrative action (best-effort). */
export async function auditAdmin(
  req: Request,
  action: string,
  outcome: "success" | "failure",
  httpStatus: number,
  errorCode: string | null = null
): Promise<void> {
  const event: AuditEvent = {
    actor: "admin",
    applicationId: null,
    appId: null,
    requestId: randomUUID(),
    endpoint: `${new URL(req.url).pathname} (${action})`,
    provider: null,
    operation: action,
    outcome,
    httpStatus,
    latencyMs: 0,
    rateLimitRemaining: null,
    errorCode,
    ipHash: null
  };
  try {
    await getStore().insertAudit(event);
  } catch {
    /* never let auditing break admin ops */
  }
  logger.info("admin_action", { action, outcome, httpStatus, errorCode });
}
