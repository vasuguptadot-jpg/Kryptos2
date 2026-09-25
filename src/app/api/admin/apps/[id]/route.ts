import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";
import type { AppStatus } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VALID_STATUSES: AppStatus[] = ["active", "disabled", "revoked"];

/**
 * Update an application's status:
 *  - "disabled": temporarily blocked (reversible)
 *  - "revoked":  permanently blocked AND all its credentials revoked
 *  - "active":   re-enable a disabled app
 */
export async function PATCH(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const { id } = await params;
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError(400, "invalid_json", "Request body must be valid JSON");
  }
  const status = (body as Record<string, unknown>)?.status;
  if (typeof status !== "string" || !VALID_STATUSES.includes(status as AppStatus)) {
    return jsonError(400, "invalid_request", `status must be one of: ${VALID_STATUSES.join(", ")}`);
  }
  try {
    const store = getStore();
    await store.setApplicationStatus(id, status as AppStatus);
    if (status === "revoked") {
      await store.revokeCredentials(id);
    }
    await auditAdmin(req, `app.status.${status}`, "success", 200);
    return json({ ok: true, id, status });
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    await auditAdmin(req, "app.status", "failure", 400, message);
    if (message === "app_not_found") return jsonError(404, "app_not_found", "Application not found");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
