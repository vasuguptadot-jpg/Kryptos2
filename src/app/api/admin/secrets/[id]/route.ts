import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Enable/disable a registered secret (metadata switch only). */
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
  const enabled = (body as Record<string, unknown>)?.enabled;
  if (typeof enabled !== "boolean") {
    return jsonError(400, "invalid_request", "enabled must be a boolean");
  }
  try {
    await getStore().setSecretEnabled(id, enabled);
    await auditAdmin(req, `secret.${enabled ? "enable" : "disable"}`, "success", 200);
    return json({ ok: true, id, enabled });
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    if (message === "secret_not_found") return jsonError(404, "secret_not_found", "Secret not found");
    await auditAdmin(req, "secret.update", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

/** Remove a secret registration (fails while capabilities still reference it). */
export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const { id } = await params;
  try {
    await getStore().deleteSecret(id);
    await auditAdmin(req, "secret.delete", "success", 200);
    return json({ ok: true, id });
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    if (message === "secret_not_found") return jsonError(404, "secret_not_found", "Secret not found");
    if (message === "secret_in_use") {
      return jsonError(409, "secret_in_use", "Delete the capabilities referencing this secret first");
    }
    await auditAdmin(req, "secret.delete", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
