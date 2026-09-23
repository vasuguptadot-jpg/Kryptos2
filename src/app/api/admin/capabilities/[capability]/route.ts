import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function PATCH(
  req: Request,
  { params }: { params: Promise<{ capability: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const capability = decodeURIComponent((await params).capability);
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
    const store = getStore();
    const cap = await store.getCapability(capability);
    if (!cap) return jsonError(404, "capability_not_found", "Capability not found");
    await store.upsertCapability({
      capability: cap.capability,
      providerId: cap.providerId,
      secretName: cap.secretName,
      operation: cap.operation,
      config: cap.config,
      enabled
    });
    await auditAdmin(req, `capability.${enabled ? "enable" : "disable"}`, "success", 200);
    return json({ ok: true, capability, enabled });
  } catch {
    await auditAdmin(req, "capability.update", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ capability: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const capability = decodeURIComponent((await params).capability);
  try {
    await getStore().deleteCapability(capability);
    await auditAdmin(req, "capability.delete", "success", 200);
    return json({ ok: true, capability });
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    if (message === "capability_not_found") {
      return jsonError(404, "capability_not_found", "Capability not found");
    }
    await auditAdmin(req, "capability.delete", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
