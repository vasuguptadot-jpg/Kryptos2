import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const { id } = await params;
  try {
    const store = getStore();
    const [perms, capabilities] = await Promise.all([
      store.getPermissions(id),
      store.listCapabilities()
    ]);
    return json({
      permissions: perms.map((p) => ({
        permission: p.permission,
        rateLimitPerMinute: p.rateLimitPerMinute
      })),
      available: capabilities.map((c) => c.capability)
    });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

/**
 * Replace an application's permission set. Permissions may only reference
 * registered operations — arbitrary capabilities cannot be invented.
 */
export async function PUT(
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
  const list = (body as Record<string, unknown>)?.permissions;
  if (!Array.isArray(list)) {
    return jsonError(400, "invalid_request", "permissions must be an array");
  }
  let valid: Set<string>;
  try {
    valid = new Set((await getStore().listCapabilities()).map((c) => c.capability));
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
  const perms: { permission: string; rateLimitPerMinute: number | null }[] = [];
  for (const p of list as Record<string, unknown>[]) {
    const permission = typeof p.permission === "string" ? p.permission : "";
    if (!valid.has(permission)) {
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
    perms.push({ permission, rateLimitPerMinute });
  }
  try {
    const store = getStore();
    const apps = await store.listApplications();
    if (!apps.some((a) => a.id === id)) {
      return jsonError(404, "app_not_found", "Application not found");
    }
    await store.setPermissions(id, perms);
    await auditAdmin(req, "app.permissions.update", "success", 200);
    return json({ ok: true, id, permissions: perms });
  } catch {
    await auditAdmin(req, "app.permissions.update", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
