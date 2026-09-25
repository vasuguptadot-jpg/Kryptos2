import { requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const url = new URL(req.url);
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? "100") || 100, 1), 500);
  try {
    const events = await getStore().listAudit(limit);
    // The audit rows never contain secrets by construction (see pipeline/audit).
    return json({ events });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
