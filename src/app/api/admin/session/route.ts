import { isAdminConfigured, isAdminRequest } from "@/lib/admin-session";
import { json } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request): Promise<Response> {
  return json({ authenticated: isAdminRequest(req), configured: isAdminConfigured() });
}
