import { adminClearCookieHeader } from "@/lib/admin-session";
import { json } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(): Promise<Response> {
  return json({ ok: true }, 200, { "set-cookie": adminClearCookieHeader() });
}
