import { methodNotAllowed } from "@/lib/http";
import { handleLegacyProviderRequest } from "@/lib/pipeline";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<Response> {
  return handleLegacyProviderRequest(req, "gemini.test");
}

export async function GET(): Promise<Response> {
  return methodNotAllowed();
}
