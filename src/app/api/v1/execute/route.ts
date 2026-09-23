import { methodNotAllowed } from "@/lib/http";
import { handleExecuteRequest } from "@/lib/pipeline";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Capability-oriented public API.
 *   POST { "capability": "ai.generate", "input": { … } }
 * The client never names (or receives) a secret.
 */
export async function POST(req: Request): Promise<Response> {
  return handleExecuteRequest(req);
}

export async function GET(): Promise<Response> {
  return methodNotAllowed();
}
