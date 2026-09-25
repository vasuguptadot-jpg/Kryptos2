import { redactSecrets } from "./secrets";

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });
}

export function jsonError(
  status: number,
  code: string,
  message: string,
  requestId?: string,
  headers: Record<string, string> = {}
): Response {
  return json(
    { error: { code, message: redactSecrets(message) }, ...(requestId ? { requestId } : {}) },
    status,
    headers
  );
}

/** Never echo method-not-allowed with details. */
export function methodNotAllowed(): Response {
  return jsonError(405, "method_not_allowed", "Method not allowed");
}
