import {
  adminSetCookieHeader,
  createAdminToken,
  isAdminConfigured,
  verifyAdminCredentials
} from "@/lib/admin-session";
import { json, jsonError } from "@/lib/http";
import { recordFailureAndCheck } from "@/lib/limiter";
import { logger } from "@/lib/logger";
import { createHash } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Throttled admin login. Sets an HttpOnly, SameSite=Strict session cookie. */
export async function POST(req: Request): Promise<Response> {
  if (!isAdminConfigured()) {
    return jsonError(503, "admin_not_configured", "Admin access is not configured on this deployment");
  }
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError(400, "invalid_json", "Request body must be valid JSON");
  }
  const { username, password } = (body ?? {}) as { username?: unknown; password?: unknown };
  if (typeof username !== "string" || typeof password !== "string") {
    return jsonError(400, "invalid_request", "username and password are required");
  }
  // Brute-force guard: ~5 failures / 5 min per client IP (best-effort instance
  // scope) plus a uniform delay. Real protection remains a long random password.
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const ipKey = createHash("sha256").update(ip).digest("hex").slice(0, 16);
  await new Promise((r) => setTimeout(r, 400));
  if (!verifyAdminCredentials(username, password)) {
    const limited = recordFailureAndCheck(`admin-login:${ipKey}`, 5, 5 * 60_000);
    logger.warn("admin_login_failed", { username: username.slice(0, 32) });
    if (limited) {
      return jsonError(429, "rate_limited", "Too many failed attempts. Try again later.", undefined, {
        "retry-after": "300"
      });
    }
    return jsonError(401, "invalid_credentials", "Invalid credentials");
  }
  const { token, maxAgeSeconds } = createAdminToken();
  logger.info("admin_login_success", {});
  return json(
    { ok: true },
    200,
    { "set-cookie": adminSetCookieHeader(token, maxAgeSeconds) }
  );
}
