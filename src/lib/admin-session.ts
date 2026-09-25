import { createHmac, timingSafeEqual } from "node:crypto";
import { safeEqual } from "./credentials";

export const ADMIN_COOKIE = "kryptos_admin";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

export function isAdminConfigured(): boolean {
  return Boolean(
    process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD && process.env.ADMIN_SESSION_SECRET
  );
}

function sign(payload: string): string {
  return createHmac("sha256", process.env.ADMIN_SESSION_SECRET!).update(payload).digest("hex");
}

export function verifyAdminCredentials(username: string, password: string): boolean {
  if (!isAdminConfigured()) return false;
  return (
    safeEqual(username, process.env.ADMIN_USERNAME!) &&
    safeEqual(password, process.env.ADMIN_PASSWORD!)
  );
}

export function createAdminToken(): { token: string; maxAgeSeconds: number } {
  const payload = `v1.${Date.now() + SESSION_TTL_MS}`;
  return { token: `${payload}.${sign(payload)}`, maxAgeSeconds: SESSION_TTL_MS / 1000 };
}

export function verifyAdminToken(token: string | undefined | null): boolean {
  if (!token || !isAdminConfigured()) return false;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return false;
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = sign(payload);
  const a = Buffer.from(parts[2], "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  const exp = Number(parts[1]);
  return Number.isFinite(exp) && Date.now() < exp;
}

export function isAdminRequest(req: Request): boolean {
  const cookieHeader = req.headers.get("cookie") ?? "";
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${ADMIN_COOKIE}=`));
  const token = match ? decodeURIComponent(match.slice(ADMIN_COOKIE.length + 1)) : undefined;
  return verifyAdminToken(token);
}

export function adminSetCookieHeader(token: string, maxAgeSeconds: number): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure}`;
}

export function adminClearCookieHeader(): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${ADMIN_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`;
}
