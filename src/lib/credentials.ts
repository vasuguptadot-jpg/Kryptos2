import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const KEY_PREFIX = "krk"; // kryptos key

export interface GeneratedCredential {
  /** Shown to the operator ONCE at creation/rotation. Never stored. */
  rawKey: string;
  /** sha256(optional-pepper + rawKey), the only thing persisted. */
  keyHash: string;
  /** First 11 chars, for identification in the admin dashboard. Not sensitive. */
  keyPrefix: string;
}

/** Generate a new application credential (128 bits of entropy). */
export function generateCredential(): GeneratedCredential {
  const rawKey = `${KEY_PREFIX}_${randomBytes(32).toString("hex")}`;
  return { rawKey, keyHash: hashCredential(rawKey), keyPrefix: rawKey.slice(0, 11) };
}

export function hashCredential(rawKey: string): string {
  const pepper = process.env.CREDENTIAL_PEPPER ?? "";
  return createHash("sha256").update(`${pepper}:${rawKey}`).digest("hex");
}

/** Constant-time comparison of a presented key against a stored hash. */
export function verifyCredential(rawKey: string, storedHash: string): boolean {
  const presented = Buffer.from(hashCredential(rawKey), "utf8");
  const stored = Buffer.from(storedHash, "utf8");
  if (presented.length !== stored.length) return false;
  return timingSafeEqual(presented, stored);
}

/** Constant-time string comparison for admin username/password. */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba); // keep timing shape roughly constant
    return false;
  }
  return timingSafeEqual(ba, bb);
}
