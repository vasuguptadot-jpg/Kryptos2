/**
 * Best-effort in-memory abuse limiter (brute-force / credential-stuffing
 * dampening). Single-instance semantics: on serverless this limits per warm
 * instance, not globally — durable per-app/per-capability rate limits live in
 * Postgres (pipeline.ts). This layer only blunts obvious hammering.
 */
const GLOBAL_KEY = "__kryptos_abuse_limiter__";

type Bucket = { count: number; windowStart: number };

function buckets(): Map<string, Bucket> {
  const g = globalThis as unknown as { [GLOBAL_KEY]?: Map<string, Bucket> };
  if (!g[GLOBAL_KEY]) g[GLOBAL_KEY] = new Map();
  return g[GLOBAL_KEY]!;
}

/**
 * Returns true when the key has exceeded `max` hits within `windowMs`.
 * Call on FAILURE paths (failed auth), not success paths.
 */
export function recordFailureAndCheck(key: string, max: number, windowMs: number): boolean {
  const map = buckets();
  const now = Date.now();
  const bucket = map.get(key);
  if (!bucket || now - bucket.windowStart > windowMs) {
    map.set(key, { count: 1, windowStart: now });
    if (map.size > 10_000) map.clear(); // bound memory
    return false;
  }
  bucket.count += 1;
  return bucket.count > max;
}
