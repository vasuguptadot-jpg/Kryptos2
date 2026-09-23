/**
 * Bootstrap / onboard a client application from the command line.
 *
 *   npm run seed -- --app MAHOLLA --name "Maholla App" \
 *     --permissions gemini.generate,gemini.test,groq.generate --limit 30
 *
 * The credential is printed ONCE to stdout. Only its hash is stored.
 *
 * For local development without a database, set STORE_BACKEND=memory — but
 * note that in-memory registrations disappear when the server restarts.
 */
import { generateCredential } from "../src/lib/credentials";
import { getStore } from "../src/lib/store";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const appId = (arg("app") ?? "").trim().toUpperCase();
  const name = (arg("name") ?? appId).trim();
  const permsArg = arg("permissions") ?? "";
  const limit = Number(arg("limit") ?? process.env.APP_DEFAULT_RATE_LIMIT ?? "60");

  if (!/^[A-Z][A-Z0-9_]{1,39}$/.test(appId)) {
    console.error("ERROR: --app must look like MAHOLLA (A-Z, 0-9, _, 2-40 chars).");
    process.exit(1);
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > 100_000) {
    console.error("ERROR: --limit must be an integer 1..100000.");
    process.exit(1);
  }

  const store = getStore();
  const available = new Set((await store.listCapabilities()).map((c) => c.capability));
  const permissions = permsArg
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  for (const p of permissions) {
    if (!available.has(p)) {
      console.error(`ERROR: unknown capability "${p}". Available: ${[...available].join(", ")}`);
      process.exit(1);
    }
  }

  const app = await store.createApplication({
    appId,
    displayName: name,
    defaultRateLimit: limit
  });
  if (permissions.length > 0) {
    await store.setPermissions(
      app.id,
      permissions.map((permission) => ({ permission, rateLimitPerMinute: null }))
    );
  }
  const cred = generateCredential();
  await store.createCredential(app.id, cred.keyHash, cred.keyPrefix);

  console.log("");
  console.log("=== KRYPTOS — application registered ===");
  console.log(`appId:       ${app.appId}`);
  console.log(`permissions: ${permissions.join(", ") || "(none)"}`);
  console.log(`rate limit:  ${limit}/min (default per operation)`);
  console.log("");
  console.log("Credential (shown ONCE — store it in the client app now):");
  console.log(`  ${cred.rawKey}`);
  console.log("");
  console.log("Client request headers:");
  console.log(`  X-Kryptos-App-Id:  ${app.appId}`);
  console.log("  X-Kryptos-App-Key: <credential above>");
  process.exit(0);
}

main().catch((err) => {
  console.error("Seed failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
