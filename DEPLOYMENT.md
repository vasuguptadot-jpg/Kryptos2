# KRYPTOS V1 — DEPLOYMENT CHECKLIST

State legend: **PASS** (verified) · **READY** (no change needed) · **OPERATOR ACTION** (you must do it) · **BLOCKED** (unresolved) · **NOT APPLICABLE**.

Every PASS below was actually executed on 2026-09-22 (PostgreSQL 17.11 local instance, Node v20.20.2, Next.js 15.5.6). Nothing here claims unexecuted checks.

## 1. Database

| Item | State |
|---|---|
| `npm run db:init` against PostgreSQL 17 | **PASS** |
| Migration 001 (core) | **PASS** |
| Migration 002 (generic registry) | **PASS** |
| Idempotent re-run (no partial/duplicate state; unique constraints intact) | **PASS** |
| Existing data preserved across re-run (probe row survived) | **PASS** |
| Tables (7): applications, application_credentials, application_permissions, audit_events, capabilities, rate_limit_state, secret_registry | **PASS** |
| Indexes (13) & constraints (22 — incl. regex CHECKs, FK ON DELETE RESTRICT on capabilities.secret_name) | **PASS** |
| Built-in registry rows (2 secrets metadata, 4 capabilities) | **PASS** |
| PostgresStore runtime (atomic rate-limit counters, audit persistence, rotation, permissions) under `next start` production mode | **PASS** |

## 2. Verification suite

| Check | Result |
|---|---|
| Typecheck (`tsc --noEmit`, strict) | **PASS** |
| Lint | **NOT APPLICABLE** — no linter is configured in the repo; not claimed. |
| Production build (`next build`, 17 routes) | **PASS** |
| Tests (`tsx --test tests/*.test.ts`) | **PASS — 42/42** (repeated runs) |
| Security tests (authz/generic/leakage/ratelimit/admin/sdk suites) | **PASS** |
| Client-bundle secret scan (all `.next/static` assets vs. registered secret names + values) | **PASS** |

## 3. Secret audit (static)

| Surface | State |
|---|---|
| Frontend source (`src/app` pages, admin UI source) | **PASS — zero secret-env references** |
| Production client bundle (`.next/static`) | **PASS — zero matches for names & synthetic values** |
| SDK (`sdk/kryptos-client.ts`) | **PASS — only baseUrl/appId/appKey/capabilities** |
| Repo-wide scan for embedded key material (`AIza…`, `gsk_…`, `krk_…`, PEM) | **PASS — none** (one intentionally invalid synthetic test string in `tests/authz.test.ts`) |
| Logs / API responses / dashboard responses / error messages | **PASS — dynamic redaction; unit-tested incl. provider-echoed keys** |
| `/api/secrets`, `/api/env`, `/api/config` | **PASS — absent** (admin metadata routes are cookie-gated and value-free) |

## 4. Vercel compatibility

| Item | State |
|---|---|
| Framework detection / build / install / output | **READY** — Next.js auto-detected; defaults apply |
| Node.js runtime on all 19 API routes (needed for `pg`) | **READY** |
| Server functions (region `bom1`, 60 s budget in `vercel.json`) | **READY** |
| Filesystem writes / local persistent storage / SQLite | **NOT APPLICABLE** — all state in Postgres |
| Long-running processes / workers / cron / WebSockets | **NOT APPLICABLE** |
| Native binaries / unsupported APIs / absolute paths | **READY** — none present |
| Hardcoded localhost/ports/dev origins | **READY** — none in `src` (localhost only inside the SSRF blocklist + tests) |
| Development-only auth bypass | **READY** — none; `STORE_BACKEND=memory` is refused in production (verified: fail-closed) |
| Cookies | **READY** — host-only, `SameSite=Strict`, `Secure` in production: no domain config needed for any assigned URL |
| Required code changes | **NONE** |

## 5. Environment variables (names only — never values)

| Variable | Purpose | Server/Client | Required | Suggested Vercel scope |
|---|---|---|---|---|
| `DATABASE_URL` | Postgres connection (metadata DB) | SERVER ONLY | YES | Production (Preview optional) |
| `ADMIN_USERNAME` | Admin login username | SERVER ONLY | YES | Production |
| `ADMIN_PASSWORD` | Admin login password (long random) | SERVER ONLY | YES | Production |
| `ADMIN_SESSION_SECRET` | HMAC key for admin session cookies (`openssl rand -hex 32`) | SERVER ONLY | YES | Production |
| `CREDENTIAL_PEPPER` | Extra input into app-credential hashes | SERVER ONLY | Recommended | Production |
| `GEMINI_API_KEY` | Gemini provider secret (resolved by registry) | SERVER ONLY | If Gemini used | Production |
| `GROQ_API_KEY` | Groq provider secret | SERVER ONLY | If Groq used | Production |
| `GEMINI_MODEL_ALLOWLIST` | JSON array restricting requestable models | SERVER ONLY | No | Production |
| `GROQ_MODEL_ALLOWLIST` | JSON array restricting requestable models | SERVER ONLY | No | Production |
| `APP_DEFAULT_RATE_LIMIT` | Default per-app per-minute limit | SERVER ONLY | No | Production |
| `PROVIDER_TIMEOUT_MS` | Upstream timeout | SERVER ONLY | No | Production |
| `APP_VERSION` | Version string in `/api/health` | SERVER ONLY | No | All |
| `PGSSLMODE` | `disable` for local DBs only | SERVER ONLY | No — not for Vercel | Development |
| _`MY_*` future secrets_ | Any new provider secret — registered via dashboard, resolved dynamically | SERVER ONLY | As added | Production |

Client applications receive ONLY: `KRYPTOS_BASE_URL`, their `X-Kryptos-App-Id`, their `X-Kryptos-App-Key`, capability names. No `VITE_*`/`NEXT_PUBLIC_*` secrets exist or are needed.

**After Vercel assigns the deployment URL, nothing in this repo must change.** The URL is entered only in the client apps (e.g. Maholla's config / `KryptosClient.baseUrl`) and used to reach `https://<deployment>/admin`.

## 6. Remaining operator actions (in order)

1. Create/import the GitHub repository in Vercel (Next.js auto-detected).
2. Provision Postgres (Vercel Postgres / Neon / Supabase); set `DATABASE_URL` (Production scope).
3. Set Production env vars: `ADMIN_USERNAME`, `ADMIN_PASSWORD` (long random), `ADMIN_SESSION_SECRET`, `CREDENTIAL_PEPPER`, `GEMINI_API_KEY`, `GROQ_API_KEY` (+ any future secrets).
4. Deploy the main branch.
5. One time: `DATABASE_URL=<prod> npm run db:init` (idempotent — safe to re-run).
6. Open `https://<production-domain>/admin` and sign in.
7. Secrets tab → confirm provider keys show **CONFIGURED**; register metadata for new secrets.
8. Capabilities tab → confirm built-ins; optionally create `ai.generate` (gemini / generateText / GEMINI_API_KEY).
9. Create app **MAHOLLA** (dashboard or `npm run seed -- --app MAHOLLA --permissions ai.generate --limit 30`) and store the shown-once credential securely (never inside the APK).
10. Configure Maholla with the Kryptos production URL + its credential.
11. Production smoke: `GET /api/health`, one execute round-trip per capability, spot-check 401/403/429.

## Final status: **READY WITH OPERATOR ACTION**
