# KRYPTOS V1 — FINAL DEPLOYMENT REPORT

Date: 2026-09-22 · Next.js 15.5.6 · TypeScript 5.7 (strict) · PostgreSQL 17.11 (real instance for verification) · Node v20.20.2
Everything below was actually executed this session. No result is assumed or copied from earlier claims.
Architecture unchanged: generic secret registry → capability → server-only resolver → env var → adapter → result.

## 1. Database (PHASE 1)

| Item | Result |
|---|---|
| `npm run db:init` | **PASS** — applied 001_init.sql + 002_generic_registry.sql against real PostgreSQL 17 |
| Migration correctness | **PASS** — single transaction per file; re-run is fully idempotent (`IF NOT EXISTS` / `ON CONFLICT DO NOTHING`): no partial state, zero duplicates |
| Registry tables | **PASS** — 7 tables, 13 indexes, 22 constraints (regex CHECKs for names, FK `ON DELETE RESTRICT` on capabilities → secret_registry) |
| Data preservation | **PASS** — probe row inserted, db:init re-run, row intact; 0 duplicate registry rows |
| Existing auth/admin intact | **PASS** — verified via production runtime (below) |
| PostgresStore runtime | **PASS** — `next start` (production) + real Postgres: health `database:"ok"`, CLI seed, credential hash-only in DB (prefix stored, 64-hex hash), admin rotation, permissions update, **atomic rate limits** (limit 1 → 502 then 429), **audit rows persisted in Postgres** (`audit_events`, `rate_limit_state` inspected directly) |

## 2. Tests (PHASE 2 — exact results)

| Check | Result |
|---|---|
| TESTS | **PASS — 42/42**, 0 skipped (repeated runs incl. after build) |
| TYPECHECK | **PASS** (`tsc --noEmit`, strict, 0 errors) |
| LINT | **NOT APPLICABLE** — no linter configured in this repository (not invented; compile correctness covered by strict TS) |
| BUILD | **PASS** (17 routes, production `next build`) |
| SECURITY TESTS | **PASS** — authz (14), generic capability/resolver/SSRF (9), admin surface incl. brute-force + registry CRUD (8), rate limits (4), leakage (5), SDK contract (3) |
| SECRET SCAN | **PASS** — every `.next/static` asset scanned against all registered secret names + synthetic values + infra names, zero hits |

## 3. Vercel compatibility (PHASE 5)

**Vercel compatible: YES. Required code changes: NONE.**

Checked and clear: Next.js auto-detection; default build/install/output; `runtime = "nodejs"` on all 19 API routes (`pg`); no filesystem writes, no local/SQLite persistence, no workers/cron/WebSockets/long timers (health's 3 s bounded probe only); no native binaries; no absolute paths; no hardcoded localhost/ports/dev origins in `src`; no dev auth bypass (`STORE_BACKEND=memory` is refused in production — verified fail-closed); minimal runtime deps (next, react, react-dom, pg); `engines.node >= 20.9.0`; `vercel.json` limited to region (`bom1`) + 60 s function budget.

## 4. Secret audit (PHASES 3, 8, 9, 10)

- Client source, SDK, public assets, production bundle, repo files: **no secret names, no key material** (greps executed; one intentionally invalid synthetic string inside a test only).
- No generic env/secret endpoint: `/api/secrets`, `/api/env`, `/api/config` absent (route-tree regression test enforces this permanently).
- Clients can request `{"capability": …}` but cannot select env vars, providers, adapters, or change secret mappings: envelope restricted to `{capability, input}`; steering attempts → 400; capability hopping → 403; missing/disable states → 404/403/503 — all covered by tests.
- http-generic stays restricted: HTTPS-only, approved origins, private/loopback/metadata/internal hosts rejected at **registration and execution**; secret injected only per config; user input cannot override origin or auth (tests pass).
- DB stores metadata/hashes only — no raw secret values anywhere.
- Admin bootstrap (PHASE 7): env-based, no embedded/default credential (503 `admin_not_configured` otherwise), HMAC HttpOnly SameSite=Strict 8h cookie, login throttle 5/5min→429, value-free admin APIs, host-only cookie works on any Vercel-assigned domain with zero config.

## 5. Environment variables (names only)

| Variable | Purpose | Server/Client | Required? | Vercel scope |
|---|---|---|---|---|
| `DATABASE_URL` | Postgres metadata DB | SERVER ONLY | YES | Production |
| `ADMIN_USERNAME` | Admin login identity | SERVER ONLY | YES | Production |
| `ADMIN_PASSWORD` | Admin login secret (long random) | SERVER ONLY | YES | Production |
| `ADMIN_SESSION_SECRET` | Signs admin session cookies (`openssl rand -hex 32`) | SERVER ONLY | YES | Production |
| `CREDENTIAL_PEPPER` | Extra input to app-credential hashes | SERVER ONLY | Recommended | Production |
| `GEMINI_API_KEY` | Gemini provider secret (registry-resolved) | SERVER ONLY | If used | Production |
| `GROQ_API_KEY` | Groq provider secret | SERVER ONLY | If used | Production |
| `GEMINI_MODEL_ALLOWLIST` / `GROQ_MODEL_ALLOWLIST` | JSON model restrictions | SERVER ONLY | No | Production |
| `APP_DEFAULT_RATE_LIMIT` | Default per-app limit/min | SERVER ONLY | No | Production |
| `PROVIDER_TIMEOUT_MS` | Upstream timeout | SERVER ONLY | No | Production |
| `APP_VERSION` | Version in `/api/health` | SERVER ONLY | No | All |
| `PGSSLMODE=disable` | Local-DB convenience only | SERVER ONLY | No (not for Vercel) | Development |
| Future `MY_*` secrets | Registry-managed arbitrary provider secrets | SERVER ONLY | As added | Production |

No client-safe/app-side variables exist in the repo (no `VITE_*`, no `NEXT_PUBLIC_*` secrets). Clients receive only: base URL, their App ID/key, capability names.

## 6. Maholla onboarding readiness (PHASE 11)

Pipeline verified end-to-end (MAHOLLA app → hashed credential → `POST /api/v1/execute` → provider → safe result; Maholla never receives keys). After the production URL exists: create `ai.generate` capability (or use `gemini.generate`) → create app MAHOLLA with limits → store shown-once credential in Maholla's secure config (not the APK) → Maholla calls `https://<production-domain>/api/v1/execute`. Full step list in README/DEPLOYMENT.md (§Operator actions).

## 7. Final status

**READY WITH OPERATOR ACTION**

(The codebase requires no further changes; only standard Vercel deployment/configuration remains: project import, Postgres + `db:init`, Production env vars, domain, admin sign-in, Maholla credential issuance. See `DEPLOYMENT.md` / `deployment-checklist.json` for the machine-readable state.)
