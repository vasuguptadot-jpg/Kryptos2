# KRYPTOS — VERCEL 404 FORENSIC DEPLOYMENT AUDIT

**Date:** 2026-09-23
**Repositories audited:** `vasuguptadot-jpg/Kryptos`, `vasuguptadot-jpg/Kryptos2`
**Branch under test:** `arena/01a0d06d-kryptos2` (from `main` @ `e0ab1d5`)
**Application:** Kryptos Secret Broker v1.0.0 — Next.js 15.5.6 App Router

---

## 1. ROOT CAUSE

**The Git repositories never contained the Kryptos application. They contained only the deployment ZIP archive.**

Every commit that Vercel ever received was:

| Repo | Commit | Tracked files (`git ls-files`) |
|---|---|---|
| `Kryptos2` | `e0ab1d5` — "Add files via upload" | **1** → `kryptos-v1-final-deployment-backup (1).zip` |
| `Kryptos`  | `3221778` — "Add files via upload" | **1** → `kryptos-v1-final-deployment-backup.zip` |

The complete, working Next.js application (65 files: `package.json`, `next.config.ts`, `vercel.json`,
`tsconfig.json`, `src/app/**`, 19 API Route Handlers, tests, migrations) was sitting **inside the
`.zip` as an opaque binary blob**.

Consequences at Vercel, in order:

1. Vercel clones a repo containing one binary file. **No `package.json` → no framework detection** (the
   `"framework": "nextjs"` in `vercel.json` was never read, because `vercel.json` was inside the ZIP too).
2. No build command exists to run → Vercel produces an **empty static deployment** (not a Next.js
   deployment; no `.next` output, no serverless functions).
3. No route is handled by any deployment → Vercel falls back to its **platform-level NOT_FOUND** for
   *every* path, including `/api/health`.
4. Because **both** repositories had the same defect, retrying with the other repo or with a second
   Vercel project ("kryptos2") reproduced the identical 404. **This is why multiple projects all failed
   the same way — the variable was never the project, it was the repository content.**

This single defect simultaneously explains investigation categories **B** (entire route tree missing from
the deployment), **C** (Vercel building an incomplete subset of the repository — here, 100% incomplete)
and **E** (build output does not contain the expected routes — there was no build output at all).

---

## 2. EVIDENCE

### 2.1 The decisive observation (repository content)

```
$ git ls-files
kryptos-v1-final-deployment-backup (1).zip

$ git ls-files | wc -l
1

$ git log --stat -1
commit e0ab1d57b52483ea4d07130706f1c0c31c391eb0
Author: vasuguptadot-jpg <vasuguptadot@gmail.com>
Date:   Tue Sep 22 17:54:14 2026 +0530
    Add files via upload
 kryptos-v1-final-deployment-backup (1).zip | Bin 0 -> 105224 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)
```

Confirmed against the GitHub API for **both** repositories (not just the local clone):

```
$ gh api repos/vasuguptadot-jpg/Kryptos2/contents --jq '.[] | "\(.type)\t\(.name)"'
file    kryptos-v1-final-deployment-backup (1).zip

$ gh api repos/vasuguptadot-jpg/Kryptos/contents --jq '.[] | "\(.type)\t\(.name)"'
file    kryptos-v1-final-deployment-backup.zip
```

### 2.2 The 404 is Vercel platform-level, not a Kryptos 404

The reported screenshot text is `404: NOT_FOUND` / `This page doesn't exist.`

Local production Next.js serves a **different** 404 (its own error page):

```
$ curl -s http://127.0.0.1:3000/definitely-does-not-exist
<title>404: This page could not be found.</title>   → body text: "This page could not be found."
```

| | Title / body | Origin |
|---|---|---|
| Screenshot (Vercel) | `404: NOT_FOUND` / "This page doesn't exist." | **Vercel platform** — no deployment handling the path |
| Local production | `404: This page could not be found.` | **Next.js application** 404 page |

These are two different strings from two different layers. A Next.js application 404 **cannot** produce
`NOT_FOUND`, and the local server emits no `x-vercel-id` header. **Classification: case 1 — Vercel
platform-level NOT_FOUND**, caused by an empty deployment. This is *not* a missing-`/`-route problem and
*not* an application-logic problem.

### 2.3 The application itself was always healthy

Once the ZIP was extracted to the repository root, everything worked with **zero source changes**:
42/42 tests pass, `tsc --noEmit` clean, `next build` emits the complete route table, and the production
server answers every expected route correctly (§5, §6). **No Kryptos source file was modified by this
audit.** The root cause was never in the code.

### 2.4 Why the previous verification missed it

`deployment-checklist.json` asserted `vercel.compatible: "READY"` and `secret_audit.git_repo_files:
"PASS"`. Neither claim was ever validated with `git ls-files` against the remote. Those entries have been
corrected (see §3.2).

---

## 3. FIX

### 3.1 Primary fix — commit the real application

The contents of the ZIP were extracted to the repository root, placed exactly where Vercel auto-detects
a Next.js project (`package.json` at the root; `src/app` App Router tree), and the opaque ZIP was removed
from the working tree so it cannot be mistaken for the application again.

65 files added, including everything deployment requires: `package.json`, `package-lock.json`,
`next.config.ts`, `vercel.json`, `tsconfig.json`, `src/app/**`, `src/lib/**`, `db/migrations/**`,
`scripts/**`, `tests/**`, `.env.example`, `.gitignore`.

No application code, architecture, dependency, configuration or security control was changed.

### 3.2 Secondary fix — correct the false assurance record

`deployment-checklist.json` was asserting verification that had not happened. Two fields were corrected
to record the incident truthfully:

* `verification.git_source_audit` → FAIL (pre-fix, with the `git ls-files` evidence) / PASS (post-fix).
* `vercel.source_committed` → documents that the repository previously held only the ZIP.

### 3.3 What was deliberately NOT changed (and why)

| Considered | Decision | Reason |
|---|---|---|
| `vercel.json` | **unchanged** | `framework: "nextjs"`, `regions`, `functions.maxDuration` are all valid; contents are now actually delivered to Vercel. No evidence it ever caused the 404. |
| `next.config.ts` | **unchanged** | Contains **no** `output`, `basePath`, `assetPrefix`, `rewrites`, `redirects`, `distDir` or `trailingSlash`. There is **no static export** — correctly, since Kryptos needs server-side Route Handlers. |
| Middleware | **none exists** | No `middleware.ts`/`.js` anywhere. Verified no middleware can 404 or redirect `/`, `/admin`, `/api/health`. |
| `runtime = "nodejs"` | **already present on all 19 API routes** | No route was missing it; nothing to add. |
| `output: "export"` | **not introduced** | Would break API routes and is forbidden by the brief. |
| Architecture, Postgres, auth, secrets | **untouched** | Not implicated. |
| New Vercel project | **not created** | Forbidden by the brief; existing project must be re-linked/redeployed. |
| Next.js 15.5.6 → patched | **flagged, not done** | npm reports a security advisory (CVE-2025-66478) for 15.5.6. This is unrelated to the 404; see §8 recommendation. |

### 3.4 `.vercelignore` / `.gitignore` audit

* **No `.vercelignore` exists** → nothing is being excluded from the upload.
* `.gitignore` ignores only `node_modules/`, `.next/`, `out/`, `build/`, `.env`, `.env.*` (with
  `!.env.example`), `.DS_Store`, `*.pem`, `coverage/`, `.vercel`, `*.tsbuildinfo`, `next-env.d.ts`.
* **No source, route, `public/`, `package.json` or config path is ignored.** Verified:
  `node_modules`, `.next`, `next-env.d.ts`, `.env` → IGNORED; every source dir → tracked.

---

## 4. DETECTED APPLICATION / ROUTE-TREE INVENTORY

| Property | Value |
|---|---|
| Framework | Next.js **15.5.6** (App Router) |
| React | **19.1.0** / react-dom 19.1.0 |
| Router | **App Router** (`src/app`) — no `pages/` directory |
| Package manager | **npm** (`package-lock.json`; no `yarn.lock`/`pnpm-lock.yaml`) |
| Application root | **repository root** (not nested) |
| Monorepo | **No** — single package |
| Node engine | `>=20.9.0` (Vercel Node 22.x satisfies) |
| Middleware | **None** |
| `next.config.ts` | Security headers only — no output/redirect/rewrite/basePath/static-export |
| `vercel.json` | `framework: nextjs`, `regions: ["bom1"]`, `functions: src/app/api/** → maxDuration 60` |
| `.vercelignore` | none |
| Runtime | `nodejs` declared on **all 19** Route Handlers |
| Migrations | `db/migrations/001_init.sql`, `002_generic_registry.sql` (+ `npm run db:init`) |
| Routes | 2 pages + 1 `_not-found` + **19 API Route Handlers** = 22 entries |

```
Route (app)                                  Type
┌ ○ /                                        Static page   (src/app/page.tsx  ✅ EXISTS)
├ ○ /_not-found                              Static
├ ○ /admin                                   Static page   (src/app/admin/page.tsx)
├ ƒ /api/admin/apps                          Dynamic (Route Handler)
├ ƒ /api/admin/apps/[id]                     Dynamic
├ ƒ /api/admin/apps/[id]/permissions         Dynamic
├ ƒ /api/admin/apps/[id]/rotate              Dynamic
├ ƒ /api/admin/audit                         Dynamic
├ ƒ /api/admin/capabilities                  Dynamic
├ ƒ /api/admin/capabilities/[capability]     Dynamic
├ ƒ /api/admin/login                         Dynamic   (auth route)
├ ƒ /api/admin/logout                        Dynamic   (auth route)
├ ƒ /api/admin/secrets                       Dynamic
├ ƒ /api/admin/secrets/[id]                  Dynamic
├ ƒ /api/admin/session                       Dynamic   (auth route)
├ ƒ /api/admin/stats                         Dynamic
├ ƒ /api/health                              Dynamic   ← Kryptos health endpoint
├ ƒ /api/v1/execute                          Dynamic   ← Kryptos public API
├ ƒ /api/v1/gemini                           Dynamic
├ ƒ /api/v1/gemini/test                      Dynamic
├ ƒ /api/v1/groq                             Dynamic
└ ƒ /api/v1/groq/test                        Dynamic
○ Static   ƒ Dynamic (server-rendered on demand / serverless function)
```

**`/` genuinely exists** (`src/app/page.tsx`, returns `<title>Kryptos Broker</title>`). The intended
public entry points are `/` (landing) and `/admin` (operator dashboard).

---

## 5. BUILD-OUTPUT VERIFICATION (proof routes are generated)

From `.next/server/app-paths-manifest.json` after `npm run build` — all four critical routes present:

```
"/page": "app/page.js"                                  ✅
"/admin/page": "app/admin/page.js"                      ✅
"/api/health/route": "app/api/health/route.js"          ✅
"/api/v1/execute/route": "app/api/v1/execute/route.js"  ✅
```

…plus all 15 other `/api/admin/**` routes. `/` and `/admin` are prerendered **static**; every API route
is a **dynamic serverless function**. Build ID `CqTF8apk0ln-Jy8fE01tO`.

---

## 6. LOCAL PRODUCTION TEST RESULTS

`npm install` → `npm run build` → `NODE_ENV=production npx next start`.

### 6.1 Without `DATABASE_URL` (fail-closed behaviour)

| Request | Status | Body |
|---|---|---|
| `GET /` | **200** | `<title>Kryptos Broker</title>` |
| `GET /admin` | **200** | dashboard HTML |
| `GET /api/health` | **200** | `{"status":"ok","service":"kryptos",...,"database":"not_configured"}` |
| `POST /api/v1/execute` (invalid) | **401** | `{"error":{"code":"missing_credentials",...}}` |
| `GET /api/v1/execute` | **405** | `{"error":{"code":"method_not_allowed",...}}` |
| `GET /definitely-does-not-exist` | **404** | Next.js page: "*This page could not be found.*" |
| `GET /api/admin/stats` (no session) | **401** | `admin_auth_required` — route is reachable, not 404 |

No route returned a platform-style 404. A missing database degraded gracefully (logged
`audit_write_failed … fail closed`) instead of crashing or 404-ing.

### 6.2 With a real PostgreSQL (wire protocol, migrations applied)

Migrations applied via `npm run db:init`: `001_init.sql`, `002_generic_registry.sql` → tables
`applications`, `application_credentials`, `application_permissions`, `audit_events`, `capabilities`,
`rate_limit_state`, `secret_registry`.

| Request | Status | Body / result |
|---|---|---|
| `GET /api/health` | **200** | `{"status":"ok","service":"kryptos","database":"ok","providers":{"gemini":"configured","groq":"not_configured"},"capabilities":4}` |
| `POST /api/admin/login` (wrong pw) | **401** | `invalid_credentials` |
| `POST /api/admin/login` (correct) | **200** | `{"ok":true}` + `HttpOnly` session cookie |
| `GET /api/admin/stats` (with session) | 503 | see note below |
| Audit persistence | ✅ | `audit_events` row count = 1 with the earlier 401 recorded |

**Note on the 503:** the sandbox's Postgres is a WASM build reached through a socket shim that **drops
simultaneous connections** (`Connection terminated unexpectedly` under 4-way `Promise.all`; identical
queries succeed serialized). The route issues 4 parallel queries, which is correct against any real
Postgres (the `pg` pool queues them, `max: 3`). Verified the SQL itself is valid and returns real data
(`{"total":1,"failures":1}`). **This is a test-harness limitation, not a Kryptos defect**, and it is a
503 (a handled error), never a 404.

### 6.3 Secret-leak verification

* Client bundle (`.next/static/**`): **0** hits for `ADMIN_PASSWORD`, `ADMIN_SESSION_SECRET`,
  `CREDENTIAL_PEPPER`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `SERVICE_ROLE`, `postgres://`.
* Source tree: **0** hardcoded provider keys (`AIza…`, `gsk_…`); **0** uses of `NEXT_PUBLIC_`.
* Response bodies for `/`, `/admin`, `/api/health`, `/api/admin/stats`: **0** occurrences of the
  injected test secret values.
* `.env` is git-ignored; only `.env.example` (all values empty) is committed.
* No new diagnostic route was needed, so **no `/api/vercel-diagnostic` was created** and none remains.

---

## 7. VERCEL CONFIGURATION (intended, for the existing project)

| Setting | Value |
|---|---|
| Framework preset | **Next.js** (auto-detected once `package.json` is present) |
| Root Directory | **`./`** (repository root — the app is **not** nested) |
| Build command | `next build` (default) |
| Install command | `npm install` (default) |
| Output directory | Next.js default (`.next`) — **no** custom output, **no** static export |
| Node version | `>=20.9.0` (Vercel 22.x) |
| Production branch | `main` |
| Env vars required (Production scope) | `DATABASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_SESSION_SECRET`, `CREDENTIAL_PEPPER` (recommended), `GEMINI_API_KEY`, `GROQ_API_KEY` — **configured/not-configured status cannot be read without Vercel credentials; no values were retrieved or printed** |
| Deployment commit | **must be refreshed** — `main` currently still points at the ZIP-only commit `e0ab1d5` until this fix is merged |

---

## 8. VALIDATION SUMMARY

| Check | Command | Result |
|---|---|---|
| Typecheck | `tsc --noEmit` | **PASS** (exit 0) |
| Build | `next build` | **PASS** — full route table generated |
| Tests | `tsx --test tests/*.test.ts` | **PASS — 42/42** (7 suites) |
| Security/leakage tests | `tests/leakage.test.ts`, `tests/authz.test.ts` | **PASS** |
| Secret scan | bundle + source + responses | **PASS** — 0 findings |
| Route generation | app-paths-manifest | **PASS** — `/`, `/admin`, `/api/health`, `/api/v1/execute` present |
| Local production HTTP | `next start` matrix | **PASS** |
| DB connectivity | migrations + DB-backed `/api/health` | **PASS** (`"database":"ok"`) |
| Vercel deployment | — | **NOT VERIFIED — blocked, see §9** |

**Recommended follow-up (not applied, out of scope):** `next@15.5.6` is flagged by npm for
CVE-2025-66478; upgrade to a patched 15.5.x/15.x in a separate, tested change.

---

## 9. FINAL STATUS

```
VERCEL BLOCKED — ROOT CAUSE IDENTIFIED
```

**Root cause is identified with certainty and fixed in the working tree.** The repositories contained
only the deployment ZIP, so Vercel built an empty deployment and returned platform-level
`404: NOT_FOUND` everywhere — which is exactly why retrying projects never helped.

**Remaining blocker (both items require actions outside this sandbox):**

1. **The fix must reach `main`.** Vercel deploys the production branch; `main` still holds the ZIP-only
   commit `e0ab1d5`. This work is on `arena/01a0d06d-kryptos2` and needs to be merged.
2. **No Vercel credentials in this environment.** Vercel CLI 59.26.0 is installed but `vercel whoami`
   returns `Logged out. / No existing credentials found`, so the existing project's framework preset,
   root directory, build command, deployment commit, build logs, runtime logs and environment-variable
   status **could not be inspected**, and no deployment could be made to it. (No new project was created,
   per instructions.)

**Next evidence needed:** after merging the fix to `main`, Vercel should auto-deploy. Provide a Vercel
access token (or run `vercel login` / paste the deployment URL + commit) so that `vercel deploy --dry`,
the build log route table, runtime logs, and the live route matrix
(`/`, `/admin`, `/api/health`, `POST /api/v1/execute`, `/definitely-does-not-exist`) can be captured to
close the remaining checkboxes.
