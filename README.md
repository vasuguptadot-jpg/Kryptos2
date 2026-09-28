# KRYPTOS — Generic Secret Broker (V1)

**Central, production-oriented capability broker for Vercel.** Applications request *capabilities*;
Kryptos resolves the provider and the server-side secret internally, calls the provider, and returns
only the safe result.

> **Core rule: clients never receive, retrieve, or see raw secrets — and they never even name them.**
> The client knows `ai.generate`. It does not know (and cannot select) `GEMINI_API_KEY`.
> There is deliberately **no secret-retrieval API** anywhere in this service.

```
MAHOLLA / TRADE_LAB / LEGAL_AI / …
        │  X-Kryptos-App-Id + X-Kryptos-App-Key
        ▼
POST /api/v1/execute { "capability": "ai.generate", "input": { … } }
        ▼
KRYPTOS  authenticate → authorize (capability) → rate-limit → resolve capability config
        → resolve provider adapter → resolve env secret (server-only) → execute → audit
        ▼
Gemini · Groq · any HTTPS provider via the domain-locked http-generic adapter
```

## The registries (metadata in Postgres — values stay in the deployment env)

| Registry | Contents | Example |
|---|---|---|
| **Secret registry** | env var NAME → provider, enabled, notes, timestamps. **Never values.** | `GEMINI_API_KEY` → gemini |
| **Capability registry** | capability → provider + adapter operation + secret reference + adapter config | `ai.generate` → gemini / generateText / `GEMINI_API_KEY` |
| **App registry** | app identity, hashed credential, status, capability permissions + per-capability limits | `MAHOLLA` ✓ ai.generate |

Adding a new secret/provider needs **no code change**: add the value in Vercel env vars, register its
metadata, map a capability (use `http-generic` with an approved HTTPS origin), grant apps access.

## Request flow (`POST /api/v1/execute`)

1. Authenticate app (`X-Kryptos-App-Id` / `X-Kryptos-App-Key`, sha256-hashed w/ optional pepper)
2. Brute-force guard on repeated auth failures
3. Check app active → check capability permission (**always before secret resolution**)
4. Per-app, per-capability fixed-window rate limit (atomic, Postgres; fail closed)
5. Resolve capability record (404 unknown, 403 disabled)
6. Resolve provider adapter (`gemini`, `groq`, `http-generic`; 503 if misconfigured)
7. Resolve server-side secret via the **server-only resolver** (403 secret disabled, 503 not configured)
8. Adapter validates input strictly and executes; response sanitized (values redacted, caps on size)
9. Return `{ capability, provider, result }` — never `secret`, `secretName`, env names or values
10. Structured metadata-only audit event (no prompts, no headers, no values)

`POST /api/v1/gemini`, `/api/v1/groq[/test]` remain as thin aliases of the built-in capabilities
for existing integrations; new clients should use `/api/v1/execute`.

## Provider adapters (`src/lib/adapters/`)

- `gemini` — operations `generateText`, `test` (model allowlist via env or capability config)
- `groq` — operations `generateText`, `test`
- `http-generic` — operation `request`: arbitrary HTTPS providers via *admin-approved* config:
  fixed `baseUrl` origin (private/loopback/link-local/metadata hosts rejected, at registration
  *and* execution), fixed path, `GET`/`POST`, secret injected as configured header or query param,
  optional field allowlist/response extraction. Client input is scalar-only, forbids steering
  fields (`url`, `host`, `secret_name`, `headers`, auth overrides…). **Not** an open proxy — the
  client can never choose a URL. (Note: checks are string-level; DNS rebinding is out of scope for V1.)

## Endpoints

Public/app-facing: `GET /api/health` · `POST /api/v1/execute` · legacy `/api/v1/gemini|groq[/test]`.
Admin (cookie session): `login`, `logout`, `session`, `apps` (+`/:id`, `/rotate`, `/permissions`),
`secrets` (+`/:id`), `capabilities` (+`/:capability`), `audit`, `stats`. Dashboard at `/admin`.
There are NO `GET /api/secrets`, no `/api/env`, no `/api/config`, no resolver endpoint — enforced
by a regression test scanning the route tree.

## Quick start (dev)

```bash
npm install
npm run dev                      # STORE_BACKEND=memory is auto-usable in dev
# or with a database:
export DATABASE_URL=postgres://... && npm run db:init   # applies 001 + 002
npm run verify                   # typecheck + production build + 42 tests
```

Set in `.env` (dev only): `GEMINI_API_KEY`, `GROQ_API_KEY`, `ADMIN_*`. See `.env.example`.

## Production (Vercel)

1. Provision Postgres (Vercel Postgres / Neon / Supabase) → set `DATABASE_URL` and, if needed, the PEM-encoded `DATABASE_CA_CERT` → `npm run db:init`.
2. Set server env vars (Settings → Environment Variables): `ADMIN_USERNAME`, strong `ADMIN_PASSWORD`,
   `ADMIN_SESSION_SECRET` (`openssl rand -hex 32`), provider keys (`GEMINI_API_KEY`, `GROQ_API_KEY`, and
   any future `MY_*` secrets), recommended `CREDENTIAL_PEPPER`. **Never `NEXT_PUBLIC_*`. Never set `STORE_BACKEND`.**
3. Deploy `vercel --prod` (region pinned in `vercel.json`), attach your domain (HTTPS auto, HSTS served).
4. Register secrets/capabilities and onboard apps in `/admin` (or `npm run seed` for apps).

**PUBLIC (client) config for an app:** base URL, `X-Kryptos-App-Id`, `X-Kryptos-App-Key`, capability names.
**PRIVATE (server) config:** everything above — and nothing private ever crosses the wire.

PostgreSQL TLS certificate and hostname verification are always enabled. `DATABASE_CA_CERT` is optional: when absent, Node's system trust store is used. Malformed/empty CA values and unsafe TLS modes are rejected; never set `PGSSLMODE=disable` or `NODE_TLS_REJECT_UNAUTHORIZED=0`. Do not commit the CA or place it in a client-prefixed variable.

## Onboarding (exact procedure)

**Maholla (example):**
1. Vercel env: set `GEMINI_API_KEY=<real key>`.
2. `/admin` → Secrets: confirm `GEMINI_API_KEY` shows **CONFIGURED** (or register: name + provider).
3. `/admin` → Capabilities → save: `ai.generate`, provider `gemini`, operation `generateText`,
   secret ref `GEMINI_API_KEY`, config `{}`.
4. `/admin` → Create app: `MAHOLLA`, permissions ✓ `ai.generate` (rate limit e.g. 30/min). Save the
   credential shown **once** (`krk_…`) into Maholla's own secure config — never hard-code into the APK.
5. Maholla calls:
   ```bash
   curl https://<kryptos-domain>/api/v1/execute \
     -H "X-Kryptos-App-Id: MAHOLLA" -H "X-Kryptos-App-Key: krk_…" \
     -H "content-type: application/json" \
     -d '{"capability":"ai.generate","input":{"prompt":"…","model":"gemini-2.0-flash"}}'
   ```
6. Optional TypeScript client: `sdk/kryptos-client.ts` — knows only base URL, app credential,
   capability names; contains no provider secrets.

Repeat for `TRADE_LAB`, `LEGAL_AI`, … — independent credentials, permissions, limits, revocation.
New weather/maps/payments/etc. providers: register secret metadata + an `http-generic` capability
(approved origin), grant apps — no code changes.

## Tests (74)

Secret protection (bundle scan of `.next/static` for registered names+values, response/header/error
leaks incl. provider-echoed keys, dynamic redaction of arbitrary secret names) · authorization
(cross-app isolation, revocation/disable/rotation, capability hopping) · resolver security (envelope
steering, input steering, unknown/disabled states, missing env) · SSRF (config-time + execution-time
host validation, no client routes for secrets/env) · abuse (per-app/per-capability limits + 429s,
admin login throttle, payload caps, malformed bodies) · SDK contract against the real pipeline.
PostgreSQL TLS tests use only a synthetic CA; certificate and hostname verification remain enabled, with optional `DATABASE_CA_CERT` trust configured server-side. Run: `npm run verify`.

## Honest limitations (V1)

Fixed-window per-minute limits; best-effort instance-scoped brute-force counters (serverless has no
durable in-memory state — durable limits are the Postgres ones); string-level host checks (no DNS
rebinding defense); credential-per-request auth (short-lived session tokens are a V2 option); audit
retention is the operator's policy. No claims of absolute security: a compromised *app* credential
yields only that app's explicitly granted capabilities and is independently revocable.
