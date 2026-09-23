-- KRYPTOS BROKER — initial schema (metadata only; NEVER provider secrets).
-- Apply with:  psql "$DATABASE_URL" -f db/migrations/001_init.sql
-- or:          npm run db:init

BEGIN;

CREATE TABLE IF NOT EXISTS applications (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id             text NOT NULL UNIQUE CHECK (app_id ~ '^[A-Z][A-Z0-9_]{1,39}$'),
  display_name       text NOT NULL,
  status             text NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'disabled', 'revoked')),
  default_rate_limit integer NOT NULL DEFAULT 60 CHECK (default_rate_limit > 0),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  last_used_at       timestamptz
);

-- Only sha256 hashes of credentials are ever stored; raw keys never persist.
CREATE TABLE IF NOT EXISTS application_credentials (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  key_hash       text NOT NULL,
  key_prefix     text NOT NULL,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  rotated_at     timestamptz,
  last_used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS idx_credentials_app ON application_credentials(application_id)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS application_permissions (
  application_id        uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  permission            text NOT NULL,           -- e.g. 'gemini.generate'
  rate_limit_per_minute integer CHECK (rate_limit_per_minute IS NULL OR rate_limit_per_minute > 0),
  PRIMARY KEY (application_id, permission)
);

-- Fixed-window counters; rows older than a few minutes are pruned.
CREATE TABLE IF NOT EXISTS rate_limit_state (
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  operation      text NOT NULL,
  window_start   timestamptz NOT NULL,
  count          integer NOT NULL DEFAULT 0,
  PRIMARY KEY (application_id, operation, window_start)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts                   timestamptz NOT NULL DEFAULT now(),
  actor                text NOT NULL CHECK (actor IN ('app', 'admin', 'system')),
  application_id       uuid,
  app_id               text,
  request_id           text NOT NULL,
  endpoint             text NOT NULL,
  provider             text,
  operation            text,
  outcome              text NOT NULL CHECK (outcome IN ('success', 'failure')),
  http_status          integer NOT NULL,
  latency_ms           integer NOT NULL DEFAULT 0,
  rate_limit_remaining integer,
  error_code           text,
  ip_hash              text
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_events(app_id);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_events(operation);

COMMIT;
