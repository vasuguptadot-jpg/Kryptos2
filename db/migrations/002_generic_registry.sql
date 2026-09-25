-- KRYPTOS BROKER — migration 002: generic secret & capability registries.
-- METADATA ONLY. Raw secret values remain in the deployment environment and
-- are never stored here. Apply with:  psql "$DATABASE_URL" -f db/migrations/002_generic_registry.sql

BEGIN;

-- Registered secret metadata (env var names, providers, enable switches).
CREATE TABLE IF NOT EXISTS secret_registry (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_name text NOT NULL UNIQUE CHECK (secret_name ~ '^[A-Z][A-Z0-9_]{1,63}$'),
  provider_id text NOT NULL,
  notes       text NOT NULL DEFAULT '',
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- What clients may request. The client names ONLY `capability`; the mapping
-- to provider/operation/secret reference is strictly server-side.
CREATE TABLE IF NOT EXISTS capabilities (
  capability  text PRIMARY KEY
              CHECK (capability ~ '^[a-z][a-z0-9]*(\.[a-z0-9_-]+){1,3}$'),
  provider_id text NOT NULL,
  secret_name text NOT NULL REFERENCES secret_registry(secret_name) ON DELETE RESTRICT,
  operation   text NOT NULL,
  config      jsonb NOT NULL DEFAULT '{}',
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Built-in registrations so existing Gemini/Groq integrations keep working.
INSERT INTO secret_registry (secret_name, provider_id, notes)
VALUES ('GEMINI_API_KEY', 'gemini', 'Google Gemini API key (env)'),
       ('GROQ_API_KEY', 'groq', 'Groq API key (env)')
ON CONFLICT (secret_name) DO NOTHING;

INSERT INTO capabilities (capability, provider_id, secret_name, operation, config, enabled)
VALUES ('gemini.generate', 'gemini', 'GEMINI_API_KEY', 'generateText', '{}', true),
       ('gemini.test',     'gemini', 'GEMINI_API_KEY', 'test',         '{}', true),
       ('groq.generate',   'groq',   'GROQ_API_KEY',   'generateText', '{}', true),
       ('groq.test',       'groq',   'GROQ_API_KEY',   'test',         '{}', true)
ON CONFLICT (capability) DO NOTHING;

COMMIT;
