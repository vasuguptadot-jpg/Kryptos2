/**
 * Built-in registrations shipped with migration 002 (SQL has the equivalents).
 * These exist so existing Gemini/Groq deployments keep working and serve as
 * reference examples. They are METADATA only — no secret values.
 */
export const BUILTIN_SECRETS = [
  { secretName: "GEMINI_API_KEY", providerId: "gemini", notes: "Google Gemini API key (env)" },
  { secretName: "GROQ_API_KEY", providerId: "groq", notes: "Groq API key (env)" }
] as const;

export const BUILTIN_CAPABILITIES = [
  {
    capability: "gemini.generate",
    providerId: "gemini",
    secretName: "GEMINI_API_KEY",
    operation: "generateText",
    config: {}
  },
  {
    capability: "gemini.test",
    providerId: "gemini",
    secretName: "GEMINI_API_KEY",
    operation: "test",
    config: {}
  },
  {
    capability: "groq.generate",
    providerId: "groq",
    secretName: "GROQ_API_KEY",
    operation: "generateText",
    config: {}
  },
  {
    capability: "groq.test",
    providerId: "groq",
    secretName: "GROQ_API_KEY",
    operation: "test",
    config: {}
  }
] as const;

// Note: the in-memory development store registers these synchronously in its
// constructor; production Postgres gets them from db/migrations/002.
