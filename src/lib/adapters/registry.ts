import { geminiAdapter } from "./gemini";
import { groqAdapter } from "./groq";
import { httpGenericAdapter } from "./http-generic";
import type { Adapter } from "./types";

/**
 * Adapter registry. Provider adapters are modular; `http-generic` covers
 * arbitrary HTTPS providers via admin-approved configuration. Capability
 * names (what clients request) live in the DATABASE — not here.
 */
const adapters: Readonly<Record<string, Adapter>> = {
  gemini: geminiAdapter,
  groq: groqAdapter,
  "http-generic": httpGenericAdapter
};

export function getAdapter(providerId: string): Adapter | null {
  return adapters[providerId] ?? null;
}

export function listAdapters(): { providerId: string; operations: string[] }[] {
  return Object.values(adapters).map((a) => ({ providerId: a.providerId, operations: [...a.supportedOperations] }));
}

/** Capability name format: "ai.generate", "weather.current", "payments.create", … */
export const CAPABILITY_NAME_RE = /^[a-z][a-z0-9]*(\.[a-z0-9_-]+){1,3}$/;
