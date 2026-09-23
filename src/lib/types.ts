export type AppStatus = "active" | "disabled" | "revoked";
export type CredentialStatus = "active" | "revoked";
export type AuditActor = "app" | "admin" | "system";
export type AuditOutcome = "success" | "failure";

export interface ApplicationRecord {
  id: string;
  appId: string;
  displayName: string;
  status: AppStatus;
  defaultRateLimit: number;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface CredentialRecord {
  id: string;
  applicationId: string;
  keyHash: string;
  keyPrefix: string;
  status: CredentialStatus;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface PermissionRecord {
  applicationId: string;
  /** The capability string granted to the app, e.g. "ai.generate". */
  permission: string;
  rateLimitPerMinute: number | null;
}

/**
 * Secret registry record — METADATA ONLY. The raw secret value lives in the
 * deployment environment (e.g. Vercel env vars) and is never stored here.
 */
export interface SecretRecord {
  id: string;
  /** Environment variable name the value is resolved from, e.g. "GEMINI_API_KEY". */
  secretName: string;
  providerId: string;
  notes: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/**
 * Capability registry record — what clients may request. The client names
 * ONLY the capability; provider, operation and secret reference are server-side.
 */
export interface CapabilityRecord {
  /** e.g. "ai.generate", "weather.current" */
  capability: string;
  providerId: string;
  /** Registry reference (env var name), never the value. */
  secretName: string;
  /** Adapter-level operation key, e.g. "generateText". */
  operation: string;
  /** Adapter-specific configuration (strictly validated per adapter). */
  config: Record<string, unknown>;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AuditEvent {
  actor: AuditActor;
  applicationId: string | null;
  appId: string | null;
  requestId: string;
  endpoint: string;
  provider: string | null;
  operation: string | null;
  outcome: AuditOutcome;
  httpStatus: number;
  latencyMs: number;
  rateLimitRemaining: number | null;
  errorCode: string | null;
  /** sha256 of the client IP, never the raw IP. */
  ipHash: string | null;
}

export interface AuditEventRow extends AuditEvent {
  id: string;
  ts: string;
}

export interface ProviderUsageStat {
  provider: string | null;
  operation: string | null;
  total: number;
  failures: number;
  rateLimited: number;
  lastUsedAt: string | null;
}

export interface StoreStats {
  totalEvents: number;
  totalFailures: number;
  totalRateLimited: number;
  perProvider: ProviderUsageStat[];
  perApplication: { appId: string; total: number; failures: number }[];
}

export interface Store {
  ping(): Promise<void>;
  getApplicationByAppId(appId: string): Promise<ApplicationRecord | null>;
  listApplications(): Promise<ApplicationRecord[]>;
  createApplication(input: {
    appId: string;
    displayName: string;
    defaultRateLimit: number;
  }): Promise<ApplicationRecord>;
  setApplicationStatus(id: string, status: AppStatus): Promise<void>;

  getActiveCredentials(applicationId: string): Promise<CredentialRecord[]>;
  createCredential(
    applicationId: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<CredentialRecord>;
  revokeCredentials(applicationId: string): Promise<void>;
  touchCredential(credentialId: string, applicationId: string, when: Date): Promise<void>;

  getPermissions(applicationId: string): Promise<PermissionRecord[]>;
  setPermissions(
    applicationId: string,
    perms: { permission: string; rateLimitPerMinute: number | null }[]
  ): Promise<void>;

  // --- Secret registry (metadata only) -------------------------------------
  listSecrets(): Promise<SecretRecord[]>;
  getSecretByName(secretName: string): Promise<SecretRecord | null>;
  createSecret(input: { secretName: string; providerId: string; notes: string }): Promise<SecretRecord>;
  setSecretEnabled(id: string, enabled: boolean): Promise<void>;
  deleteSecret(id: string): Promise<void>;

  // --- Capability registry ---------------------------------------------------
  listCapabilities(): Promise<CapabilityRecord[]>;
  getCapability(capability: string): Promise<CapabilityRecord | null>;
  upsertCapability(input: {
    capability: string;
    providerId: string;
    secretName: string;
    operation: string;
    config: Record<string, unknown>;
    enabled: boolean;
  }): Promise<CapabilityRecord>;
  deleteCapability(capability: string): Promise<void>;

  /** Atomically increment and return the current count for this window. */
  incrementRateLimit(applicationId: string, operation: string, windowStart: Date): Promise<number>;
  pruneRateLimits(olderThan: Date): Promise<void>;

  insertAudit(event: AuditEvent): Promise<void>;
  listAudit(limit: number): Promise<AuditEventRow[]>;
  stats(): Promise<StoreStats>;
}
