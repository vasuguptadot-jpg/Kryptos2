import { randomUUID } from "node:crypto";
import { BUILTIN_CAPABILITIES, BUILTIN_SECRETS } from "./builtins";
import type {
  ApplicationRecord,
  AppStatus,
  AuditEvent,
  AuditEventRow,
  CapabilityRecord,
  CredentialRecord,
  PermissionRecord,
  SecretRecord,
  Store,
  StoreStats
} from "./types";

/**
 * In-memory Store. Used for automated tests and local development only.
 * Refused in production (see store.ts). Data is lost on restart — it must
 * never be a source of authorization truth in production.
 */
export class MemoryStore implements Store {
  private applications = new Map<string, ApplicationRecord & { updatedAt: string }>();
  private byAppId = new Map<string, string>();
  private credentials = new Map<string, CredentialRecord>();
  private permissions = new Map<string, PermissionRecord[]>();
  private audit: AuditEventRow[] = [];
  private rateWindows = new Map<string, number>();

  constructor() {
    // Synchronously pre-register built-in metadata (env names only) so the
    // very first request in dev/test sees a consistent registry. Production
    // gets the same rows from migration 002 instead.
    const now = new Date().toISOString();
    for (const s of BUILTIN_SECRETS) {
      const id = randomUUID();
      this.secrets.set(id, {
        id,
        secretName: s.secretName,
        providerId: s.providerId,
        notes: s.notes,
        enabled: true,
        createdAt: now,
        updatedAt: now
      });
    }
    for (const c of BUILTIN_CAPABILITIES) {
      this.capabilities.set(c.capability, {
        ...c,
        enabled: true,
        createdAt: now,
        updatedAt: now
      });
    }
  }

  async ping(): Promise<void> {}

  async getApplicationByAppId(appId: string): Promise<ApplicationRecord | null> {
    const id = this.byAppId.get(appId);
    if (!id) return null;
    const rec = this.applications.get(id)!;
    const { updatedAt: _u, ...app } = rec;
    return app;
  }

  async listApplications(): Promise<ApplicationRecord[]> {
    return [...this.applications.values()].map(({ updatedAt: _u, ...app }) => app);
  }

  async createApplication(input: {
    appId: string;
    displayName: string;
    defaultRateLimit: number;
  }): Promise<ApplicationRecord> {
    if (this.byAppId.has(input.appId)) throw new Error("app_id_exists");
    const now = new Date().toISOString();
    const rec = {
      id: randomUUID(),
      appId: input.appId,
      displayName: input.displayName,
      status: "active" as AppStatus,
      defaultRateLimit: input.defaultRateLimit,
      createdAt: now,
      updatedAt: now,
      lastUsedAt: null
    };
    this.applications.set(rec.id, rec);
    this.byAppId.set(rec.appId, rec.id);
    const { updatedAt: _u, ...app } = rec;
    return app;
  }

  async setApplicationStatus(id: string, status: AppStatus): Promise<void> {
    const rec = this.applications.get(id);
    if (!rec) throw new Error("app_not_found");
    rec.status = status;
    rec.updatedAt = new Date().toISOString();
  }

  async getActiveCredentials(applicationId: string): Promise<CredentialRecord[]> {
    return [...this.credentials.values()].filter(
      (c) => c.applicationId === applicationId && c.status === "active"
    );
  }

  async createCredential(
    applicationId: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<CredentialRecord> {
    const rec: CredentialRecord = {
      id: randomUUID(),
      applicationId,
      keyHash,
      keyPrefix,
      status: "active",
      createdAt: new Date().toISOString(),
      lastUsedAt: null
    };
    this.credentials.set(rec.id, rec);
    return rec;
  }

  async revokeCredentials(applicationId: string): Promise<void> {
    for (const c of this.credentials.values()) {
      if (c.applicationId === applicationId) c.status = "revoked";
    }
  }

  async touchCredential(credentialId: string, applicationId: string, when: Date): Promise<void> {
    const cred = this.credentials.get(credentialId);
    if (cred) cred.lastUsedAt = when.toISOString();
    const app = this.applications.get(applicationId);
    if (app) app.lastUsedAt = when.toISOString();
  }

  async getPermissions(applicationId: string): Promise<PermissionRecord[]> {
    return this.permissions.get(applicationId) ?? [];
  }

  // --- Secret registry -------------------------------------------------------

  private secrets = new Map<string, SecretRecord>();
  private capabilities = new Map<string, CapabilityRecord>();

  async listSecrets(): Promise<SecretRecord[]> {
    return [...this.secrets.values()].sort((a, b) => a.secretName.localeCompare(b.secretName));
  }

  async getSecretByName(secretName: string): Promise<SecretRecord | null> {
    for (const s of this.secrets.values()) if (s.secretName === secretName) return s;
    return null;
  }

  async createSecret(input: {
    secretName: string;
    providerId: string;
    notes: string;
  }): Promise<SecretRecord> {
    if (await this.getSecretByName(input.secretName)) throw new Error("secret_exists");
    const now = new Date().toISOString();
    const rec: SecretRecord = {
      id: randomUUID(),
      secretName: input.secretName,
      providerId: input.providerId,
      notes: input.notes,
      enabled: true,
      createdAt: now,
      updatedAt: now
    };
    this.secrets.set(rec.id, rec);
    return rec;
  }

  async setSecretEnabled(id: string, enabled: boolean): Promise<void> {
    const rec = this.secrets.get(id);
    if (!rec) throw new Error("secret_not_found");
    rec.enabled = enabled;
    rec.updatedAt = new Date().toISOString();
  }

  async deleteSecret(id: string): Promise<void> {
    const rec = this.secrets.get(id);
    if (!rec) throw new Error("secret_not_found");
    if ([...this.capabilities.values()].some((c) => c.secretName === rec.secretName)) {
      throw new Error("secret_in_use");
    }
    this.secrets.delete(id);
  }

  // --- Capability registry -----------------------------------------------------

  async listCapabilities(): Promise<CapabilityRecord[]> {
    return [...this.capabilities.values()].sort((a, b) => a.capability.localeCompare(b.capability));
  }

  async getCapability(capability: string): Promise<CapabilityRecord | null> {
    return this.capabilities.get(capability) ?? null;
  }

  async upsertCapability(input: {
    capability: string;
    providerId: string;
    secretName: string;
    operation: string;
    config: Record<string, unknown>;
    enabled: boolean;
  }): Promise<CapabilityRecord> {
    const existing = this.capabilities.get(input.capability);
    const now = new Date().toISOString();
    const rec: CapabilityRecord = {
      ...input,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.capabilities.set(rec.capability, rec);
    return rec;
  }

  async deleteCapability(capability: string): Promise<void> {
    if (!this.capabilities.delete(capability)) throw new Error("capability_not_found");
  }

  async setPermissions(
    applicationId: string,
    perms: { permission: string; rateLimitPerMinute: number | null }[]
  ): Promise<void> {
    this.permissions.set(
      applicationId,
      perms.map((p) => ({ applicationId, ...p }))
    );
  }

  async incrementRateLimit(
    applicationId: string,
    operation: string,
    windowStart: Date
  ): Promise<number> {
    // Epoch milliseconds — colon-free, so prune can parse the suffix safely.
    const key = `${applicationId}|${operation}|${windowStart.getTime()}`;
    const next = (this.rateWindows.get(key) ?? 0) + 1;
    this.rateWindows.set(key, next);
    return next;
  }

  async pruneRateLimits(olderThan: Date): Promise<void> {
    const cutoff = olderThan.getTime();
    for (const key of this.rateWindows.keys()) {
      const windowMs = Number(key.slice(key.lastIndexOf("|") + 1));
      if (!Number.isNaN(windowMs) && windowMs < cutoff) this.rateWindows.delete(key);
    }
  }

  async insertAudit(event: AuditEvent): Promise<void> {
    this.audit.unshift({ id: randomUUID(), ts: new Date().toISOString(), ...event });
    if (this.audit.length > 5000) this.audit.length = 5000;
  }

  async listAudit(limit: number): Promise<AuditEventRow[]> {
    return this.audit.slice(0, limit);
  }

  async stats(): Promise<StoreStats> {
    const perProvider = new Map<string, NonNullable<StoreStats["perProvider"]>[number]>();
    const perApp = new Map<string, { appId: string; total: number; failures: number }>();
    let failures = 0;
    let limited = 0;
    for (const e of this.audit) {
      if (e.outcome === "failure") failures += 1;
      if (e.httpStatus === 429) limited += 1;
      if (e.provider || e.operation) {
        const key = `${e.provider ?? ""}|${e.operation ?? ""}`;
        const cur =
          perProvider.get(key) ?? {
            provider: e.provider,
            operation: e.operation,
            total: 0,
            failures: 0,
            rateLimited: 0,
            lastUsedAt: null
          };
        cur.total += 1;
        if (e.outcome === "failure") cur.failures += 1;
        if (e.httpStatus === 429) cur.rateLimited += 1;
        if (!cur.lastUsedAt || e.ts > cur.lastUsedAt) cur.lastUsedAt = e.ts;
        perProvider.set(key, cur);
      }
      if (e.appId) {
        const cur = perApp.get(e.appId) ?? { appId: e.appId, total: 0, failures: 0 };
        cur.total += 1;
        if (e.outcome === "failure") cur.failures += 1;
        perApp.set(e.appId, cur);
      }
    }
    return {
      totalEvents: this.audit.length,
      totalFailures: failures,
      totalRateLimited: limited,
      perProvider: [...perProvider.values()],
      perApplication: [...perApp.values()]
    };
  }
}
