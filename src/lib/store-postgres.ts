import { Pool } from "pg";
import { classifyDbError, sanitizeDbErrorMessage, tlsVerificationMode } from "./db-diagnostics";
import { logger } from "./logger";
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
 * SSL config for the pg Pool. TLS verification stays enforced unless the
 * operator explicitly set PGSSLMODE=disable (local development only).
 * Never sets rejectUnauthorized: false.
 */
export function postgresSslConfig(): { rejectUnauthorized: true } | undefined {
  return process.env.PGSSLMODE === "disable" ? undefined : { rejectUnauthorized: true };
}

function logPostgresFailure(event: string, err: unknown): void {
  logger.error(event, {
    diagnostic: classifyDbError(err),
    reason: sanitizeDbErrorMessage(err),
    tlsVerification: tlsVerificationMode()
  });
}

/**
 * Postgres-backed Store. Works with Vercel Postgres, Neon or Supabase
 * (any DATABASE_URL). Stores metadata only — never provider secrets.
 */
export class PostgresStore implements Store {
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 3,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
      ssl: postgresSslConfig()
    });
    this.pool.on("error", (err) => {
      logPostgresFailure("postgres_pool_error", err);
    });
  }

  async ping(): Promise<void> {
    try {
      await this.pool.query("SELECT 1");
    } catch (err) {
      logPostgresFailure("postgres_ping_failed", err);
      throw err;
    }
  }

  async getApplicationByAppId(appId: string): Promise<ApplicationRecord | null> {
    const res = await this.pool.query(
      `SELECT id, app_id, display_name, status, default_rate_limit, created_at, last_used_at
       FROM applications WHERE app_id = $1`,
      [appId]
    );
    return res.rows[0] ? mapApp(res.rows[0]) : null;
  }

  async listApplications(): Promise<ApplicationRecord[]> {
    const res = await this.pool.query(
      `SELECT id, app_id, display_name, status, default_rate_limit, created_at, last_used_at
       FROM applications ORDER BY created_at DESC`
    );
    return res.rows.map(mapApp);
  }

  async createApplication(input: {
    appId: string;
    displayName: string;
    defaultRateLimit: number;
  }): Promise<ApplicationRecord> {
    try {
      const res = await this.pool.query(
        `INSERT INTO applications (app_id, display_name, default_rate_limit)
         VALUES ($1, $2, $3)
         RETURNING id, app_id, display_name, status, default_rate_limit, created_at, last_used_at`,
        [input.appId, input.displayName, input.defaultRateLimit]
      );
      return mapApp(res.rows[0]);
    } catch (err) {
      if ((err as { code?: string }).code === "23505") throw new Error("app_id_exists");
      throw err;
    }
  }

  async setApplicationStatus(id: string, status: AppStatus): Promise<void> {
    const res = await this.pool.query(
      `UPDATE applications SET status = $2, updated_at = now() WHERE id = $1`,
      [id, status]
    );
    if (res.rowCount === 0) throw new Error("app_not_found");
  }

  async getActiveCredentials(applicationId: string): Promise<CredentialRecord[]> {
    const res = await this.pool.query(
      `SELECT id, application_id, key_hash, key_prefix, status, created_at, last_used_at
       FROM application_credentials
       WHERE application_id = $1 AND status = 'active'`,
      [applicationId]
    );
    return res.rows.map(mapCredential);
  }

  async createCredential(
    applicationId: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<CredentialRecord> {
    const res = await this.pool.query(
      `INSERT INTO application_credentials (application_id, key_hash, key_prefix)
       VALUES ($1, $2, $3)
       RETURNING id, application_id, key_hash, key_prefix, status, created_at, last_used_at`,
      [applicationId, keyHash, keyPrefix]
    );
    return mapCredential(res.rows[0]);
  }

  async revokeCredentials(applicationId: string): Promise<void> {
    await this.pool.query(
      `UPDATE application_credentials SET status = 'revoked' WHERE application_id = $1`,
      [applicationId]
    );
  }

  async touchCredential(credentialId: string, applicationId: string, when: Date): Promise<void> {
    await Promise.all([
      this.pool.query(`UPDATE application_credentials SET last_used_at = $2 WHERE id = $1`, [
        credentialId,
        when
      ]),
      this.pool.query(`UPDATE applications SET last_used_at = $2 WHERE id = $1`, [
        applicationId,
        when
      ])
    ]);
  }

  async getPermissions(applicationId: string): Promise<PermissionRecord[]> {
    const res = await this.pool.query(
      `SELECT application_id, permission, rate_limit_per_minute
       FROM application_permissions WHERE application_id = $1`,
      [applicationId]
    );
    return res.rows.map((r) => ({
      applicationId: r.application_id,
      permission: r.permission,
      rateLimitPerMinute: r.rate_limit_per_minute
    }));
  }

  // --- Secret registry (metadata only — raw values never leave the env) ------

  async listSecrets(): Promise<SecretRecord[]> {
    const res = await this.pool.query(
      `SELECT id, secret_name, provider_id, notes, enabled, created_at, updated_at
       FROM secret_registry ORDER BY secret_name`
    );
    return res.rows.map(mapSecret);
  }

  async getSecretByName(secretName: string): Promise<SecretRecord | null> {
    const res = await this.pool.query(
      `SELECT id, secret_name, provider_id, notes, enabled, created_at, updated_at
       FROM secret_registry WHERE secret_name = $1`,
      [secretName]
    );
    return res.rows[0] ? mapSecret(res.rows[0]) : null;
  }

  async createSecret(input: {
    secretName: string;
    providerId: string;
    notes: string;
  }): Promise<SecretRecord> {
    try {
      const res = await this.pool.query(
        `INSERT INTO secret_registry (secret_name, provider_id, notes)
         VALUES ($1, $2, $3)
         RETURNING id, secret_name, provider_id, notes, enabled, created_at, updated_at`,
        [input.secretName, input.providerId, input.notes]
      );
      return mapSecret(res.rows[0]);
    } catch (err) {
      if ((err as { code?: string }).code === "23505") throw new Error("secret_exists");
      throw err;
    }
  }

  async setSecretEnabled(id: string, enabled: boolean): Promise<void> {
    const res = await this.pool.query(
      `UPDATE secret_registry SET enabled = $2, updated_at = now() WHERE id = $1`,
      [id, enabled]
    );
    if (res.rowCount === 0) throw new Error("secret_not_found");
  }

  async deleteSecret(id: string): Promise<void> {
    try {
      const res = await this.pool.query(`DELETE FROM secret_registry WHERE id = $1`, [id]);
      if (res.rowCount === 0) throw new Error("secret_not_found");
    } catch (err) {
      if ((err as { code?: string }).code === "23503") throw new Error("secret_in_use");
      throw err;
    }
  }

  // --- Capability registry -----------------------------------------------------

  async listCapabilities(): Promise<CapabilityRecord[]> {
    const res = await this.pool.query(
      `SELECT capability, provider_id, secret_name, operation, config, enabled, created_at, updated_at
       FROM capabilities ORDER BY capability`
    );
    return res.rows.map(mapCapability);
  }

  async getCapability(capability: string): Promise<CapabilityRecord | null> {
    const res = await this.pool.query(
      `SELECT capability, provider_id, secret_name, operation, config, enabled, created_at, updated_at
       FROM capabilities WHERE capability = $1`,
      [capability]
    );
    return res.rows[0] ? mapCapability(res.rows[0]) : null;
  }

  async upsertCapability(input: {
    capability: string;
    providerId: string;
    secretName: string;
    operation: string;
    config: Record<string, unknown>;
    enabled: boolean;
  }): Promise<CapabilityRecord> {
    const res = await this.pool.query(
      `INSERT INTO capabilities (capability, provider_id, secret_name, operation, config, enabled)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (capability)
       DO UPDATE SET provider_id = EXCLUDED.provider_id,
                     secret_name = EXCLUDED.secret_name,
                     operation = EXCLUDED.operation,
                     config = EXCLUDED.config,
                     enabled = EXCLUDED.enabled,
                     updated_at = now()
       RETURNING capability, provider_id, secret_name, operation, config, enabled, created_at, updated_at`,
      [
        input.capability,
        input.providerId,
        input.secretName,
        input.operation,
        JSON.stringify(input.config),
        input.enabled
      ]
    );
    return mapCapability(res.rows[0]);
  }

  async deleteCapability(capability: string): Promise<void> {
    const res = await this.pool.query(`DELETE FROM capabilities WHERE capability = $1`, [capability]);
    if (res.rowCount === 0) throw new Error("capability_not_found");
  }

  async setPermissions(
    applicationId: string,
    perms: { permission: string; rateLimitPerMinute: number | null }[]
  ): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`DELETE FROM application_permissions WHERE application_id = $1`, [
        applicationId
      ]);
      for (const p of perms) {
        await client.query(
          `INSERT INTO application_permissions (application_id, permission, rate_limit_per_minute)
           VALUES ($1, $2, $3)`,
          [applicationId, p.permission, p.rateLimitPerMinute]
        );
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async incrementRateLimit(
    applicationId: string,
    operation: string,
    windowStart: Date
  ): Promise<number> {
    const res = await this.pool.query(
      `INSERT INTO rate_limit_state (application_id, operation, window_start, count)
       VALUES ($1, $2, $3, 1)
       ON CONFLICT (application_id, operation, window_start)
       DO UPDATE SET count = rate_limit_state.count + 1
       RETURNING count`,
      [applicationId, operation, windowStart]
    );
    return Number(res.rows[0].count);
  }

  async pruneRateLimits(olderThan: Date): Promise<void> {
    await this.pool.query(`DELETE FROM rate_limit_state WHERE window_start < $1`, [olderThan]);
  }

  async insertAudit(event: AuditEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_events
        (actor, application_id, app_id, request_id, endpoint, provider, operation,
         outcome, http_status, latency_ms, rate_limit_remaining, error_code, ip_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        event.actor,
        event.applicationId,
        event.appId,
        event.requestId,
        event.endpoint,
        event.provider,
        event.operation,
        event.outcome,
        event.httpStatus,
        event.latencyMs,
        event.rateLimitRemaining,
        event.errorCode,
        event.ipHash
      ]
    );
  }

  async listAudit(limit: number): Promise<AuditEventRow[]> {
    const res = await this.pool.query(
      `SELECT id, ts, actor, application_id, app_id, request_id, endpoint, provider,
              operation, outcome, http_status, latency_ms, rate_limit_remaining,
              error_code, ip_hash
       FROM audit_events ORDER BY ts DESC LIMIT $1`,
      [limit]
    );
    return res.rows.map((r) => ({
      id: String(r.id),
      ts: new Date(r.ts).toISOString(),
      actor: r.actor,
      applicationId: r.application_id,
      appId: r.app_id,
      requestId: r.request_id,
      endpoint: r.endpoint,
      provider: r.provider,
      operation: r.operation,
      outcome: r.outcome,
      httpStatus: r.http_status,
      latencyMs: r.latency_ms,
      rateLimitRemaining: r.rate_limit_remaining,
      errorCode: r.error_code,
      ipHash: r.ip_hash
    }));
  }

  async stats(): Promise<StoreStats> {
    const totals = await this.pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE outcome = 'failure')::int AS failures,
              count(*) FILTER (WHERE http_status = 429)::int AS rate_limited
       FROM audit_events`
    );
    const perProvider = await this.pool.query(
      `SELECT provider, operation, count(*)::int AS total,
              count(*) FILTER (WHERE outcome = 'failure')::int AS failures,
              count(*) FILTER (WHERE http_status = 429)::int AS rate_limited,
              max(ts) AS last_used_at
       FROM audit_events
       WHERE provider IS NOT NULL OR operation IS NOT NULL
       GROUP BY provider, operation`
    );
    const perApp = await this.pool.query(
      `SELECT app_id, count(*)::int AS total,
              count(*) FILTER (WHERE outcome = 'failure')::int AS failures
       FROM audit_events
       WHERE app_id IS NOT NULL
       GROUP BY app_id`
    );
    return {
      totalEvents: totals.rows[0].total,
      totalFailures: totals.rows[0].failures,
      totalRateLimited: totals.rows[0].rate_limited,
      perProvider: perProvider.rows.map((r) => ({
        provider: r.provider,
        operation: r.operation,
        total: r.total,
        failures: r.failures,
        rateLimited: r.rate_limited,
        lastUsedAt: r.last_used_at ? new Date(r.last_used_at).toISOString() : null
      })),
      perApplication: perApp.rows.map((r) => ({
        appId: r.app_id,
        total: r.total,
        failures: r.failures
      }))
    };
  }
}

function mapApp(r: Record<string, unknown>): ApplicationRecord {
  return {
    id: String(r.id),
    appId: String(r.app_id),
    displayName: String(r.display_name),
    status: r.status as AppStatus,
    defaultRateLimit: Number(r.default_rate_limit),
    createdAt: new Date(r.created_at as string).toISOString(),
    lastUsedAt: r.last_used_at ? new Date(r.last_used_at as string).toISOString() : null
  };
}

function mapSecret(r: Record<string, unknown>): SecretRecord {
  return {
    id: String(r.id),
    secretName: String(r.secret_name),
    providerId: String(r.provider_id),
    notes: String(r.notes ?? ""),
    enabled: Boolean(r.enabled),
    createdAt: new Date(r.created_at as string).toISOString(),
    updatedAt: new Date(r.updated_at as string).toISOString()
  };
}

function mapCapability(r: Record<string, unknown>): CapabilityRecord {
  return {
    capability: String(r.capability),
    providerId: String(r.provider_id),
    secretName: String(r.secret_name),
    operation: String(r.operation),
    config: (r.config ?? {}) as Record<string, unknown>,
    enabled: Boolean(r.enabled),
    createdAt: new Date(r.created_at as string).toISOString(),
    updatedAt: new Date(r.updated_at as string).toISOString()
  };
}

function mapCredential(r: Record<string, unknown>): CredentialRecord {
  return {
    id: String(r.id),
    applicationId: String(r.application_id),
    keyHash: String(r.key_hash),
    keyPrefix: String(r.key_prefix),
    status: r.status as CredentialRecord["status"],
    createdAt: new Date(r.created_at as string).toISOString(),
    lastUsedAt: r.last_used_at ? new Date(r.last_used_at as string).toISOString() : null
  };
}
