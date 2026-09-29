import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { GET as healthGET } from "../src/app/api/health/route";
import {
  classifyDbError,
  diagnosticFromCaught,
  inspectConnectionString,
  isTlsVerificationEnforced,
  safeReason,
  sanitizeDbErrorMessage,
  tlsVerificationMode,
  type DbDiagnosticCode
} from "../src/lib/db-diagnostics";
import { postgresTlsConfig } from "../src/lib/postgres-tls";
import { StoreUnavailableError, getStore, resetStoreForTests } from "../src/lib/store";

const SECRET_URL =
  "postgres://kryptos_user:p%40ssw0rd-SECRET@db.internal.example:5432/kryptos?sslmode=require";
const SUPABASE_ROOT_2021_CA = readFileSync(join(__dirname, "fixtures", "supabase-root-2021-ca.crt"), "utf8").trim();

function withEnv(overrides: Record<string, string | undefined>, fn: () => void | Promise<void>): Promise<void> {
  const prev: Record<string, string | undefined> = {};
  for (const key of Object.keys(overrides)) {
    prev[key] = process.env[key];
    const value = overrides[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  resetStoreForTests();
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const key of Object.keys(overrides)) {
        if (prev[key] === undefined) delete process.env[key];
        else process.env[key] = prev[key];
      }
      resetStoreForTests();
    });
}

describe("database diagnostics", () => {
  after(() => {
    resetStoreForTests();
  });

  it("inspects a missing DATABASE_URL without inventing facts", () => {
    const facts = inspectConnectionString(undefined);
    assert.equal(facts.present, false);
    assert.equal(facts.valid, false);
    assert.equal(facts.scheme, null);
    assert.equal(facts.hasPassword, false);
    assert.equal(facts.sslMode, null);
  });

  it("reports structure of a postgres URL without leaking host, user, or password", () => {
    const facts = inspectConnectionString(SECRET_URL);
    assert.equal(facts.present, true);
    assert.equal(facts.valid, true);
    assert.equal(facts.scheme, "postgres");
    assert.equal(facts.hasUsername, true);
    assert.equal(facts.hasPassword, true);
    assert.equal(facts.sslMode, "require");
    const serialized = JSON.stringify(facts);
    assert.ok(!serialized.includes("p%40ssw0rd-SECRET"));
    assert.ok(!serialized.includes("p@ssw0rd-SECRET"));
    assert.ok(!serialized.includes("db.internal.example"));
    assert.ok(!serialized.includes("kryptos_user"));
    assert.ok(!serialized.includes("5432"));
    assert.ok(!serialized.includes(SECRET_URL));
  });

  it("marks non-postgres and unparsable values as invalid", () => {
    assert.equal(inspectConnectionString("not a url").valid, false);
    assert.equal(inspectConnectionString("http://example.com/db").valid, false);
    assert.equal(inspectConnectionString("http://example.com/db").scheme, "other");
    assert.equal(inspectConnectionString("").present, false);
  });

  it("classifies TLS certificate failures", () => {
    assert.equal(
      classifyDbError(Object.assign(new Error("self signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" })),
      "tls_failure"
    );
    assert.equal(
      classifyDbError(Object.assign(new Error("unable to verify the first certificate"), { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" })),
      "tls_failure"
    );
  });

  it("classifies an invalid configured CA without exposing its value", () => {
    const err = new Error("database_ca_cert_invalid");
    assert.equal(classifyDbError(err), "invalid_ca_cert");
    return withEnv({ DATABASE_URL: SECRET_URL }, () => {
      const diag = diagnosticFromCaught(err);
      assert.equal(diag.code, "invalid_ca_cert");
      assert.equal(diag.reason, "configured CA certificate is invalid");
      assert.equal(diag.tlsVerification, "enforced");
    });
  });

  it("classifies authentication failures", () => {
    assert.equal(
      classifyDbError(Object.assign(new Error("password authentication failed for user \"kryptos\""), { code: "28P01" })),
      "auth_failure"
    );
    assert.equal(classifyDbError(new Error("no pg_hba.conf entry for host")), "auth_failure");
  });

  it("classifies timeouts, DNS, and connection-refused errors", () => {
    assert.equal(classifyDbError(new Error("timeout")), "timeout");
    assert.equal(
      classifyDbError(Object.assign(new Error("connect ETIMEDOUT"), { code: "ETIMEDOUT" })),
      "timeout"
    );
    assert.equal(
      classifyDbError(Object.assign(new Error("getaddrinfo ENOTFOUND db.internal.example"), { code: "ENOTFOUND" })),
      "dns_failure"
    );
    assert.equal(
      classifyDbError(Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5432"), { code: "ECONNREFUSED" })),
      "connection_refused"
    );
  });

  it("classifies a missing database catalog", () => {
    assert.equal(
      classifyDbError(Object.assign(new Error("database \"kryptos\" does not exist"), { code: "3D000" })),
      "database_missing"
    );
  });

  it("sanitizes connection strings and userinfo out of error messages", () => {
    const err = new Error(`connection to ${SECRET_URL} failed as kryptos_user:p@ssw0rd-SECRET@db.internal.example`);
    const sanitized = sanitizeDbErrorMessage(err);
    assert.ok(!sanitized.includes("p@ssw0rd-SECRET"));
    assert.ok(!sanitized.includes("p%40ssw0rd-SECRET"));
    assert.ok(!sanitized.includes(SECRET_URL));
    assert.ok(sanitized.includes("[REDACTED]"));
  });

  it("enforces TLS verification and rejects disabled PGSSLMODE", async () => {
    await withEnv({ PGSSLMODE: undefined, DATABASE_CA_CERT: undefined }, () => {
      assert.equal(tlsVerificationMode(), "enforced");
      assert.equal(isTlsVerificationEnforced(), true);
      assert.deepEqual(postgresTlsConfig(), { rejectUnauthorized: true });
    });
    await withEnv({ PGSSLMODE: "require" }, () => {
      assert.deepEqual(postgresTlsConfig(), { rejectUnauthorized: true });
      assert.equal(tlsVerificationMode(), "enforced");
    });
    await withEnv({ PGSSLMODE: "disable" }, () => {
      assert.throws(() => postgresTlsConfig(), /postgres_tls_unsafe_configuration/);
      assert.equal(tlsVerificationMode(), "enforced");
      assert.equal(isTlsVerificationEnforced(), true);
    });
  });

  it("rejects process-wide disabling of Node TLS verification", async () => {
    await withEnv({ NODE_TLS_REJECT_UNAUTHORIZED: "0", DATABASE_CA_CERT: undefined }, () => {
      assert.throws(() => postgresTlsConfig(), /postgres_tls_unsafe_configuration/);
    });
  });

  it("tags StoreUnavailableError as not_configured when DATABASE_URL is missing", async () => {
    await withEnv({ STORE_BACKEND: "postgres", DATABASE_URL: undefined }, () => {
      assert.throws(
        () => getStore(),
        (err: unknown) =>
          err instanceof StoreUnavailableError &&
          err.diagnosticCode === "not_configured"
      );
    });
  });

  it("maps a tagged store error onto a secret-free diagnostic", () => {
    const err = new StoreUnavailableError("DATABASE_URL is not configured (fail closed)", "not_configured");
    const diag = diagnosticFromCaught(err);
    assert.equal(diag.code, "not_configured");
    assert.equal(diag.database, "not_configured");
    assert.equal(diag.reason, "DATABASE_URL is not set");
    const serialized = JSON.stringify(diag);
    assert.ok(!serialized.includes("postgres://"));
    assert.ok(!serialized.toLowerCase().includes("password"));
  });

  it("health reports not_configured diagnostics without leaking DATABASE_URL", async () => {
    await withEnv({ STORE_BACKEND: "postgres", DATABASE_URL: SECRET_URL, PGSSLMODE: undefined }, async () => {
      // URL is present but we have no live database — ping will fail closed.
      // Replace the store with a throwing ping so this test never opens a socket.
      resetStoreForTests({
        ping: async () => {
          throw Object.assign(new Error(`connect ${SECRET_URL}`), { code: "ENOTFOUND" });
        },
        listCapabilities: async () => []
      } as never);

      const res = await healthGET();
      assert.equal(res.status, 200);
      const text = await res.text();
      const body = JSON.parse(text) as {
        database: string;
        databaseDiagnostic: { code: string; tlsVerification: string; reason: string };
      };
      assert.equal(body.database, "unavailable");
      assert.equal(body.databaseDiagnostic.code, "dns_failure");
      assert.equal(body.databaseDiagnostic.tlsVerification, "enforced");
      assert.ok(!text.includes(SECRET_URL));
      assert.ok(!text.includes("p%40ssw0rd-SECRET"));
      assert.ok(!text.includes("db.internal.example"));
      assert.ok(!text.includes("kryptos_user"));
    });

    await withEnv({ STORE_BACKEND: "postgres", DATABASE_URL: undefined }, async () => {
      const res = await healthGET();
      assert.equal(res.status, 200);
      const text = await res.text();
      const body = JSON.parse(text) as {
        database: string;
        databaseDiagnostic: { code: string; tlsVerification: string; reason: string };
      };
      assert.equal(body.database, "not_configured");
      assert.equal(body.databaseDiagnostic.code, "not_configured");
      assert.equal(body.databaseDiagnostic.tlsVerification, "enforced");
      assert.ok(!text.includes("postgres://"));
      assert.ok(!text.toLowerCase().includes("password"));
    });
  });

  it("health reports malformed CA diagnostics without exposing certificate material", async () => {
    const malformedCa = "-----BEGIN CERTIFICATE-----malformed-and-private-----END CERTIFICATE-----";
    await withEnv(
      {
        STORE_BACKEND: "postgres",
        DATABASE_URL: SECRET_URL,
        DATABASE_CA_CERT: malformedCa,
        NODE_TLS_REJECT_UNAUTHORIZED: undefined,
        PGSSLMODE: undefined
      },
      async () => {
        const res = await healthGET();
        const text = await res.text();
        const body = JSON.parse(text) as {
          databaseDiagnostic: { code: string; tlsVerification: string; reason: string };
        };
        assert.equal(body.databaseDiagnostic.code, "invalid_ca_cert");
        assert.equal(body.databaseDiagnostic.tlsVerification, "enforced");
        assert.equal(body.databaseDiagnostic.reason, "configured CA certificate is invalid");
        assert.ok(!text.includes(malformedCa));
        assert.ok(!text.includes("BEGIN CERTIFICATE"));
      }
    );
  });

  it("health never returns the configured CA or its fingerprint", async () => {
    await withEnv(
      {
        STORE_BACKEND: "postgres",
        DATABASE_URL: SECRET_URL,
        DATABASE_CA_CERT: SUPABASE_ROOT_2021_CA,
        NODE_TLS_REJECT_UNAUTHORIZED: undefined,
        PGSSLMODE: undefined
      },
      async () => {
        resetStoreForTests({
          ping: async () => {
            throw Object.assign(new Error("connect ENOTFOUND"), { code: "ENOTFOUND" });
          },
          listCapabilities: async () => []
        } as never);

        const response = await healthGET();
        const body = await response.text();
        const fingerprint = new X509Certificate(SUPABASE_ROOT_2021_CA).fingerprint256;
        assert.ok(!body.includes(SUPABASE_ROOT_2021_CA));
        assert.ok(!body.includes(fingerprint));
        assert.ok(!body.includes("BEGIN CERTIFICATE"));
      }
    );
  });

  it("health maps PostgreSQL failures to safe diagnostic classifications", async () => {
    const errorDetails = [
      SECRET_URL,
      "MIIDOTCC_CA_PRIVATE_MATERIAL",
      "RAW_POSTGRES_ERROR_MARKER"
    ];
    const detail = errorDetails.join(" ");
    const cases: Array<{ code: DbDiagnosticCode; error: Error }> = [
      { code: "invalid_ca_cert", error: new Error(`database_ca_cert_invalid ${detail}`) },
      { code: "unsafe_tls_config", error: new Error(`postgres_tls_unsafe_configuration ${detail}`) },
      {
        code: "tls_failure",
        error: Object.assign(new Error(`certificate verification failed ${detail}`), {
          code: "ERR_TLS_CERT_ALTNAME_INVALID"
        })
      },
      {
        code: "tcp_failure",
        error: Object.assign(new Error(`socket reset ${detail}`), { code: "ECONNRESET" })
      },
      {
        code: "schema_failure",
        error: Object.assign(new Error(`schema unavailable ${detail}`), { code: "3F000" })
      },
      { code: "database_unreachable", error: new Error(`unclassified failure ${detail}`) }
    ];

    await withEnv(
      { STORE_BACKEND: "postgres", DATABASE_URL: SECRET_URL, PGSSLMODE: undefined },
      async () => {
        for (const { code, error } of cases) {
          resetStoreForTests({
            ping: async () => {
              throw error;
            },
            listCapabilities: async () => []
          } as never);

          const res = await healthGET();
          assert.equal(res.status, 200);
          const text = await res.text();
          const body = JSON.parse(text) as {
            database: string;
            databaseDiagnostic: { code: string; tlsVerification: string; reason: string };
          };
          assert.equal(body.database, "unavailable");
          assert.equal(body.databaseDiagnostic.code, code);
          assert.equal(body.databaseDiagnostic.tlsVerification, "enforced");
          assert.equal(body.databaseDiagnostic.reason, safeReason(code));
          for (const secretOrRawDetail of errorDetails) {
            assert.ok(!text.includes(secretOrRawDetail));
          }
        }
      }
    );
  });
});
