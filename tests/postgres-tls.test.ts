import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyDbError, sanitizeDbErrorMessage } from "../src/lib/db-diagnostics";
import { logger } from "../src/lib/logger";
import { postgresPoolConfig, postgresTlsConfig } from "../src/lib/postgres-tls";

const SYNTHETIC_CA = `-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIUa1jLaGbdyJXqG/NI+MMggdFuqvEwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZS3J5cHRvcyBTeW50aGV0aWMgVGVzdCBDQTAeFw0yNjA5
MjgwODExMDVaFw0yNjA5MzAwODExMDVaMCQxIjAgBgNVBAMMGUtyeXB0b3MgU3lu
dGhldGljIFRlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQ
Pwo3NFY2ydOfXhsZnsc55DgEJyc38kGnU+PqfvTbRUnB26hvF8L44fiUtQTau8xu
YkUtML3+hLUJ79WcwlWVZjWFL2UKr2CIU2Dv5RurGLIVxjEok8Vg7qLOXKHwpSLr
jpRAn0Se5aW6BSDJHcMNmFJwC5eX20Dp0S8GXmMU2L2ck5+g4Ym2w55UiWYSh8Nn
LWCGw2EKYf83PlF1IRdlHCUI56cNteJ3OhfW+ewINjy8+O6s9asKHQW4Vk2ntSvN
K3MvQCkHeduUyTi1Q3dPkSifh4EGp5d82DHbO/nG01pF6U5R6/UcwWtnvtSJkT8q
M1aKSJMGF31DmQz8XRSXAgMBAAGjYzBhMB0GA1UdDgQWBBTnEf+37LKs6wmwW6EJ
GXAsL+XS1jAfBgNVHSMEGDAWgBTnEf+37LKs6wmwW6EJGXAsL+XS1jAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEACfmW
n18WkSV88XXcVkYCog4EiWBuviGqYELCjc9qQ3xOiDv/xt9uXoM56P4PfmzHYdVW
7poewfm8yyJoVGiEnR8WV0ep0VS+KLGJlQy4u2B5SdXlI6pQum2oUcTT/L3ymSjB
e9DXE7D5vx8qJuUg4s3mHttGk0IvwUuiUYlEWlsbH7D4PQ7UR2aBMlVPpqOg7nGG
HLGwx8hsjKGGeFKNTZTcOOomTLKCpzhTT13C9CYWzJ65TmllyEnqSKO5F2HugtWi
CPoGqR3Nvqdsutgadrtf7rwaj2oIkIwh5MuCwicUxJPTkLy+1GP2DHRJcvLdIwGP
/0APE4PiNk9MSbo/tA==
-----END CERTIFICATE-----`;
const DATABASE_URL = "postgres://synthetic_user:synthetic_password@db.example.test:5432/kryptos";
const SAFE_ENV: Record<string, string | undefined> = {};

function captureErrorLog(callback: () => void): string {
  const originalError = console.error;
  let output = "";
  console.error = (value?: unknown) => {
    output += String(value);
  };
  try {
    callback();
  } finally {
    console.error = originalError;
  }
  return output;
}

describe("verified PostgreSQL TLS configuration", () => {
  it("accepts a valid synthetic CA", () => {
    assert.deepEqual(postgresTlsConfig({ DATABASE_CA_CERT: SYNTHETIC_CA }), {
      rejectUnauthorized: true,
      ca: SYNTHETIC_CA
    });
  });

  it("uses system trust when the CA is missing", () => {
    assert.deepEqual(postgresTlsConfig(SAFE_ENV), { rejectUnauthorized: true });
  });

  it("rejects malformed CA material", () => {
    assert.throws(() => postgresTlsConfig({ DATABASE_CA_CERT: "not a certificate" }), /database_ca_cert_invalid/);
  });

  it("rejects an empty CA", () => {
    assert.throws(() => postgresTlsConfig({ DATABASE_CA_CERT: "" }), /database_ca_cert_invalid/);
  });

  it("rejects a whitespace-only CA", () => {
    assert.throws(() => postgresTlsConfig({ DATABASE_CA_CERT: " \n\t " }), /database_ca_cert_invalid/);
  });

  it("always sets rejectUnauthorized to true", () => {
    assert.equal(postgresTlsConfig(SAFE_ENV).rejectUnauthorized, true);
    assert.equal(postgresTlsConfig({ DATABASE_CA_CERT: SYNTHETIC_CA }).rejectUnauthorized, true);
  });

  it("rejects sslmode=disable in the URL", () => {
    assert.throws(
      () => postgresPoolConfig(`${DATABASE_URL}?sslmode=disable`, SAFE_ENV),
      /postgres_tls_unsafe_configuration/
    );
  });

  it("rejects sslmode=no-verify in the URL", () => {
    assert.throws(
      () => postgresPoolConfig(`${DATABASE_URL}?sslmode=no-verify`, SAFE_ENV),
      /postgres_tls_unsafe_configuration/
    );
  });

  it("rejects NODE_TLS_REJECT_UNAUTHORIZED=0", () => {
    assert.throws(
      () => postgresPoolConfig(DATABASE_URL, { NODE_TLS_REJECT_UNAUTHORIZED: "0" }),
      /postgres_tls_unsafe_configuration/
    );
  });

  it("rejects production PGSSLMODE=disable", () => {
    assert.throws(
      () => postgresPoolConfig(DATABASE_URL, { NODE_ENV: "production", PGSSLMODE: "disable" }),
      /postgres_tls_unsafe_configuration/
    );
  });

  it("leaves Node hostname verification at its default", () => {
    const ssl = postgresTlsConfig(SAFE_ENV);
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(Object.hasOwn(ssl, "checkServerIdentity"), false);
  });

  it("passes the configured CA to PostgreSQL TLS options", () => {
    const config = postgresPoolConfig(DATABASE_URL, { DATABASE_CA_CERT: SYNTHETIC_CA });
    assert.deepEqual(config.ssl, { rejectUnauthorized: true, ca: SYNTHETIC_CA });
    assert.equal("connectionString" in config, false);
  });

  it("never writes CA contents to logs", () => {
    const output = captureErrorLog(() =>
      logger.error("postgres_ping_failed", {
        reason: sanitizeDbErrorMessage(new Error(SYNTHETIC_CA)),
        tlsVerification: "enforced"
      })
    );
    assert.ok(!output.includes(SYNTHETIC_CA));
    assert.ok(!output.includes("BEGIN CERTIFICATE"));
  });

  it("never writes DATABASE_URL to logs", () => {
    const output = captureErrorLog(() =>
      logger.error("postgres_ping_failed", {
        reason: sanitizeDbErrorMessage(new Error(`failed to connect ${DATABASE_URL}`))
      })
    );
    assert.ok(!output.includes(DATABASE_URL));
  });

  it("never writes the database password to logs", () => {
    const output = captureErrorLog(() =>
      logger.error("postgres_ping_failed", {
        reason: sanitizeDbErrorMessage(new Error(`failed to connect ${DATABASE_URL}`))
      })
    );
    assert.ok(!output.includes("synthetic_password"));
  });

  it("classifies TLS failures", () => {
    assert.equal(
      classifyDbError(Object.assign(new Error("certificate verify failed"), { code: "SELF_SIGNED_CERT_IN_CHAIN" })),
      "tls_failure"
    );
  });

  it("classifies TCP failures", () => {
    assert.equal(
      classifyDbError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" })),
      "connection_refused"
    );
  });

  it("classifies schema failures", () => {
    assert.equal(classifyDbError(Object.assign(new Error("schema does not exist"), { code: "3F000" })), "schema_failure");
    assert.equal(classifyDbError(Object.assign(new Error("relation does not exist"), { code: "42P01" })), "schema_failure");
  });

  it("builds a successful verified pool configuration from discrete fields", () => {
    const config = postgresPoolConfig(`${DATABASE_URL}?sslmode=verify-full`, {
      DATABASE_CA_CERT: SYNTHETIC_CA
    });
    assert.equal(config.host, "db.example.test");
    assert.equal(config.port, 5432);
    assert.equal(config.user, "synthetic_user");
    assert.equal(config.password, "synthetic_password");
    assert.equal(config.database, "kryptos");
    assert.deepEqual(config.ssl, { rejectUnauthorized: true, ca: SYNTHETIC_CA });
    assert.equal("connectionString" in config, false);
  });
});