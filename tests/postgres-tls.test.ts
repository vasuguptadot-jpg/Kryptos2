import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { classifyDbError, sanitizeDbErrorMessage } from "../src/lib/db-diagnostics";
import { logger } from "../src/lib/logger";
import {
  diagnoseCaCertificate,
  diagnoseCaCertificateFormat,
  postgresPoolConfig,
  postgresTlsConfig
} from "../src/lib/postgres-tls";

const SUPABASE_ROOT_2021_CA = readFileSync(join(__dirname, "fixtures", "supabase-root-2021-ca.crt"), "utf8").trim();
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
  it("reports only safe CA format metadata using the connection parser", () => {
    const cases = [
      { name: "undefined CA", value: undefined, classification: "missing", accepted: false },
      { name: "empty CA", value: "", classification: "empty", accepted: false },
      { name: "valid PEM", value: SUPABASE_ROOT_2021_CA, classification: "pem", accepted: true },
      {
        name: "literal newline escapes",
        value: SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\n"),
        classification: "escaped_newlines",
        accepted: true
      },
      {
        name: "CRLF",
        value: SUPABASE_ROOT_2021_CA.replace(/\n/g, "\r\n"),
        classification: "whitespace_normalized",
        accepted: true
      },
      {
        name: "surrounding whitespace",
        value: ` \t\n${SUPABASE_ROOT_2021_CA}\n \t`,
        classification: "whitespace_normalized",
        accepted: true
      },
      {
        name: "surrounding quotes",
        value: `"${SUPABASE_ROOT_2021_CA}"`,
        classification: "quoted",
        accepted: false
      },
      {
        name: "double-escaped newlines",
        value: SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\\\n"),
        classification: "double_escaped_newlines",
        accepted: false
      },
      {
        name: "malformed PEM",
        value: "-----BEGIN CERTIFICATE-----PRIVATE_DIAGNOSTIC_MARKER-----END CERTIFICATE-----",
        classification: "malformed",
        accepted: false
      },
      {
        name: "truncated PEM",
        value: "-----BEGIN CERTIFICATE-----PRIVATE_DIAGNOSTIC_MARKER",
        classification: "malformed",
        accepted: false
      }
    ] as const;
    const allowedKeys = [
      "defined",
      "length",
      "actualNewlines",
      "escapedNewlines",
      "doubleEscapedNewlines",
      "escapedCarriageReturns",
      "hasBeginMarker",
      "hasEndMarker",
      "pemBlockCount",
      "surroundingQuotes",
      "leadingWhitespace",
      "trailingWhitespace",
      "parserAccepted",
      "pemEnvelopeValid",
      "base64Decodable",
      "base64Length",
      "payloadLineCount",
      "payloadLineLengthsPlausible",
      "emptyPayloadLineCount",
      "asciiCharacterCount",
      "nonAsciiCharacterCount",
      "environmentNonAsciiCharacterCount",
      "whitespaceCharacterCount",
      "spaceCount",
      "tabCount",
      "carriageReturnCount",
      "lineFeedCount",
      "plusCount",
      "slashCount",
      "paddingCharacterCount",
      "unexpectedCharacterCount",
      "unexpectedCharacterClasses",
      "alphabetValid",
      "lengthModulo4",
      "paddingAtEnd",
      "paddingStructureValid",
      "paddingBeforeFinalCharacters",
      "possibleTruncation",
      "impossibleBase64Length",
      "unicodeWhitespaceCount",
      "unicodeDashLikeCount",
      "unicodeQuoteCount",
      "bomPresent",
      "controlCharacterCount",
      "zeroWidthCharacterCount",
      "knownGoodControlComparison",
      "derStructureValid",
      "derLength",
      "x509Parsable",
      "nativeX509Accepted",
      "certificateType",
      "validityFieldsParsable",
      "basicConstraintsPresent",
      "basicConstraintsIndicatesCA",
      "appearsToBeCertificate",
      "certificateClassification",
      "classification"
    ].sort();

    for (const testCase of cases) {
      const metadata = diagnoseCaCertificateFormat(testCase.value);
      const serialized = JSON.stringify(metadata);
      assert.deepEqual(Object.keys(metadata).sort(), allowedKeys, testCase.name);
      assert.equal(metadata.classification, testCase.classification, testCase.name);
      assert.equal(metadata.parserAccepted, testCase.accepted, testCase.name);
      assert.equal(
        metadata.parserAccepted,
        testCase.value === undefined
          ? false
          : (() => {
              try {
                postgresTlsConfig({ DATABASE_CA_CERT: testCase.value });
                return true;
              } catch {
                return false;
              }
            })(),
        `${testCase.name} parser behavior`
      );
      assert.ok(!serialized.includes(SUPABASE_ROOT_2021_CA), `${testCase.name} exposed certificate contents`);
      assert.ok(!serialized.includes("PRIVATE_DIAGNOSTIC_MARKER"), `${testCase.name} exposed a secret marker`);
      assert.ok(!/fingerprint|sha.?256|hash|subject|issuer|serial/i.test(serialized), `${testCase.name} exposed forbidden metadata`);
    }

    const missing = diagnoseCaCertificateFormat(undefined);
    assert.equal(missing.defined, false);
    assert.equal(missing.length, null);
    const empty = diagnoseCaCertificateFormat("");
    assert.equal(empty.defined, true);
    assert.equal(empty.length, 0);
    const escaped = diagnoseCaCertificateFormat(SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\n"));
    assert.ok(escaped.escapedNewlines > 0);
    const crlf = diagnoseCaCertificateFormat(SUPABASE_ROOT_2021_CA.replace(/\n/g, "\r\n"));
    assert.ok(crlf.actualNewlines > 0);
    assert.equal(crlf.escapedCarriageReturns, 0);
    const doubleEscaped = diagnoseCaCertificateFormat(SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\\\n"));
    assert.ok(doubleEscaped.doubleEscapedNewlines > 0);
    const quotes = diagnoseCaCertificateFormat(`"${SUPABASE_ROOT_2021_CA}"`);
    assert.equal(quotes.surroundingQuotes, true);
    const whitespace = diagnoseCaCertificateFormat(` ${SUPABASE_ROOT_2021_CA} `);
    assert.equal(whitespace.leadingWhitespace, true);
    assert.equal(whitespace.trailingWhitespace, true);
    const truncated = diagnoseCaCertificateFormat("-----BEGIN CERTIFICATE-----truncated");
    assert.equal(truncated.hasBeginMarker, true);
    assert.equal(truncated.hasEndMarker, false);
  });

  it("separates PEM, Base64, DER, X.509, and CA metadata without exposing certificate data", () => {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const fillerLength = 200 - begin.length - end.length - 5;
    const filler = "A".repeat(fillerLength);
    const productionStyleMalformed = [
      begin,
      filler.slice(0, 36),
      filler.slice(36, 72),
      filler.slice(72, 108),
      filler.slice(108),
      end
    ].join("\n");
    const cases = [
      {
        name: "known-good Supabase root CA",
        value: SUPABASE_ROOT_2021_CA,
        expected: {
          pemEnvelopeValid: true,
          base64Decodable: true,
          derStructureValid: true,
          x509Parsable: true,
          nativeX509Accepted: true,
          certificateType: "x509_certificate",
          validityFieldsParsable: true,
          basicConstraintsPresent: true,
          basicConstraintsIndicatesCA: true,
          appearsToBeCertificate: true,
          certificateClassification: "ca_certificate",
          parserAccepted: true
        }
      },
      {
        name: "malformed PEM",
        value: `${begin}truncated`,
        expected: {
          pemEnvelopeValid: false,
          base64Decodable: false,
          derStructureValid: false,
          x509Parsable: false,
          nativeX509Accepted: false,
          certificateType: "unparsed",
          validityFieldsParsable: false,
          basicConstraintsPresent: false,
          basicConstraintsIndicatesCA: false,
          appearsToBeCertificate: false,
          certificateClassification: "invalid_pem_envelope",
          parserAccepted: false
        }
      },
      {
        name: "valid PEM envelope with invalid Base64",
        value: `${begin}\n%%%not-base64%%%\n${end}`,
        expected: {
          pemEnvelopeValid: true,
          base64Decodable: false,
          derStructureValid: false,
          x509Parsable: false,
          nativeX509Accepted: false,
          certificateType: "unparsed",
          validityFieldsParsable: false,
          basicConstraintsPresent: false,
          basicConstraintsIndicatesCA: false,
          appearsToBeCertificate: false,
          certificateClassification: "invalid_base64",
          parserAccepted: false
        }
      },
      {
        name: "valid Base64 containing non-certificate DER",
        value: `${begin}\nMAA=\n${end}`,
        expected: {
          pemEnvelopeValid: true,
          base64Decodable: true,
          derStructureValid: true,
          x509Parsable: false,
          nativeX509Accepted: false,
          certificateType: "non_x509_der",
          validityFieldsParsable: false,
          basicConstraintsPresent: false,
          basicConstraintsIndicatesCA: false,
          appearsToBeCertificate: false,
          certificateClassification: "not_x509_certificate",
          parserAccepted: false
        }
      },
      {
        name: "production-style 200-character malformed value",
        value: productionStyleMalformed,
        expected: {
          pemEnvelopeValid: true,
          base64Decodable: false,
          derStructureValid: false,
          x509Parsable: false,
          nativeX509Accepted: false,
          certificateType: "unparsed",
          validityFieldsParsable: false,
          basicConstraintsPresent: false,
          basicConstraintsIndicatesCA: false,
          appearsToBeCertificate: false,
          certificateClassification: "invalid_base64",
          parserAccepted: false
        }
      }
    ] as const;

    assert.equal(productionStyleMalformed.length, 200);
    assert.equal(productionStyleMalformed.match(/\n/g)?.length, 5);
    for (const testCase of cases) {
      const metadata = diagnoseCaCertificateFormat(testCase.value);
      const serialized = JSON.stringify(metadata);
      for (const [key, value] of Object.entries(testCase.expected)) {
        assert.equal(metadata[key as keyof typeof metadata], value, `${testCase.name}: ${key}`);
      }
      if (testCase.name === "known-good Supabase root CA") {
        assert.ok((metadata.derLength ?? 0) > 0);
      } else {
        assert.equal(metadata.derLength, testCase.expected.base64Decodable ? 2 : null);
      }
      if (testCase.name === "production-style 200-character malformed value") {
        assert.equal(metadata.length, 200);
        assert.equal(metadata.actualNewlines, 5);
        assert.equal(metadata.pemBlockCount, 1);
        assert.equal(metadata.hasBeginMarker, true);
        assert.equal(metadata.hasEndMarker, true);
      }
      assert.ok(!serialized.includes(testCase.value), `${testCase.name}: certificate content leaked`);
      assert.ok(
        !/-----BEGIN CERTIFICATE-----|subject|issuer|serial|fingerprint|sha.?256|hash|public.?key/i.test(serialized),
        `${testCase.name}: forbidden certificate metadata leaked`
      );
    }
  });

  it("validates the exact strict Base64 path for normalizations and contaminated PEM", () => {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const payload = SUPABASE_ROOT_2021_CA.replace(begin, "").replace(end, "").replace(/\s/g, "");
    const pem = (body: string) => `${begin}\n${body}\n${end}`;
    const cases = [
      { name: "standard PEM", value: SUPABASE_ROOT_2021_CA, valid: true },
      { name: "multiline Base64", value: pem(payload.match(/.{1,64}/g)?.join("\n") ?? ""), valid: true },
      { name: "normal PEM line wrapping", value: pem(payload.match(/.{1,48}/g)?.join("\n") ?? ""), valid: true },
      { name: "known-good Supabase Root 2021 CA", value: SUPABASE_ROOT_2021_CA, valid: true },
      { name: "invalid Base64 symbol", value: pem(`!${payload.slice(1)}`), valid: false },
      { name: "malformed padding", value: pem(`${payload}=`), valid: false },
      { name: "truncated Base64", value: pem(payload.replace(/=$/, "")), valid: false },
      { name: "impossible Base64 length", value: pem("A"), valid: false },
      { name: "Unicode contamination", value: pem(`${payload.slice(0, 8)}\u00a0${payload.slice(8)}`), valid: false },
      { name: "control-character contamination", value: pem(`${payload.slice(0, 8)}\u0001${payload.slice(8)}`), valid: false },
      {
        name: "BOM contamination",
        value: `\uFEFF${SUPABASE_ROOT_2021_CA}`,
        valid: false,
        base64Valid: true
      },
      {
        name: "Unicode dash in envelope",
        value: SUPABASE_ROOT_2021_CA.replace("-----BEGIN", "\u2014----BEGIN"),
        valid: false,
        base64Valid: false
      },
      {
        name: "Unicode quote in envelope",
        value: `“${SUPABASE_ROOT_2021_CA}”`,
        valid: false,
        base64Valid: true
      },
      {
        name: "zero-width contamination",
        value: pem(`${payload.slice(0, 8)}\u200b${payload.slice(8)}`),
        valid: false
      },
      { name: "empty Base64 payload", value: pem(""), valid: false },
      { name: "missing PEM body", value: `${begin}${end}`, valid: false },
      {
        name: "multiple certificate blocks",
        value: `${SUPABASE_ROOT_2021_CA}\n${SUPABASE_ROOT_2021_CA}`,
        valid: false,
        base64Valid: true
      },
      {
        name: "overlong payload line",
        value: pem(payload),
        valid: true,
        base64Valid: true
      },
      {
        name: "empty payload line",
        value: pem(`${payload.slice(0, 64)}\n\n${payload.slice(64)}`),
        valid: false
      },
      {
        name: "padding before final characters",
        value: pem(`${payload.slice(0, 8)}=${payload.slice(8).replace(/=$/, "")}`),
        valid: false
      },
      {
        name: "literal newline normalization",
        value: SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\n"),
        valid: true
      },
      {
        name: "CRLF normalization",
        value: SUPABASE_ROOT_2021_CA.replace(/\n/g, "\r\n"),
        valid: true
      },
      {
        name: "surrounding ASCII whitespace normalization",
        value: ` \t\n${SUPABASE_ROOT_2021_CA}\n \t`,
        valid: true
      }
    ] as const;

    for (const testCase of cases) {
      const metadata = diagnoseCaCertificateFormat(testCase.value);
      assert.equal(metadata.parserAccepted, testCase.valid, testCase.name);
      assert.equal(metadata.base64Decodable, "base64Valid" in testCase ? testCase.base64Valid : testCase.valid, testCase.name);
      assert.ok(!JSON.stringify(metadata).includes(testCase.value), `${testCase.name} leaked input`);
      if (testCase.name === "invalid Base64 symbol") {
        assert.ok(metadata.unexpectedCharacterCount > 0);
        assert.equal(metadata.alphabetValid, false);
        assert.equal(metadata.knownGoodControlComparison.sameCharacterClassDistribution, false);
      }
      if (testCase.name === "Unicode contamination") {
        assert.ok(metadata.nonAsciiCharacterCount > 0);
        assert.ok(metadata.unicodeWhitespaceCount > 0);
        assert.ok(metadata.unexpectedCharacterClasses.includes("non_ascii"));
      }
      if (testCase.name === "control-character contamination") {
        assert.equal(metadata.controlCharacterCount, 1);
      }
      if (testCase.name === "BOM contamination") {
        assert.equal(metadata.bomPresent, true);
        assert.ok(metadata.environmentNonAsciiCharacterCount > 0);
      }
      if (testCase.name === "Unicode dash in envelope") {
        assert.ok(metadata.unicodeDashLikeCount > 0);
      }
      if (testCase.name === "Unicode quote in envelope") {
        assert.ok(metadata.unicodeQuoteCount > 0);
      }
      if (testCase.name === "zero-width contamination") {
        assert.equal(metadata.zeroWidthCharacterCount, 1);
      }
      if (testCase.name === "impossible Base64 length") {
        assert.equal(metadata.lengthModulo4, 1);
        assert.equal(metadata.impossibleBase64Length, true);
      }
      if (testCase.name === "truncated Base64") {
        assert.equal(metadata.possibleTruncation, true);
        assert.equal(metadata.paddingStructureValid, false);
      }
      if (testCase.name === "empty Base64 payload") {
        assert.equal(metadata.base64Length, 0);
      }
      if (testCase.name === "overlong payload line") {
        assert.equal(metadata.payloadLineLengthsPlausible, false);
      }
      if (testCase.name === "empty payload line") {
        assert.equal(metadata.emptyPayloadLineCount, 1);
      }
      if (testCase.name === "padding before final characters") {
        assert.equal(metadata.paddingBeforeFinalCharacters, true);
        assert.equal(metadata.paddingAtEnd, false);
      }
      if (testCase.name === "multiple certificate blocks") {
        assert.equal(metadata.pemBlockCount, 2);
        assert.equal(metadata.pemEnvelopeValid, false);
      }
    }

    assert.deepEqual(diagnoseCaCertificateFormat(SUPABASE_ROOT_2021_CA).knownGoodControlComparison, {
      samePemBlockCount: true,
      sameBase64Length: true,
      samePayloadLineCount: true,
      sameCharacterClassDistribution: true,
      samePaddingStructure: true
    });
  });

  it("does not treat Node's permissive Base64 decoding as validation", () => {
    assert.equal(Buffer.from("AA=A", "base64").length, 1);
    assert.equal(Buffer.from("A", "base64").length, 0);
    assert.equal(Buffer.from("%%%", "base64").length, 0);

    for (const malformedPayload of ["AA=A", "A", "%%%"]) {
      const malformed = `-----BEGIN CERTIFICATE-----\n${malformedPayload}\n-----END CERTIFICATE-----`;
      assert.equal(diagnoseCaCertificateFormat(malformed).base64Decodable, false);
      assert.throws(() => postgresTlsConfig({ DATABASE_CA_CERT: malformed }), /database_ca_cert_invalid/);
    }
  });

  it("accepts a valid synthetic CA", () => {
    assert.deepEqual(postgresTlsConfig({ DATABASE_CA_CERT: SYNTHETIC_CA }), {
      rejectUnauthorized: true,
      ca: SYNTHETIC_CA
    });
  });

  it("uses system trust when the CA is missing", () => {
    assert.deepEqual(postgresTlsConfig(SAFE_ENV), { rejectUnauthorized: true });
    assert.deepEqual(diagnoseCaCertificate(undefined), { status: "missing" });
  });

  it("parses the exact Supabase Root 2021 CA PEM", () => {
    const certificate = new X509Certificate(SUPABASE_ROOT_2021_CA);
    assert.equal(certificate.ca, true);
    assert.deepEqual(diagnoseCaCertificate(SUPABASE_ROOT_2021_CA), {
      status: "valid",
      representation: "pem"
    });
    assert.deepEqual(postgresTlsConfig({ DATABASE_CA_CERT: SUPABASE_ROOT_2021_CA }), {
      rejectUnauthorized: true,
      ca: SUPABASE_ROOT_2021_CA
    });
  });

  it("normalizes only literal escaped newline sequences in the CA environment value", () => {
    const escapedCa = SUPABASE_ROOT_2021_CA.replace(/\n/g, "\\n");
    assert.deepEqual(diagnoseCaCertificate(escapedCa), {
      status: "valid",
      representation: "escaped_newlines"
    });
    assert.deepEqual(postgresTlsConfig({ DATABASE_CA_CERT: escapedCa }), {
      rejectUnauthorized: true,
      ca: SUPABASE_ROOT_2021_CA
    });
    const previous = {
      ca: process.env.DATABASE_CA_CERT,
      nodeTls: process.env.NODE_TLS_REJECT_UNAUTHORIZED,
      sslMode: process.env.PGSSLMODE
    };
    process.env.DATABASE_CA_CERT = escapedCa;
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    delete process.env.PGSSLMODE;
    try {
      assert.deepEqual(postgresTlsConfig(), {
        rejectUnauthorized: true,
        ca: SUPABASE_ROOT_2021_CA
      });
    } finally {
      if (previous.ca === undefined) delete process.env.DATABASE_CA_CERT;
      else process.env.DATABASE_CA_CERT = previous.ca;
      if (previous.nodeTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous.nodeTls;
      if (previous.sslMode === undefined) delete process.env.PGSSLMODE;
      else process.env.PGSSLMODE = previous.sslMode;
    }
  });

  it("accepts whitespace-normalized PEM while identifying that input format", () => {
    const normalizedCa = ` \t\n${SUPABASE_ROOT_2021_CA}\n \t`;
    assert.deepEqual(diagnoseCaCertificate(normalizedCa), {
      status: "valid",
      representation: "whitespace_normalized"
    });
    assert.deepEqual(postgresTlsConfig({ DATABASE_CA_CERT: normalizedCa }), {
      rejectUnauthorized: true,
      ca: SUPABASE_ROOT_2021_CA
    });
  });

  it("diagnoses malformed CA material without returning its contents", () => {
    const malformed = "not a certificate";
    assert.deepEqual(diagnoseCaCertificate(malformed), {
      status: "malformed",
      representation: "pem"
    });
    assert.throws(() => postgresTlsConfig({ DATABASE_CA_CERT: malformed }), /database_ca_cert_invalid/);
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

  it("keeps TLS verification enabled with the Supabase root CA", () => {
    const ssl = postgresTlsConfig({ DATABASE_CA_CERT: SUPABASE_ROOT_2021_CA });
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

  it("never writes the Supabase CA PEM to logs", () => {
    const original = process.env.DATABASE_CA_CERT;
    process.env.DATABASE_CA_CERT = SUPABASE_ROOT_2021_CA;
    try {
      const output = captureErrorLog(() =>
        logger.error("postgres_ping_failed", {
          reason: sanitizeDbErrorMessage(new Error(SUPABASE_ROOT_2021_CA)),
          tlsVerification: "enforced"
        })
      );
      assert.ok(!output.includes(SUPABASE_ROOT_2021_CA));
      assert.ok(!output.includes("BEGIN CERTIFICATE"));
      assert.ok(!output.includes("80:70:25:AD"));
    } finally {
      if (original === undefined) delete process.env.DATABASE_CA_CERT;
      else process.env.DATABASE_CA_CERT = original;
    }
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