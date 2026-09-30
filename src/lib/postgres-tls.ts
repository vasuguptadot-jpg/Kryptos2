import { X509Certificate } from "node:crypto";
import type { PoolConfig } from "pg";
import { noteResolvedSecret } from "./secrets";

export interface PostgresTlsConfig {
  rejectUnauthorized: true;
  ca?: string;
}

const CERTIFICATE_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const UNSAFE_SSL_MODES = new Set(["disable", "no-verify", "allow", "prefer"]);
const ACCEPTED_SSL_MODES = new Set(["require", "verify-ca", "verify-full"]);
type Environment = Readonly<Record<string, string | undefined>>;
type CaCertificateRepresentation = "pem" | "escaped_newlines" | "whitespace_normalized";

export interface CaCertificateFormatDiagnostic {
  defined: boolean;
  length: number | null;
  actualNewlines: number;
  escapedNewlines: number;
  doubleEscapedNewlines: number;
  escapedCarriageReturns: number;
  hasBeginMarker: boolean;
  hasEndMarker: boolean;
  pemBlockCount: number;
  surroundingQuotes: boolean;
  leadingWhitespace: boolean;
  trailingWhitespace: boolean;
  parserAccepted: boolean;
  pemEnvelopeValid: boolean;
  base64Decodable: boolean;
  derStructureValid: boolean;
  derLength: number | null;
  x509Parsable: boolean;
  nativeX509Accepted: boolean;
  certificateType: "x509_certificate" | "non_x509_der" | "unparsed";
  validityFieldsParsable: boolean;
  basicConstraintsPresent: boolean;
  basicConstraintsIndicatesCA: boolean;
  appearsToBeCertificate: boolean;
  certificateClassification:
    | "missing"
    | "invalid_pem_envelope"
    | "invalid_base64"
    | "invalid_der"
    | "not_x509_certificate"
    | "not_ca_certificate"
    | "ca_certificate";
  classification:
    | "missing"
    | "empty"
    | "pem"
    | "escaped_newlines"
    | "whitespace_normalized"
    | "double_escaped_newlines"
    | "quoted"
    | "malformed";
}

export type CaCertificateDiagnostic =
  | { status: "missing" }
  | { status: "valid"; representation: CaCertificateRepresentation }
  | { status: "malformed"; representation: CaCertificateRepresentation };

function assertSafeTlsEnvironment(env: Environment): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("postgres_tls_unsafe_configuration");
  }

  const sslMode = env.PGSSLMODE?.trim().toLowerCase();
  if (sslMode && (!ACCEPTED_SSL_MODES.has(sslMode) || UNSAFE_SSL_MODES.has(sslMode))) {
    throw new Error("postgres_tls_unsafe_configuration");
  }
}

function normalizeCaCertificate(value: string): {
  ca: string;
  representation: CaCertificateRepresentation;
} {
  const escapedNewlines = /(?:\\r)?\\n/.test(value);
  const ca = (escapedNewlines ? value.replace(/(?:\\r)?\\n/g, "\n") : value).trim();
  const hasWhitespaceNormalization =
    /^[ \t]/.test(value) ||
    /[ \t]$/.test(value) ||
    /\r\n/.test(value) ||
    /\n[ \t]+/.test(value);
  return {
    ca,
    representation: escapedNewlines
      ? "escaped_newlines"
      : hasWhitespaceNormalization
        ? "whitespace_normalized"
        : "pem"
  };
}

function parseX509Certificate(value: string | Buffer): X509Certificate | null {
  try {
    return new X509Certificate(value);
  } catch {
    return null;
  }
}

function parseCaCertificate(ca: string): boolean {
  if (!ca) return false;
  const blocks = ca.match(CERTIFICATE_BLOCK_RE) ?? [];
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").trim();
  if (blocks.length === 0 || remainder.length > 0) return false;

  for (const block of blocks) {
    if (!parseX509Certificate(block)?.ca) return false;
  }
  return true;
}

export function diagnoseCaCertificate(value: string | undefined): CaCertificateDiagnostic {
  if (value === undefined) return { status: "missing" };
  const { ca, representation } = normalizeCaCertificate(value);
  return {
    status: parseCaCertificate(ca) ? "valid" : "malformed",
    representation
  };
}

function countMatches(value: string, pattern: RegExp): number {
  return value.match(pattern)?.length ?? 0;
}

interface DerNode {
  tagClass: number;
  tagNumber: number;
  contentStart: number;
  contentEnd: number;
  children: DerNode[];
}

function parseDerNode(
  bytes: Buffer,
  offset: number,
  limit: number,
  depth = 0
): { node: DerNode; next: number } | null {
  if (offset >= limit || depth > 64) return null;
  let cursor = offset;
  const firstTag = bytes[cursor++];
  const tagClass = firstTag >> 6;
  const constructed = (firstTag & 0x20) !== 0;
  let tagNumber = firstTag & 0x1f;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let tagByte: number;
    do {
      if (cursor >= limit) return null;
      tagByte = bytes[cursor++];
      if (tagNumber === 0 && (tagByte & 0x7f) === 0) return null;
      tagNumber = tagNumber * 128 + (tagByte & 0x7f);
      if (!Number.isSafeInteger(tagNumber)) return null;
    } while ((tagByte & 0x80) !== 0);
  }

  if (cursor >= limit) return null;
  const firstLength = bytes[cursor++];
  let contentLength: number;
  if (firstLength < 0x80) {
    contentLength = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 6 || cursor + lengthBytes > limit || bytes[cursor] === 0) return null;
    contentLength = 0;
    for (let index = 0; index < lengthBytes; index += 1) {
      contentLength = contentLength * 256 + bytes[cursor++];
      if (!Number.isSafeInteger(contentLength)) return null;
    }
    if (contentLength < 0x80) return null;
  }

  const contentStart = cursor;
  const contentEnd = contentStart + contentLength;
  if (contentEnd > limit) return null;

  const children: DerNode[] = [];
  if (constructed) {
    while (cursor < contentEnd) {
      const child = parseDerNode(bytes, cursor, contentEnd, depth + 1);
      if (!child) return null;
      children.push(child.node);
      cursor = child.next;
    }
    if (cursor !== contentEnd) return null;
  }

  return { node: { tagClass, tagNumber, contentStart, contentEnd, children }, next: contentEnd };
}

function parseDer(bytes: Buffer): DerNode | null {
  const parsed = parseDerNode(bytes, 0, bytes.length);
  return parsed?.next === bytes.length ? parsed.node : null;
}

function hasBasicConstraintsExtension(certificateNode: DerNode | null, bytes: Buffer): boolean {
  const tbsCertificate = certificateNode?.children[0];
  const extensions = tbsCertificate?.children.find((node) => node.tagClass === 2 && node.tagNumber === 3);
  const extensionSequence = extensions?.children[0];
  if (!extensionSequence) return false;

  return extensionSequence.children.some((extension) => {
    const oid = extension.children[0];
    return (
      oid?.tagClass === 0 &&
      oid.tagNumber === 6 &&
      bytes.subarray(oid.contentStart, oid.contentEnd).equals(Buffer.from([0x55, 0x1d, 0x13]))
    );
  });
}

function decodePemCertificate(block: string): Buffer | null {
  const match = /^-----BEGIN CERTIFICATE-----\r?\n?([\s\S]*?)\r?\n?-----END CERTIFICATE-----$/.exec(block);
  if (!match) return null;
  const base64 = match[1].replace(/\s/g, "");
  if (
    !base64 ||
    base64.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)
  ) {
    return null;
  }

  const der = Buffer.from(base64, "base64");
  return der.toString("base64") === base64 ? der : null;
}

export function diagnoseCaCertificateFormat(value: string | undefined): CaCertificateFormatDiagnostic {
  const defined = value !== undefined;
  const raw = value ?? "";
  const normalized = defined ? normalizeCaCertificate(raw) : null;
  const ca = normalized?.ca ?? "";
  const blocks = ca.match(CERTIFICATE_BLOCK_RE) ?? [];
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").trim();
  const pemEnvelopeValid =
    blocks.length > 0 &&
    remainder.length === 0 &&
    blocks.every((block) => /^-----BEGIN CERTIFICATE-----\r?\n?[\s\S]*?\r?\n?-----END CERTIFICATE-----$/.test(block));
  const decoded = pemEnvelopeValid ? blocks.map(decodePemCertificate) : [];
  const base64Decodable = decoded.length > 0 && decoded.every((der) => der !== null);
  const derBuffers = base64Decodable ? (decoded as Buffer[]) : [];
  const derNodes = derBuffers.map(parseDer);
  const derStructureValid = derNodes.length > 0 && derNodes.every((node) => node !== null);
  const certificates = derBuffers.map(parseX509Certificate);
  const x509Parsable = certificates.length > 0 && certificates.every((certificate) => certificate !== null);
  const parserAccepted = normalized ? parseCaCertificate(normalized.ca) : false;
  const parsedCertificates = certificates.filter((certificate): certificate is X509Certificate => certificate !== null);
  const validityFieldsParsable =
    parsedCertificates.length > 0 &&
    parsedCertificates.every(
      (certificate) =>
        Number.isFinite(Date.parse(certificate.validFrom)) && Number.isFinite(Date.parse(certificate.validTo))
    );
  const basicConstraintsPresent =
    x509Parsable && derNodes.every((node, index) => hasBasicConstraintsExtension(node, derBuffers[index]));
  const basicConstraintsIndicatesCA = x509Parsable && parsedCertificates.every((certificate) => certificate.ca);
  const certificateType: CaCertificateFormatDiagnostic["certificateType"] = x509Parsable
    ? "x509_certificate"
    : derStructureValid
      ? "non_x509_der"
      : "unparsed";
  const certificateClassification: CaCertificateFormatDiagnostic["certificateClassification"] = !defined
    ? "missing"
    : !pemEnvelopeValid
      ? "invalid_pem_envelope"
      : !base64Decodable
        ? "invalid_base64"
        : !derStructureValid
          ? "invalid_der"
          : !x509Parsable
            ? "not_x509_certificate"
            : !basicConstraintsIndicatesCA
              ? "not_ca_certificate"
              : "ca_certificate";
  const doubleEscapedNewlines = countMatches(raw, /\\\\n/g);
  const escapedCarriageReturns = countMatches(raw, /\\r\\n/g);
  const escapedNewlines = countMatches(raw, /(?<!\\)(?<!\\r)\\n/g);
  const surroundingQuotes =
    raw.length >= 2 &&
    ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'")));
  const classification: CaCertificateFormatDiagnostic["classification"] = !defined
    ? "missing"
    : raw.length === 0
      ? "empty"
      : surroundingQuotes
        ? "quoted"
        : doubleEscapedNewlines > 0
          ? "double_escaped_newlines"
          : parserAccepted && normalized
            ? normalized.representation
            : "malformed";

  return {
    defined,
    length: defined ? raw.length : null,
    actualNewlines: countMatches(raw, /\n/g),
    escapedNewlines,
    doubleEscapedNewlines,
    escapedCarriageReturns,
    hasBeginMarker: raw.includes("-----BEGIN CERTIFICATE-----"),
    hasEndMarker: raw.includes("-----END CERTIFICATE-----"),
    pemBlockCount: normalized ? normalized.ca.match(CERTIFICATE_BLOCK_RE)?.length ?? 0 : 0,
    surroundingQuotes,
    leadingWhitespace: /^\s/.test(raw),
    trailingWhitespace: /\s$/.test(raw),
    parserAccepted,
    pemEnvelopeValid,
    base64Decodable,
    derStructureValid,
    derLength: base64Decodable ? derBuffers.reduce((length, der) => length + der.length, 0) : null,
    x509Parsable,
    nativeX509Accepted: x509Parsable,
    certificateType,
    validityFieldsParsable,
    basicConstraintsPresent,
    basicConstraintsIndicatesCA,
    appearsToBeCertificate: x509Parsable,
    certificateClassification,
    classification
  };
}

function validateCaCertificate(value: string): string {
  const { ca } = normalizeCaCertificate(value);
  if (!parseCaCertificate(ca)) throw new Error("database_ca_cert_invalid");

  noteResolvedSecret("DATABASE_CA_CERT", ca);
  return ca;
}

export function postgresTlsConfig(env: Environment = process.env): PostgresTlsConfig {
  assertSafeTlsEnvironment(env);
  const caValue = env.DATABASE_CA_CERT;
  if (caValue === undefined) return { rejectUnauthorized: true };
  return { rejectUnauthorized: true, ca: validateCaCertificate(caValue) };
}

function decodeUrlPart(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error("database_url_invalid");
  }
}

export function postgresPoolConfig(
  connectionString: string,
  env: Environment = process.env
): PoolConfig {
  const url = (() => {
    try {
      return new URL(connectionString);
    } catch {
      throw new Error("database_url_invalid");
    }
  })();

  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new Error("database_url_invalid");
  }

  for (const [key, value] of url.searchParams) {
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "sslmode") {
      const mode = value.toLowerCase();
      if (UNSAFE_SSL_MODES.has(mode) || !ACCEPTED_SSL_MODES.has(mode)) {
        throw new Error("postgres_tls_unsafe_configuration");
      }
    } else if (normalizedKey.startsWith("ssl")) {
      throw new Error("postgres_tls_unsafe_configuration");
    }
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname || !url.username) throw new Error("database_url_invalid");

  return {
    host: hostname,
    port: url.port ? Number(url.port) : undefined,
    user: decodeUrlPart(url.username),
    password: decodeUrlPart(url.password),
    database: decodeUrlPart(url.pathname.replace(/^\//, "")),
    max: 3,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
    ssl: postgresTlsConfig(env)
  };
}