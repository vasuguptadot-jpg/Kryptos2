import { X509Certificate } from "node:crypto";
import type { PoolConfig } from "pg";
import { noteResolvedSecret } from "./secrets";

export interface PostgresTlsConfig {
  rejectUnauthorized: true;
  ca?: string;
}

const CERTIFICATE_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const KNOWN_GOOD_CONTROL_PROFILE = {
  pemBlockCount: 1,
  base64Length: 1292,
  payloadLineCount: 21,
  asciiCharacterCount: 1312,
  nonAsciiCharacterCount: 0,
  whitespaceCharacterCount: 20,
  spaceCount: 0,
  tabCount: 0,
  carriageReturnCount: 0,
  lineFeedCount: 20,
  plusCount: 11,
  slashCount: 14,
  paddingCharacterCount: 1,
  unexpectedCharacterCount: 0,
  lengthModulo4: 0,
  paddingAtEnd: true,
  paddingStructureValid: true
} as const;
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
  base64Length: number | null;
  payloadLineCount: number;
  payloadLineLengthsPlausible: boolean;
  emptyPayloadLineCount: number;
  asciiCharacterCount: number;
  nonAsciiCharacterCount: number;
  environmentNonAsciiCharacterCount: number;
  whitespaceCharacterCount: number;
  spaceCount: number;
  tabCount: number;
  carriageReturnCount: number;
  lineFeedCount: number;
  plusCount: number;
  slashCount: number;
  paddingCharacterCount: number;
  unexpectedCharacterCount: number;
  unexpectedCharacterClasses: Array<"non_ascii" | "whitespace" | "invalid_base64_symbol">;
  alphabetValid: boolean;
  lengthModulo4: number | null;
  paddingAtEnd: boolean;
  paddingStructureValid: boolean;
  paddingBeforeFinalCharacters: boolean;
  possibleTruncation: boolean;
  impossibleBase64Length: boolean;
  unicodeWhitespaceCount: number;
  unicodeDashLikeCount: number;
  unicodeQuoteCount: number;
  bomPresent: boolean;
  controlCharacterCount: number;
  zeroWidthCharacterCount: number;
  knownGoodControlComparison: {
    samePemBlockCount: boolean;
    sameBase64Length: boolean;
    samePayloadLineCount: boolean;
    sameCharacterClassDistribution: boolean;
    samePaddingStructure: boolean;
  };
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
  const ca = (escapedNewlines ? value.replace(/(?:\\r)?\\n/g, "\n") : value).replace(
    /^[ \t\r\n]+|[ \t\r\n]+$/g,
    ""
  );
  const hasWhitespaceNormalization =
    /^[ \t\r\n]/.test(value) ||
    /[ \t\r\n]$/.test(value) ||
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
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  if (blocks.length !== 1 || remainder.length > 0) return false;

  for (const block of blocks) {
    const der = decodePemCertificate(block);
    if (!der || !parseX509Certificate(der)?.ca) return false;
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

function extractPemBody(block: string): string | null {
  const match = /^-----BEGIN CERTIFICATE-----\r?\n?([\s\S]*?)\r?\n?-----END CERTIFICATE-----$/.exec(block);
  return match?.[1] ?? null;
}

function decodePemCertificate(block: string): Buffer | null {
  const body = extractPemBody(block);
  if (body === null) return null;
  const normalizedBody = body.replace(/^(?:\r\n|\n)|(?:\r\n|\n)$/g, "");
  const lines = normalizedBody.split(/\r\n|\n/);
  if (lines.some((line) => line.length === 0)) return null;
  const base64 = lines.join("");
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

function base64PayloadDiagnostics(bodies: string[], value: string, pemBlockCount: number): Pick<
  CaCertificateFormatDiagnostic,
  | "base64Length"
  | "payloadLineCount"
  | "payloadLineLengthsPlausible"
  | "emptyPayloadLineCount"
  | "asciiCharacterCount"
  | "nonAsciiCharacterCount"
  | "environmentNonAsciiCharacterCount"
  | "whitespaceCharacterCount"
  | "spaceCount"
  | "tabCount"
  | "carriageReturnCount"
  | "lineFeedCount"
  | "plusCount"
  | "slashCount"
  | "paddingCharacterCount"
  | "unexpectedCharacterCount"
  | "unexpectedCharacterClasses"
  | "alphabetValid"
  | "lengthModulo4"
  | "paddingAtEnd"
  | "paddingStructureValid"
  | "paddingBeforeFinalCharacters"
  | "possibleTruncation"
  | "impossibleBase64Length"
  | "unicodeWhitespaceCount"
  | "unicodeDashLikeCount"
  | "unicodeQuoteCount"
  | "bomPresent"
  | "controlCharacterCount"
  | "zeroWidthCharacterCount"
  | "knownGoodControlComparison"
> {
  const body = bodies.join("\n");
  const base64 = body.replace(/\r\n|\n/g, "");
  const characters = Array.from(body);
  const environmentCharacters = Array.from(value);
  const lines = bodies.flatMap((pemBody) => {
    const trimmedBody = pemBody.replace(/^(?:\r\n|\n)|(?:\r\n|\n)$/g, "");
    return trimmedBody ? trimmedBody.split(/\r\n|\n/) : [];
  });
  const paddingCharacterCount = countMatches(base64, /=/g);
  const lengthModulo4 = base64.length % 4;
  const alphabetValid = base64.length > 0 && /^[A-Za-z0-9+/=]+$/.test(base64);
  const paddingAtEnd = paddingCharacterCount === 0 || /={1,2}$/.test(base64);
  const paddingBeforeFinalCharacters = /=.*[^=]/.test(base64);
  const paddingStructureValid =
    alphabetValid &&
    base64.length % 4 === 0 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64);
  const unexpectedCharacterClasses = new Set<"non_ascii" | "whitespace" | "invalid_base64_symbol">();
  let unexpectedCharacterCount = 0;
  const environmentControlCharacterCount = environmentCharacters.filter(
    (character) => /\p{Cc}/u.test(character) && character !== "\r" && character !== "\n"
  ).length;
  const environmentNonAsciiCharacterCount = environmentCharacters.filter(
    (character) => character.codePointAt(0)! > 0x7f
  ).length;
  const environmentWhitespaceCount =
    countMatches(value, /\p{White_Space}/gu) - countMatches(value, /[\t\n\v\f\r ]/g);
  const environmentDashLikeCount = countMatches(value, /[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/gu);
  const environmentQuoteCount = countMatches(value, /[\u2018-\u201F\u00AB\u00BB\u2039\u203A]/gu);
  const environmentZeroWidthCount = countMatches(value, /[\u200B-\u200D\u2060]/gu);
  const lineFeedCount = countMatches(body, /\n/g);

  for (const character of Array.from(base64)) {
    if (/[A-Za-z0-9+/=]/.test(character)) continue;
    unexpectedCharacterCount += 1;
    if (character.codePointAt(0)! > 0x7f) unexpectedCharacterClasses.add("non_ascii");
    if (/\s/u.test(character)) unexpectedCharacterClasses.add("whitespace");
    else unexpectedCharacterClasses.add("invalid_base64_symbol");
  }

  const characterClassMatchesControl =
    characters.filter((character) => character.codePointAt(0)! <= 0x7f).length ===
      KNOWN_GOOD_CONTROL_PROFILE.asciiCharacterCount &&
    characters.filter((character) => character.codePointAt(0)! > 0x7f).length ===
      KNOWN_GOOD_CONTROL_PROFILE.nonAsciiCharacterCount &&
    countMatches(body, /\s/gu) === KNOWN_GOOD_CONTROL_PROFILE.whitespaceCharacterCount &&
    countMatches(body, / /g) === KNOWN_GOOD_CONTROL_PROFILE.spaceCount &&
    countMatches(body, /\t/g) === KNOWN_GOOD_CONTROL_PROFILE.tabCount &&
    countMatches(body, /\r/g) === KNOWN_GOOD_CONTROL_PROFILE.carriageReturnCount &&
    lineFeedCount === KNOWN_GOOD_CONTROL_PROFILE.lineFeedCount &&
    countMatches(base64, /\+/g) === KNOWN_GOOD_CONTROL_PROFILE.plusCount &&
    countMatches(base64, /\//g) === KNOWN_GOOD_CONTROL_PROFILE.slashCount &&
    paddingCharacterCount === KNOWN_GOOD_CONTROL_PROFILE.paddingCharacterCount &&
    unexpectedCharacterCount === KNOWN_GOOD_CONTROL_PROFILE.unexpectedCharacterCount;

  return {
    base64Length: bodies.length > 0 ? base64.length : null,
    payloadLineCount: lines.length,
    payloadLineLengthsPlausible: lines.length > 0 && lines.every((line) => line.length > 0 && line.length <= 64),
    emptyPayloadLineCount: bodies.reduce((count, pemBody) => {
      const trimmedBody = pemBody.replace(/^(?:\r\n|\n)|(?:\r\n|\n)$/g, "");
      return count + (trimmedBody ? trimmedBody.split(/\r\n|\n/).filter((line) => line.length === 0).length : 0);
    }, 0),
    asciiCharacterCount: characters.filter((character) => character.codePointAt(0)! <= 0x7f).length,
    nonAsciiCharacterCount: characters.filter((character) => character.codePointAt(0)! > 0x7f).length,
    environmentNonAsciiCharacterCount,
    whitespaceCharacterCount: countMatches(body, /\s/gu),
    spaceCount: countMatches(body, / /g),
    tabCount: countMatches(body, /\t/g),
    carriageReturnCount: countMatches(body, /\r/g),
    lineFeedCount,
    plusCount: countMatches(base64, /\+/g),
    slashCount: countMatches(base64, /\//g),
    paddingCharacterCount,
    unexpectedCharacterCount,
    unexpectedCharacterClasses: [...unexpectedCharacterClasses],
    alphabetValid,
    lengthModulo4: bodies.length > 0 ? lengthModulo4 : null,
    paddingAtEnd,
    paddingStructureValid,
    paddingBeforeFinalCharacters,
    possibleTruncation: alphabetValid && lengthModulo4 !== 0,
    impossibleBase64Length: bodies.length > 0 && lengthModulo4 === 1,
    unicodeWhitespaceCount: environmentWhitespaceCount,
    unicodeDashLikeCount: environmentDashLikeCount,
    unicodeQuoteCount: environmentQuoteCount,
    bomPresent: value.includes("\uFEFF"),
    controlCharacterCount: environmentControlCharacterCount,
    zeroWidthCharacterCount: environmentZeroWidthCount,
    knownGoodControlComparison: {
      samePemBlockCount: pemBlockCount === KNOWN_GOOD_CONTROL_PROFILE.pemBlockCount,
      sameBase64Length: base64.length === KNOWN_GOOD_CONTROL_PROFILE.base64Length,
      samePayloadLineCount: lines.length === KNOWN_GOOD_CONTROL_PROFILE.payloadLineCount,
      sameCharacterClassDistribution: characterClassMatchesControl,
      samePaddingStructure:
        lengthModulo4 === KNOWN_GOOD_CONTROL_PROFILE.lengthModulo4 &&
        paddingAtEnd === KNOWN_GOOD_CONTROL_PROFILE.paddingAtEnd &&
        paddingStructureValid === KNOWN_GOOD_CONTROL_PROFILE.paddingStructureValid
    }
  };
}

export function diagnoseCaCertificateFormat(value: string | undefined): CaCertificateFormatDiagnostic {
  const defined = value !== undefined;
  const raw = value ?? "";
  const normalized = defined ? normalizeCaCertificate(raw) : null;
  const ca = normalized?.ca ?? "";
  const blocks = ca.match(CERTIFICATE_BLOCK_RE) ?? [];
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  const pemEnvelopeValid =
    blocks.length === 1 &&
    remainder.length === 0 &&
    blocks.every((block) => /^-----BEGIN CERTIFICATE-----\r?\n?[\s\S]*?\r?\n?-----END CERTIFICATE-----$/.test(block));
  const bodies = blocks.map(extractPemBody).filter((body): body is string => body !== null);
  const decoded = blocks.map(decodePemCertificate);
  const base64Decodable = decoded.length > 0 && decoded.every((der) => der !== null);
  const payloadDiagnostics = base64PayloadDiagnostics(bodies, raw, blocks.length);
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
    ...payloadDiagnostics,
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