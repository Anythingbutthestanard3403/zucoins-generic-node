import { Buffer } from "node:buffer";

declare const UUID_BRAND: unique symbol;
declare const WALLET_PUBLIC_KEY_BRAND: unique symbol;
declare const ED25519_SIGNATURE_BRAND: unique symbol;
declare const PREVIOUS_STATE_SIGNATURE_BRAND: unique symbol;
declare const UNIX_TIME_SECS_V2_BRAND: unique symbol;
declare const EXPIRY_UNIX_TIME_SECS_BRAND: unique symbol;
declare const SHA256_HEX_BRAND: unique symbol;
declare const OPAQUE_REFERENCE_BRAND: unique symbol;

/** Lowercase canonical RFC 4122 textual spelling. Semantic version/nil policy belongs elsewhere. */
export type Uuid = string & { readonly [UUID_BRAND]: "Uuid" };

/** Canonical padded base64url encoding of exactly 32 public-key bytes. */
export type WalletPublicKey = string & {
  readonly [WALLET_PUBLIC_KEY_BRAND]: "WalletPublicKey";
};

/** Canonical padded base64url encoding of exactly 64 Ed25519 signature bytes. */
export type Ed25519Signature = string & {
  readonly [ED25519_SIGNATURE_BRAND]: "Ed25519Signature";
};

/** A settled predecessor signature, or the exact empty genesis sentinel. */
export type PreviousStateSignature = string & {
  readonly [PREVIOUS_STATE_SIGNATURE_BRAND]: "PreviousStateSignature";
};

/** Wallet-compatible non-negative decimal seconds; it is never converted to a JS number. */
export type UnixTimeSecsV2 = string & {
  readonly [UNIX_TIME_SECS_V2_BRAND]: "UnixTimeSecsV2";
};

/** Non-negative minimal base-10 integer seconds. Request-specific bounds are checked separately. */
export type ExpiryUnixTimeSecs = string & {
  readonly [EXPIRY_UNIX_TIME_SECS_BRAND]: "ExpiryUnixTimeSecs";
};

export type Sha256Hex = string & { readonly [SHA256_HEX_BRAND]: "Sha256Hex" };
export type CanonicalVersion = 1;

/** Exact application reference text. Parsing never trims or Unicode-normalizes it. */
export type OpaqueReference = string & {
  readonly [OPAQUE_REFERENCE_BRAND]: "OpaqueReference";
};

export type ScalarKind =
  | "Uuid"
  | "WalletPublicKey"
  | "Ed25519Signature"
  | "PreviousStateSignature"
  | "UnixTimeSecsV2"
  | "ExpiryUnixTimeSecs"
  | "Sha256Hex"
  | "CanonicalVersion"
  | "OpaqueReference"
  | "ZkzBalance"
  | "PositiveZkzAmount"
  | "ComputedZkz";

export type ScalarFailureReason =
  | "wrong_type"
  | "invalid_format"
  | "invalid_length"
  | "non_canonical_encoding"
  | "non_canonical"
  | "out_of_range"
  | "not_positive"
  | "wrong_literal"
  | "invalid_utf16"
  | "invalid_limits"
  | "limit_exceeded";

/**
 * Typed trust-boundary rejection. It deliberately stores neither the rejected value nor a derived
 * excerpt, so logs and error serialization cannot echo attacker-controlled signed material.
 */
export class InvalidScalarError extends Error {
  readonly code = "INVALID_SCALAR";

  constructor(
    readonly scalarKind: ScalarKind,
    readonly reason: ScalarFailureReason,
  ) {
    super(`${scalarKind} failed canonical validation (${reason})`);
    this.name = "InvalidScalarError";
  }
}

export interface OpaqueReferenceLimits {
  readonly maxUtf8Bytes: number;
  readonly maxCodePoints: number;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PADDED_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}=$/;
const PADDED_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}==$/;
const MAX_UNIX_TIME_SECS_V2_LENGTH = 17;
// Node-authored CONSTRUCTION grammar: canonical shortest-form wallet seconds — an optional
// fractional part of 1–3 digits whose final digit is non-zero (no trailing zeros), so the node
// only ever signs the minimal spelling and never rewrites signed bytes (the byte-exact signing rule). The
// FOREIGN-signed verify path deliberately does NOT use this pattern: a wallet may legitimately
// sign a grammar-valid but non-canonical trailing-zero spelling such as "1784332800.50", which is
// judged by inspectForeignSignedUnixTimeSecs below (grammar only; the layer class).
const UNIX_TIME_SECS_V2_PATTERN = /^(0|[1-9][0-9]{0,12})(?:\.[0-9]{0,2}[1-9])?$/;
// FOREIGN-signed acceptance grammar (layer boundary): identical to the
// construction pattern except the fractional part accepts ANY 1–3 digits, trailing zeros
// included. Used ONLY by inspectForeignSignedUnixTimeSecs — never by parseUnixTimeSecsV2.
const FOREIGN_SIGNED_UNIX_TIME_SECS_PATTERN = /^(0|[1-9][0-9]{0,12})(?:\.[0-9]{1,3})?$/;
const EXPIRY_UNIX_TIME_SECS_PATTERN = /^(0|[1-9][0-9]*)$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

function requireString(value: unknown, scalarKind: ScalarKind): string {
  if (typeof value !== "string") {
    throw new InvalidScalarError(scalarKind, "wrong_type");
  }
  return value;
}

function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  const paddingLength = (4 - (unpadded.length % 4)) % 4;
  return unpadded + "=".repeat(paddingLength);
}

function parsePaddedBase64Url(
  value: unknown,
  scalarKind: "WalletPublicKey" | "Ed25519Signature",
  pattern: RegExp,
  encodedLength: number,
  decodedLength: number,
): string {
  const text = requireString(value, scalarKind);
  if (text.length !== encodedLength || !pattern.test(text)) {
    throw new InvalidScalarError(scalarKind, "invalid_format");
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(text, "base64url");
  } catch {
    throw new InvalidScalarError(scalarKind, "invalid_format");
  }

  if (decoded.length !== decodedLength) {
    throw new InvalidScalarError(scalarKind, "invalid_length");
  }
  if (paddedBase64Url(decoded) !== text) {
    throw new InvalidScalarError(scalarKind, "non_canonical_encoding");
  }
  return text;
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function parseUuid(value: unknown): Uuid {
  const text = requireString(value, "Uuid");
  if (!UUID_PATTERN.test(text)) throw new InvalidScalarError("Uuid", "invalid_format");
  return text as Uuid;
}

export function parseWalletPublicKey(value: unknown): WalletPublicKey {
  return parsePaddedBase64Url(
    value,
    "WalletPublicKey",
    PADDED_PUBLIC_KEY_PATTERN,
    44,
    32,
  ) as WalletPublicKey;
}

export function parseEd25519Signature(value: unknown): Ed25519Signature {
  return parsePaddedBase64Url(
    value,
    "Ed25519Signature",
    PADDED_SIGNATURE_PATTERN,
    88,
    64,
  ) as Ed25519Signature;
}

export function parsePreviousStateSignature(value: unknown): PreviousStateSignature {
  const text = requireString(value, "PreviousStateSignature");
  if (text === "") return text as PreviousStateSignature;
  try {
    return parseEd25519Signature(text) as unknown as PreviousStateSignature;
  } catch (error) {
    if (error instanceof InvalidScalarError) {
      throw new InvalidScalarError("PreviousStateSignature", error.reason);
    }
    throw error;
  }
}

export function parseUnixTimeSecsV2(value: unknown): UnixTimeSecsV2 {
  const text = requireString(value, "UnixTimeSecsV2");
  if (text.length > MAX_UNIX_TIME_SECS_V2_LENGTH) {
    throw new InvalidScalarError("UnixTimeSecsV2", "invalid_length");
  }
  if (!UNIX_TIME_SECS_V2_PATTERN.test(text)) {
    throw new InvalidScalarError("UnixTimeSecsV2", "invalid_format");
  }
  return text as UnixTimeSecsV2;
}

/**
 * Grammar-only anomaly vocabulary for a FOREIGN-signed unix_time_secs. There is deliberately no
 * NON_CANONICAL member (the byte-exact signing rule): a grammar-valid but non-canonical foreign spelling
 * such as "1784332800.50" is well-formed and preserved verbatim, never re-judged against the
 * node-authored shortest-form strictness of parseUnixTimeSecsV2.
 */
export type ForeignUnixTimeSecsAnomaly = "NON_STRING" | "INVALID_LENGTH" | "INVALID_FORMAT";

/**
 * Evidence-only inspection. It carries no branded UnixTimeSecsV2: the foreign container must be
 * preserved verbatim in the signed head, and any node-authored re-emission goes through the
 * canonical parser. Mirrors amounts.ts's ForeignSignedAmountInspection.
 */
export interface ForeignSignedUnixTimeSecsInspection {
  readonly exactText: string | null;
  readonly wellFormed: boolean;
  readonly anomaly: ForeignUnixTimeSecsAnomaly | null;
  readonly requiresRawContainerPreservation: true;
  readonly semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE";
}

/**
 * Foreign-signed verify inspector for field 3 (the byte-exact signing rule / canonical ZKZ amount contract, the layer
 * class). Judges a foreign wallet's unix_time_secs by the STRUCTURAL grammar alone — trailing
 * fractional zeros ("1784332800.50") included — so a legitimately signed, gateway-accepted spelling
 * is not rejected before its signature is checked. Still bounded by MAX_UNIX_TIME_SECS_V2_LENGTH and
 * the 1–13 integer / 1–3 fractional digit grammar; a violation is recorded as evidence, never
 * rewritten. Node-authored construction stays strict via parseUnixTimeSecsV2 above.
 */
export function inspectForeignSignedUnixTimeSecs(
  value: unknown,
): ForeignSignedUnixTimeSecsInspection {
  if (typeof value !== "string") {
    return {
      exactText: null,
      wellFormed: false,
      anomaly: "NON_STRING",
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    };
  }
  if (value.length > MAX_UNIX_TIME_SECS_V2_LENGTH) {
    return {
      exactText: value,
      wellFormed: false,
      anomaly: "INVALID_LENGTH",
      requiresRawContainerPreservation: true,
      semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
    };
  }
  const wellFormed = FOREIGN_SIGNED_UNIX_TIME_SECS_PATTERN.test(value);
  return {
    exactText: value,
    wellFormed,
    anomaly: wellFormed ? null : "INVALID_FORMAT",
    requiresRawContainerPreservation: true,
    semanticPromotion: "REQUIRES_EXPLICIT_CANONICAL_PARSE",
  };
}

export function parseExpiryUnixTimeSecs(value: unknown): ExpiryUnixTimeSecs {
  const text = requireString(value, "ExpiryUnixTimeSecs");
  if (!EXPIRY_UNIX_TIME_SECS_PATTERN.test(text)) {
    throw new InvalidScalarError("ExpiryUnixTimeSecs", "invalid_format");
  }
  return text as ExpiryUnixTimeSecs;
}

export function parseSha256Hex(value: unknown): Sha256Hex {
  const text = requireString(value, "Sha256Hex");
  if (!SHA256_HEX_PATTERN.test(text)) {
    throw new InvalidScalarError("Sha256Hex", "invalid_format");
  }
  return text as Sha256Hex;
}

export function parseCanonicalVersion(value: unknown): CanonicalVersion {
  if (value !== 1 || typeof value !== "number") {
    throw new InvalidScalarError("CanonicalVersion", "wrong_literal");
  }
  return value;
}

export function parseOpaqueReference(
  value: unknown,
  limits: OpaqueReferenceLimits,
): OpaqueReference {
  if (
    typeof limits !== "object" ||
    limits === null ||
    !Number.isSafeInteger(limits.maxUtf8Bytes) ||
    limits.maxUtf8Bytes < 0 ||
    !Number.isSafeInteger(limits.maxCodePoints) ||
    limits.maxCodePoints < 0
  ) {
    throw new InvalidScalarError("OpaqueReference", "invalid_limits");
  }

  const text = requireString(value, "OpaqueReference");
  if (hasLoneSurrogate(text)) {
    throw new InvalidScalarError("OpaqueReference", "invalid_utf16");
  }
  if (
    Buffer.byteLength(text, "utf8") > limits.maxUtf8Bytes ||
    [...text].length > limits.maxCodePoints
  ) {
    throw new InvalidScalarError("OpaqueReference", "limit_exceeded");
  }
  return text as OpaqueReference;
}
