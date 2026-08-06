// the strict `get_transaction__v1` gateway envelope parser: the
// The envelope stage of the observation verification pipeline, fed by the
// capture precondition (steps 3–5: capture the complete body into a byte buffer
// BEFORE any decoding, digest the exact bytes, then strict-decode and verify).
//
// Pure and side-effect free: raw captured bytes in, typed verdict
// out. No DB write, no operation state mutation, no retry/rebuild/resubmit authority
// (the never-blind-retry rule; the `gateway_read_indeterminate`/`gateway_submit_indeterminate` codes
// are the only typed retry-authority carriers and are not this module's concern).
//
// clean-room: the frozen v1 analogues (packages/splitchain/src/gateway.ts
// `isGatewayResponseShape`, packages/splitchain/src/response-verify.ts) are design
// references only — no v1 code is copied here. This parser is deliberately narrower and
// stricter than v1: it rejects trailing bytes after the JSON value, keeps
// MALFORMED_ENVELOPE distinct from genesis, and never folds signature verification into
// the shape check (signatures, exact inner scalars, and role determination are the later
// stages —).
//
// Vocabulary note: the generic core's neutrality gate forbids a certain product
// token as a whole word; where key positioning is meant, this module says
// "insertion sequence" instead — same bytes, same meaning.
import { createHash } from "node:crypto";

// established action-name literals are byte-sensitive and never generically renamed.
export const GET_TRANSACTION_ACTION_NAME = "get_transaction__v1";

// Mirrored byte-for-byte from its canonical freeze at
// packages/generic-node-contracts/src/transfer-code/candidate-intake.contract.ts
// (`GATEWAY_RESPONSE_FIELDS`; the response envelope). The contracts package's
// `exports` map exposes no `./transfer-code` subpath, so node-core mirrors the frozen
// constant instead of importing it; gateway-envelope.test.ts pins the mirror against the
// source line so a freeze change cannot drift silently.
export const GATEWAY_RESPONSE_FIELDS = ["status", "code", "message", "data"] as const;

// The settled transaction's fixed top-level sequence, retained verbatim.
export const SETTLED_TRANSACTION_FIELDS = ["inner", "step_1_signature", "step_2_signature"] as const;

// genesis is either (a) authoritative `account_not_found` with null/empty
// object data, or (b) status:true with an exact empty history array `data:[]` (the live
// gateway virgin-wallet shape; v1 `isGenesisLookup`). Envelope step 4 as amended by
// virgin-wallet empty history. Still NOT genesis: generic HTTP 404, timeout, malformed body, v1's
// `no_transaction_found` alone, non-empty wrong shapes.
export const GENESIS_ACCOUNT_NOT_FOUND_CODE = "account_not_found";

// Field 2: the only transaction version the v2 pipeline supports. Envelope step 5:
// an unknown transaction version fails closed.
export const SUPPORTED_TRANSACTION_VERSION = "2";

export const GATEWAY_ENVELOPE_CLASSIFICATIONS = ["GENESIS", "HEAD", "MALFORMED_ENVELOPE"] as const;

export type GatewayEnvelopeClassification = (typeof GATEWAY_ENVELOPE_CLASSIFICATIONS)[number];

// One rejection reason per envelope step, so a downstream anomaly record can say exactly
// which step failed closed. acceptance bar: unknown or malformed authoritative
// fields fail before any state promotion.
export const ENVELOPE_REJECTION_REASONS = [
  "utf8_decode_failed",
  "not_exactly_one_json_value",
  "envelope_shape_invalid",
  "not_authoritative_genesis",
  "not_exactly_one_complete_settled_transaction",
] as const;

export type EnvelopeRejectionReason = (typeof ENVELOPE_REJECTION_REASONS)[number];

// The envelope-layer view of one settled transaction entry. Honest about its own depth:
// the envelope stage (step 5) proves the fixed top-level sequence, both non-empty
// signatures, and a known inner version — nothing deeper. Exact inner field/scalar
// validation and Ed25519 signature verification are the next stage; typing
// `inner` any deeper here would let a consumer skip that stage.
export interface ParsedTransactionInner {
  readonly version: "2";
  readonly [field: string]: unknown;
}

export interface ParsedSettledTransaction {
  readonly inner: ParsedTransactionInner;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
}

interface EnvelopeVerdictBase {
  // The exact captured bytes (`raw_response_bytes`) — authoritative evidence
  // even when the classification is MALFORMED_ENVELOPE. Never mutated by this module.
  readonly rawBytes: Uint8Array;
  // Capture step 4 `raw_response_sha256`: SHA-256 of the exact raw bytes, computed BEFORE
  // any decode — a decode failure still yields the digest over the original bytes.
  readonly rawSha256: string;
}

export interface GenesisEnvelopeVerdict extends EnvelopeVerdictBase {
  readonly classification: "GENESIS";
  readonly parsed: null;
}

export interface HeadEnvelopeVerdict extends EnvelopeVerdictBase {
  readonly classification: "HEAD";
  // Direct JSON.parse output with property insertion sequence preserved (the next stage's
  // preimage reconstruction depends on it) — never resequenced, spread, or re-serialized.
  readonly parsed: ParsedSettledTransaction;
}

export interface MalformedEnvelopeVerdict extends EnvelopeVerdictBase {
  readonly classification: "MALFORMED_ENVELOPE";
  readonly parsed: null;
  readonly reason: EnvelopeRejectionReason;
}

export type GatewayEnvelopeVerdict =
  | GenesisEnvelopeVerdict
  | HeadEnvelopeVerdict
  | MalformedEnvelopeVerdict;

// Fatal-mode strict UTF-8 (step 1): an invalid byte sequence throws instead of
// silently substituting U+FFFD. `ignoreBOM: true` keeps a stray BOM in the body as a
// U+FEFF character, which the JSON parse step then rejects — fail closed. Non-streaming
// decode calls are stateless, so one shared decoder is safe for a pure function.
const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function malformed(
  rawBytes: Uint8Array,
  rawSha256: string,
  reason: EnvelopeRejectionReason,
): MalformedEnvelopeVerdict {
  return { rawBytes, rawSha256, classification: "MALFORMED_ENVELOPE", parsed: null, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function hasExactKeySequence(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

interface GatewayEnvelopeObject {
  readonly status: boolean;
  readonly code: string;
  readonly message: string;
  readonly data: unknown;
}

// Envelope step 3: the configured get_transaction__v1 envelope shape — the frozen
// {status, code, message, data} wrapper in its exact key sequence with exact scalar
// types. Unknown extra envelope fields fail closed.
function isGatewayEnvelopeObject(value: unknown): value is GatewayEnvelopeObject {
  if (!isRecord(value)) return false;
  if (!hasExactKeySequence(value, GATEWAY_RESPONSE_FIELDS)) return false;
  return (
    typeof value.status === "boolean" &&
    typeof value.code === "string" &&
    typeof value.message === "string"
  );
}

// Envelope step 4 / chain-link equals prior settled step_2_signature: authoritative account-not-found with no transaction data.
// Live `data` shapes are `null` and the empty object.
function isAuthoritativeAccountNotFound(envelope: GatewayEnvelopeObject): boolean {
  if (envelope.code !== GENESIS_ACCOUNT_NOT_FOUND_CODE) return false;
  if (envelope.data === null) return true;
  return isRecord(envelope.data) && Object.keys(envelope.data).length === 0;
}

// live gateway virgin-wallet shape — status:true + exact empty history array.
// Code string is opaque (not required to be "ok"/"success"). Fail-closed on non-array
// or any length other than 0 (length 1 is HEAD; length >1 is malformed head-only).
function isAuthoritativeEmptyHistory(envelope: GatewayEnvelopeObject): boolean {
  return envelope.status === true && Array.isArray(envelope.data) && envelope.data.length === 0;
}

// Envelope step 5: a head result carries exactly one complete settled transaction.
// Missing/empty step-2 signature, a partial transaction, or an unknown transaction
// version fails closed; the entry must carry the fixed top-level sequence exactly
// (unknown extra entry fields fail closed). Inner field/scalar exactness is the next
// stage, not this one.
function isCompleteSettledTransaction(entry: unknown): entry is ParsedSettledTransaction {
  if (!isRecord(entry)) return false;
  if (!hasExactKeySequence(entry, SETTLED_TRANSACTION_FIELDS)) return false;
  if (!isRecord(entry.inner) || entry.inner.version !== SUPPORTED_TRANSACTION_VERSION) return false;
  return isNonEmptyString(entry.step_1_signature) && isNonEmptyString(entry.step_2_signature);
}

// The envelope stage over one captured `get_transaction__v1` response body.
// `rawResponseBytes` is the complete body captured BEFORE any decode (never a combined
// decode-and-parse result); the digest is taken from those exact bytes first, so even an
// undecodable body yields the SHA-256 of the authoritative original bytes. The input
// buffer is never mutated.
export function parseGatewayEnvelope(rawResponseBytes: Uint8Array): GatewayEnvelopeVerdict {
  // Capture step 4 — digest the exact captured bytes, before any decode.
  const rawSha256 = createHash("sha256").update(rawResponseBytes).digest("hex");

  // Envelope step 1 — strict UTF-8; replacement characters are not permitted.
  let text: string;
  try {
    text = STRICT_UTF8_DECODER.decode(rawResponseBytes);
  } catch {
    return malformed(rawResponseBytes, rawSha256, "utf8_decode_failed");
  }

  // Envelope step 2 — exactly one JSON value; trailing non-whitespace bytes fail
  // (JSON.parse tolerates surrounding whitespace and nothing else).
  let parsedValue: unknown;
  try {
    parsedValue = JSON.parse(text);
  } catch {
    return malformed(rawResponseBytes, rawSha256, "not_exactly_one_json_value");
  }

  // Envelope step 3 — the configured get_transaction__v1 envelope shape; a success-
  // looking body from a different action schema fails closed here or at step 5.
  if (!isGatewayEnvelopeObject(parsedValue)) {
    return malformed(rawResponseBytes, rawSha256, "envelope_shape_invalid");
  }

  // Envelope step 4 / virgin-wallet empty history — genesis from account-not-found OR status:true empty [].
  if (!parsedValue.status) {
    if (isAuthoritativeAccountNotFound(parsedValue)) {
      return { rawBytes: rawResponseBytes, rawSha256, classification: "GENESIS", parsed: null };
    }
    return malformed(rawResponseBytes, rawSha256, "not_authoritative_genesis");
  }
  if (isAuthoritativeEmptyHistory(parsedValue)) {
    return { rawBytes: rawResponseBytes, rawSha256, classification: "GENESIS", parsed: null };
  }

  // Envelope step 5 — a head result carries exactly one complete settled transaction.
  const data = parsedValue.data;
  if (!Array.isArray(data) || data.length !== 1) {
    return malformed(rawResponseBytes, rawSha256, "not_exactly_one_complete_settled_transaction");
  }
  const entry: unknown = data[0];
  if (!isCompleteSettledTransaction(entry)) {
    return malformed(rawResponseBytes, rawSha256, "not_exactly_one_complete_settled_transaction");
  }
  return { rawBytes: rawResponseBytes, rawSha256, classification: "HEAD", parsed: entry };
}
