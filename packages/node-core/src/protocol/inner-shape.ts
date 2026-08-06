// Closed-shape + foreign-scalar narrow for SplitChain inner.
// Shared by (verifier) and receive candidate intake (write-time gate). Lives under
// protocol/ so receive ↛ verifier boundary stays intact while both compose one implementation.
//
// Input is a plain parsed object (JSON.parse insertion ordering preserved) — typically the
// envelope stage's inner or a captured candidate preimage. Honest about its own depth:
// version "2" and nothing deeper is proved here, not assumed by the type.
//
// Check sequence: closed field set in the exact insertion sequence
// (positions 1–12 fixed; positions 13–14 optional and only those two), fixed literals,
// exact state-object shape, then every scalar through the on-main branded validators
// (scalars.ts) — with the two foreign-signed step amounts held to amounts.ts's FOREIGN
// layer, the grammar alone. Fail closed throughout, with one of two shape codes:
// `unexpected_inner_shape` for field-set, sequence, literal, and state-shape deviations;
// `invalid_scalar` for branded-grammar failures (carrying the validator's own fixed
// scalar vocabulary).
//
// Narrowing never rebuilds the object: on success the parsed object itself is the
// `SplitChainInnerV2`. A rebuild (spread, re-parse, key sort) would rewrite the signed
// bytes — the A.9 #15 JSONB-reconstruction attack surface this stage exists to deny.
import { inspectForeignSignedAmount } from "./amounts.js";
import { type SplitChainInnerV2, type SplitChainStateV2 } from "./inner.js";
import {
  InvalidScalarError,
  inspectForeignSignedUnixTimeSecs,
  parseExpiryUnixTimeSecs,
  parseOpaqueReference,
  parsePreviousStateSignature,
  parseWalletPublicKey,
  type ScalarFailureReason,
  type ScalarKind,
} from "./scalars.js";

/** Closed-shape input: plain object with insertion-ordered keys preserved (JSON.parse). */
export type SplitChainInnerParseInput = Readonly<Record<string, unknown>>;

// Positions 1–12: always present, in this exact insertion sequence.
export const SPLIT_CHAIN_INNER_REQUIRED_FIELDS = [
  "type",
  "version",
  "unix_time_secs",
  "signer_steps",
  "step_1_signer",
  "step_2_signer",
  "step_1_key_public__base64urlsafe",
  "step_2_key_public__base64urlsafe",
  "step_1_state",
  "step_2_state",
  "previous_step_1_state_signature",
  "previous_step_2_state_signature",
] as const;

// Positions 13–14: the only optional fields, in this exact trailing sequence.
export const SPLIT_CHAIN_INNER_OPTIONAL_FIELDS = ["expiry__unix_time_secs", "message"] as const;

// The closed set of permitted inner key sequences: the 12 required fields, plus each
// optional alone, plus both together (still in sequence).
const PERMITTED_INNER_KEY_SEQUENCES: readonly (readonly string[])[] = [
  SPLIT_CHAIN_INNER_REQUIRED_FIELDS,
  [...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "expiry__unix_time_secs"],
  [...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "message"],
  [...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "expiry__unix_time_secs", "message"],
];

// Field 14, mirroring the write-path limits: message is an opaque reference of at
// most 256 Unicode scalars / 1024 UTF-8 bytes. Content policy beyond the scalar grammar
// (non-emptiness) is a construction concern, never a verification rejection — foreign
// signed bytes are judged by grammar alone (the byte-exact signing rule).
const MESSAGE_OPAQUE_LIMITS = { maxUtf8Bytes: 1024, maxCodePoints: 256 } as const;

export type InnerShapeRejection =
  | { readonly reason: "unexpected_inner_shape"; readonly detail: string }
  | {
      readonly reason: "invalid_scalar";
      readonly scalarKind: ScalarKind;
      readonly scalarReason: ScalarFailureReason;
    };

export type InnerShapeNarrowing =
  | { readonly ok: true; readonly inner: SplitChainInnerV2 }
  | { readonly ok: false; readonly rejection: InnerShapeRejection };

function unexpected(detail: string): InnerShapeNarrowing {
  return { ok: false, rejection: { reason: "unexpected_inner_shape", detail } };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeySequence(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

// Fields 9–10: a state object is exactly {"amount"} or {"amount","metadata"} in
// that sequence. The amount's grammar is the scalar stage's concern below; here only the
// container shape is proved.
function isSplitChainStateShape(value: unknown): value is SplitChainStateV2 {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value);
  if (keys[0] !== "amount") return false;
  if (keys.length === 1) return true;
  return keys.length === 2 && keys[1] === "metadata";
}

// Fields 9–10 carry FOREIGN-signed absolute balances, so they are judged by the
// `ZkzAmount` GRAMMAR alone through the foreign-signed layer's inspector — never by
// the node-authored canonical parser `parseZkzBalance`, whose additional
// `decimal.toFixed === text` equality would reject a legitimately signed, gateway-accepted
// spelling such as "7.50" before a single signature byte is read: "Foreign signed
// transactions are verified over their original parsed field strings; their signed bytes
// MUST NOT be rewritten merely to satisfy the node's preferred construction format." On the
// money path that false reject is a stuck settlement, and it is the FAIL class
// `amounts.ts` warns about verbatim — node-authored strictness collapsing the
// foreign/node-authored layer boundary in the unsafe direction.
//
// Nothing is widened: the grammar itself carries `0 <= amount < 1e8` bound (at most 8
// integer digits, at most 32 fractional), keeps "0" valid, and is byte-for-byte the frozen
// `zkz_balance_text` domain the record layer already accepts for the very `b_amount` this
// stage projects (generic-node-contracts observation/scalars.contract.ts). The rejection stays
// inside the `invalid_scalar` code and the validator's own scalar vocabulary.
function requireForeignSignedAmount(value: unknown): void {
  const inspection = inspectForeignSignedAmount(value);
  if (inspection.wellFormed) return;
  throw new InvalidScalarError(
    "ZkzBalance",
    inspection.anomaly === "NON_STRING" ? "wrong_type" : "invalid_format",
  );
}

// Field 3 (unix_time_secs) carries a FOREIGN-signed absolute wallet clock, so it is judged by
// the SECONDS-string GRAMMAR alone through the foreign-signed inspector — never by the
// node-authored construction parser parseUnixTimeSecsV2, whose shortest-form strictness (no trailing
// fractional zeros) would reject a legitimately signed, gateway-accepted spelling such as
// "1784332800.50" before a single signature byte is read. That false reject is the same stuck-
// settlement class amounts.ts warns about (the byte-exact signing rule), here for field 3 instead
// of the step amounts. Nothing is widened: the grammar keeps the 1–13 integer / 1–3 fractional digit
// bound and MAX_UNIX_TIME_SECS_V2_LENGTH, and the rejection stays inside the invalid_scalar code
// with the validator's own UnixTimeSecsV2 vocabulary (wrong_type / invalid_length / invalid_format).
function requireForeignSignedUnixTimeSecs(value: unknown): void {
  const inspection = inspectForeignSignedUnixTimeSecs(value);
  if (inspection.wellFormed) return;
  const reason: ScalarFailureReason =
    inspection.anomaly === "NON_STRING"
      ? "wrong_type"
      : inspection.anomaly === "INVALID_LENGTH"
        ? "invalid_length"
        : "invalid_format";
  throw new InvalidScalarError("UnixTimeSecsV2", reason);
}

export function narrowSplitChainInner(parsed: SplitChainInnerParseInput): InnerShapeNarrowing {
  // Closed field set in the exact insertion sequence — unknown fields, missing
  // fields, and sequence deviations all fail here (item 2's unknown-
  // field and field-position vectors).
  if (!PERMITTED_INNER_KEY_SEQUENCES.some((sequence) => hasExactKeySequence(parsed, sequence))) {
    return unexpected(
      "inner field set is not the closed 14-field shape in its exact insertion sequence",
    );
  }

  // Fixed literals (fields 1, 2, 4, 5, 6). signer_steps must be the NUMBER 2 — the
  // string "2" is a shape deviation, not a scalar failure.
  if (parsed.type !== "unique_combinable") {
    return unexpected(`type must be the literal "unique_combinable"`);
  }
  if (parsed.version !== "2") {
    return unexpected(`version must be the literal "2"`);
  }
  if (parsed.signer_steps !== 2) {
    return unexpected("signer_steps must be the number 2");
  }
  if (parsed.step_1_signer !== "sender") {
    return unexpected(`step_1_signer must be the literal "sender"`);
  }
  if (parsed.step_2_signer !== "receiver") {
    return unexpected(`step_2_signer must be the literal "receiver"`);
  }

  const step1State: unknown = parsed.step_1_state;
  if (!isSplitChainStateShape(step1State)) {
    return unexpected(`step_1_state must be a JSON object shaped {"amount"} or {"amount","metadata"}`);
  }
  const step2State: unknown = parsed.step_2_state;
  if (!isSplitChainStateShape(step2State)) {
    return unexpected(`step_2_state must be a JSON object shaped {"amount"} or {"amount","metadata"}`);
  }

  // Branded scalars (fields 3, 7, 8, the 9–10 amounts, 11, 12, and the optionals).
  // unix_time_secs is a foreign-signed SECONDS string — never a JS number — judged by the
  // grammar alone (see requireForeignSignedUnixTimeSecs), so a legitimately non-canonical
  // trailing-zero spelling survives to the signature check. Both step amounts are likewise
  // string-only foreign-signed ZKZ text with zero valid (canonical ZKZ amount contract), judged by the grammar alone
  // (see requireForeignSignedAmount). Keys and previous-state signatures ARE held to canonical
  // re-encoding, because the grammar makes that part of their own validity rule.
  try {
    requireForeignSignedUnixTimeSecs(parsed.unix_time_secs);
    parseWalletPublicKey(parsed.step_1_key_public__base64urlsafe);
    parseWalletPublicKey(parsed.step_2_key_public__base64urlsafe);
    requireForeignSignedAmount(step1State.amount);
    requireForeignSignedAmount(step2State.amount);
    parsePreviousStateSignature(parsed.previous_step_1_state_signature);
    parsePreviousStateSignature(parsed.previous_step_2_state_signature);
    if (parsed.expiry__unix_time_secs !== undefined) {
      parseExpiryUnixTimeSecs(parsed.expiry__unix_time_secs);
    }
    if (parsed.message !== undefined) {
      parseOpaqueReference(parsed.message, MESSAGE_OPAQUE_LIMITS);
    }
  } catch (error) {
    if (error instanceof InvalidScalarError) {
      return {
        ok: false,
        rejection: {
          reason: "invalid_scalar",
          scalarKind: error.scalarKind,
          scalarReason: error.reason,
        },
      };
    }
    throw error;
  }

  // Runtime-proven narrowing: the parsed object itself, never a rebuild.
  return { ok: true, inner: parsed as unknown as SplitChainInnerV2 };
}
