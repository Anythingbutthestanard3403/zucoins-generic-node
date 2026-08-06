// The one canonical suite-tuple serializer (spec: "The codebase MUST expose one
// canonical module ... Calling JSON.stringify for these tuples outside that module is forbidden").
//
// Discipline (the byte-exact signing rule + + exact-byte rules):
// - construct the payload object with explicit key insertion sequence taken from the frozen schema;
// - serialize EXACTLY ONCE with the native JSON.stringify — never a hand-rolled/alternate encoder,
// never a sort, spread, normalization, or parsed reconstruction;
// - the preimage is `purpose + "\n" + payload_json`; purpose is both the domain-separation prefix
// and payload field 1, and both copies are the same registered literal;
// - nullable fields are always present as JSON null; `null` and the empty-string sentinel `""`
// stay distinct.
// The serializer is pure: no I/O. SHA-256 is a deterministic digest of the preimage bytes (the spec
// requires the builder to yield `{preimageText, preimageBytes, sha256}`), not a side effect.

import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";

import { type CanonicalJson, type JsonObject } from "./encoders.js";
import { suitePurposeSpec, type SuitePurposeSpec } from "./registry.js";

export type SuiteSerializeReason =
  | "unknown_purpose"
  | "missing_field"
  | "unexpected_field"
  | "null_not_allowed"
  | "expiry_not_after_issue"
  | "expiry_window_exceeded";

// Structural rejection from the serializer itself (as opposed to a field encoder's value rejection).
// It carries a static reason and the schema field name only — never the caller's value.
export class SuiteSerializeError extends Error {
  readonly code = "SUITE_SERIALIZE";

  constructor(
    readonly reason: SuiteSerializeReason,
    readonly field: string,
  ) {
    super(`suite serialization rejected (${reason}${field ? `: ${field}` : ""})`);
    this.name = "SuiteSerializeError";
  }
}

// The frozen output of the one canonical builder. `preimageBytes` is the exact UTF-8 of
// `preimageText`; `sha256` is its lowercase-hex digest. There is deliberately no accessor for the
// assembled payload object — a caller can obtain the finished preimage and nothing that would let it
// re-run JSON.stringify itself (the external-serialization prohibition, enforced additionally by the
// census source scan).
export interface SuiteTuplePreimage {
  readonly preimageText: string;
  readonly preimageBytes: Uint8Array;
  readonly sha256: string;
}

export type SuiteTupleValues = Readonly<Record<string, unknown>>;

// Own-property presence only. `in` walks the prototype chain, so under a polluted
// `Object.prototype` an absent required field would read as present and the inherited value would be
// encoded into signed bytes; `rejectUnexpectedFields` uses own-only `Object.keys`, so the two checks
// must agree on own-property semantics or an inherited field slips between them.
function hasOwnField(values: SuiteTupleValues, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(values, name);
}

function buildOrderedPayload(specification: SuitePurposeSpec, values: SuiteTupleValues): JsonObject {
  const payload: Record<string, CanonicalJson> = {};
  for (const fieldSpec of specification.fields) {
    if (!hasOwnField(values, fieldSpec.name)) {
      throw new SuiteSerializeError("missing_field", fieldSpec.name);
    }
    const raw = values[fieldSpec.name];
    if (raw === null) {
      if (!fieldSpec.nullable) throw new SuiteSerializeError("null_not_allowed", fieldSpec.name);
      payload[fieldSpec.name] = null;
      continue;
    }
    // Byte-exact guard: caller-supplied scalar — never re-derive from parsed inner (canonical-field rule v15, signing rule r4)
    payload[fieldSpec.name] = fieldSpec.encoder(raw);
  }
  return payload as JsonObject;
}

function rejectUnexpectedFields(specification: SuitePurposeSpec, values: SuiteTupleValues): void {
  const allowed = new Set(specification.fields.map((fieldSpec) => fieldSpec.name));
  for (const key of Object.keys(values)) {
    if (!allowed.has(key)) throw new SuiteSerializeError("unexpected_field", key);
  }
}

const ISSUED_AT_FIELD = "issued_at";
const EXPIRES_AT_FIELD = "expires_at";

// A.4.1–A.4.3 / A.5 / A.5.1 signed freshness window: `0 < expires_at − issued_at ≤ windowSeconds`,
// measured against the SIGNED `issued_at` and never receipt time. Both operands were already
// validated as canonical RFC3339-ms by `encodeCanonicalTimestamp` in the pass above, so `Date.parse`
// is total here. Enforcing it in the serializer — rather than once per verifier — is what makes it
// unskippable: every verifier reaches its payload through `parseSuitePurpose`, which rebuilds the
// tuple through this function BEFORE `verifyEnvelope` checks the Ed25519 signature, satisfying
// A.4.3's "checked ... before signature verification". It also fails the signing direction closed, so
// a node cannot mint an over-long approval in the first place.
//
// Both comparisons are written as negated positives so a NaN delta fails closed rather than slipping
// through a `>` that is false for NaN. `≤ window` is inclusive: A.8.2's approval/bless/enrol goldens
// are themselves the exactly-+300.000s boundary case (conformance note), so an exclusive
// ceiling would reject committed canon.
function enforceSignedWindow(specification: SuitePurposeSpec, payload: JsonObject): void {
  const windowSeconds = specification.windowSeconds;
  if (windowSeconds === undefined) return;

  const issuedAt = Date.parse(payload[ISSUED_AT_FIELD] as string);
  const expiresAt = Date.parse(payload[EXPIRES_AT_FIELD] as string);
  const elapsedMs = expiresAt - issuedAt;

  if (!(elapsedMs > 0)) throw new SuiteSerializeError("expiry_not_after_issue", EXPIRES_AT_FIELD);
  if (!(elapsedMs <= windowSeconds * 1000)) {
    throw new SuiteSerializeError("expiry_window_exceeded", EXPIRES_AT_FIELD);
  }
}

// Serialize one suite tuple to its exact canonical preimage. `purpose` selects the frozen schema
// (versioned-purpose dispatch); an unregistered purpose is rejected before any bytes form. Every
// field is validated by its canonical encoder in schema sequence, no extra field is tolerated, and
// the object is JSON.stringify'd exactly once behind the `purpose + "\n"` domain prefix.
export function serializeSuiteTuple(purpose: string, values: SuiteTupleValues): SuiteTuplePreimage {
  const specification = suitePurposeSpec(purpose);
  if (specification === undefined) throw new SuiteSerializeError("unknown_purpose", purpose);

  rejectUnexpectedFields(specification, values);
  const payload = buildOrderedPayload(specification, values);
  enforceSignedWindow(specification, payload);

  const preimageText = `${purpose}\n${JSON.stringify(payload)}`;
  const preimageBytes = Buffer.from(preimageText, "utf8");
  const sha256 = createHash("sha256").update(preimageBytes).digest("hex");
  return { preimageText, preimageBytes, sha256 };
}
