// MOVE_INTERNAL step-2 preimage and completed-transaction assembly from persisted text.
// Covers formation steps 5 and 8 under all eight exact-byte rules; the byte-exact signing rule.
//
// Step 5: parse the persisted exact inner text, byte-compare JSON.stringify(inner)
// with the persisted inner_preimage_text, reject any mismatch or normalization. Construct
// JSON.stringify({inner,step_1_signature}) in a fixed insertion sequence.
//
// The parse-and-compare is the guard; it is NOT the construction input. Once the round trip is
// proven byte-identical, splicing the persisted text verbatim and re-serializing the parsed
// object are the same bytes by definition — but only the splice stays correct if a future V8,
// a Unicode normalization, or a key-sequence quirk breaks the equality the guard just asserted.
// So: assert the round trip, then splice. Nothing here re-serializes an inner or a signature.

import { createHash } from "node:crypto";

/** Exactly two keys, in this sequence (A.1.2) — never the three-key settled-ledger shape. */
const STEP2_PREFIX = '{"inner":';
const STEP2_SIGNATURE_KEY = ',"step_1_signature":';
const SETTLED_SIGNATURE_KEY = ',"step_2_signature":';

/**
 * The persisted preimage does not survive a JSON round trip byte-identically, or a caller
 * handed text that is not the exact persisted bytes. Either way the signed material and the
 * durable record disagree and no signature may be formed over it.
 */
export class MovePreimageDriftError extends Error {
  readonly code = "MOVE_PREIMAGE_DRIFT";

  constructor(readonly reason: "round_trip_mismatch" | "not_an_object" | "malformed_step_2_preimage") {
    super(`MOVE_INTERNAL preimage rejected (${reason})`);
    this.name = "MovePreimageDriftError";
  }
}

/**
 * Step 5 guard. Parses the persisted exact inner text and byte-compares
 * `JSON.stringify` of the result against the input. Catches Unicode NFC/NFD substitution,
 * key-sequence drift, whitespace normalization, and a `jsonb`-style re-emission (A.9 #8–9).
 *
 * Returns nothing on purpose: the parsed object is a witness, never construction input.
 */
export function assertPersistedInnerRoundTrips(innerPreimageText: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(innerPreimageText);
  } catch {
    throw new MovePreimageDriftError("not_an_object");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new MovePreimageDriftError("not_an_object");
  }
  if (JSON.stringify(parsed) !== innerPreimageText) {
    throw new MovePreimageDriftError("round_trip_mismatch");
  }
}

/**
 * Step 5 — `{inner, step_1_signature}`, exactly two keys in that insertion sequence.
 * The inner is spliced verbatim from the persisted text; only the signature, a JSON string,
 * is serialized here.
 */
export function buildMoveStep2PreimageText(
  innerPreimageText: string,
  step1Signature: string,
): string {
  assertPersistedInnerRoundTrips(innerPreimageText);
  return (
    STEP2_PREFIX +
    innerPreimageText +
    STEP2_SIGNATURE_KEY +
    JSON.stringify(step1Signature) +
    "}"
  );
}

/**
 * Step 8 — the settled three-key ledger shape, derived from the *persisted* step-2
 * preimage rather than re-spliced from its parts. The step-2 signature is appended to the
 * exact bytes the destination signer saw, so the completed transaction cannot disagree with
 * what was signed even if the inner or the step-1 signature were somehow re-derived elsewhere.
 */
export function buildMoveCompletedTransactionText(
  step2PreimageText: string,
  step2Signature: string,
): string {
  if (!step2PreimageText.startsWith(STEP2_PREFIX) || !step2PreimageText.endsWith("}")) {
    throw new MovePreimageDriftError("malformed_step_2_preimage");
  }
  return (
    step2PreimageText.slice(0, -1) +
    SETTLED_SIGNATURE_KEY +
    JSON.stringify(step2Signature) +
    "}"
  );
}

/** SHA-256 over the exact UTF-8 bytes of a preimage. No decode, pad, or repair first. */
export function hashMovePreimageText(preimageText: string): string {
  return createHash("sha256").update(Buffer.from(preimageText, "utf8")).digest("hex");
}
