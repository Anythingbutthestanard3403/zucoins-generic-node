// Negative vectors for the implementer-events concern (A.9 baseline).
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// Each vector proves a specific rejection path. The verifier MUST reject all of these.

import {
  IMPLEMENTER_EVENT_GOLDEN_A,
  IMPLEMENTER_EVENT_PURPOSE,
} from "./implementer-event-tuple.js";
import { evaluateCheckpoint } from "./implementer-checkpoint.js";
import {
  IMPLEMENTER_KEYROTATION_GOLDEN,
  IMPLEMENTER_KEYROTATION_PURPOSE,
} from "./implementer-keyrotation.js";

// --- Field reorder / missing / unexpected ---

export function reorderedImplementerEvent(): string {
  const { purpose, canonical_version, ...rest } = IMPLEMENTER_EVENT_GOLDEN_A;
  return `${IMPLEMENTER_EVENT_PURPOSE}\n${JSON.stringify({ canonical_version, purpose, ...rest })}`;
}

export function missingFieldImplementerEvent(): string {
  const json = JSON.stringify(IMPLEMENTER_EVENT_GOLDEN_A);
  return `${IMPLEMENTER_EVENT_PURPOSE}\n${json.replace(',"wallet_id":"55555555-5555-4555-8555-555555555555"', "")}`;
}

export function unexpectedFieldImplementerEvent(): string {
  const json = JSON.stringify({ ...IMPLEMENTER_EVENT_GOLDEN_A, extra_field: "injected" });
  return `${IMPLEMENTER_EVENT_PURPOSE}\n${json}`;
}

// --- Purpose mismatch ---

export function purposeMismatchImplementerEvent(): string {
  const json = JSON.stringify(IMPLEMENTER_EVENT_GOLDEN_A);
  return `zp-node-event-v1\n${json}`;
}

export function payloadPurposeMismatch(): string {
  const payload = { ...IMPLEMENTER_EVENT_GOLDEN_A, purpose: "zp-node-event-v1" as const };
  return `${IMPLEMENTER_EVENT_PURPOSE}\n${JSON.stringify(payload)}`;
}

// --- Checkpoint rollback ---

export function checkpointRollback() {
  return evaluateCheckpoint(5n, 10n, 3n, 10n);
}

export function checkpointConflictingEqualEpoch() {
  return evaluateCheckpoint(5n, 10n, 5n, 11n);
}

// --- Key-rotation cursor violations ---

export function keyRotationUsesGlobalCursor(): string {
  // A keyrotation that references a global seq instead of implementer_seq is invalid.
  // This vector proves the field is named implementer_seq, not seq.
  const json = JSON.stringify({ ...IMPLEMENTER_KEYROTATION_GOLDEN, seq: "99" });
  return `${IMPLEMENTER_KEYROTATION_PURPOSE}\n${json}`;
}

export function keyRotationMissingSupersedes(): string {
  const json = JSON.stringify(IMPLEMENTER_KEYROTATION_GOLDEN);
  return `${IMPLEMENTER_KEYROTATION_PURPOSE}\n${json.replace(',"supersedes_key_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"', "")}`;
}

// --- Non-invertibility proof ---
// Given only node_event_hash, the tenant cannot recover global seq or previous_event_hash.
// This is a structural proof: SHA-256 is one-way; the preimage is not recoverable.

export const NON_INVERTIBILITY_PROOF = {
  nodeEventHash: "1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be",
  globalSeqRecoverable: false,
  globalPreviousEventHashRecoverable: false,
  reason: "SHA256_is_one_way_preimage_not_recoverable",
} as const;
