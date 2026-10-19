/**
 * Public receive instruction (ZTR-1335).
 *
 * This is a browser projection of one receive. It is not a Layer-1 status
 * vocabulary: `OPERATION_STATES` stays the frozen four receive statuses.
 * `RECEIVE_LANDED` is projected to `SETTLED` on this surface only.
 * `OBSERVED` and `FAILED` are reserved projection labels and are not written
 * onto `operations.status`.
 *
 * The signed object is the persisted `zp-receive-expected-v1` artifact
 * (`key_id`, `preimage_text`, `preimage_sha256`, `signature`). The preimage
 * bytes stay intact so a browser can verify them. Callers must not treat
 * those bytes as a second public field set.
 */

export const PUBLIC_RECEIVE_INSTRUCTION_STATES = [
  "CREATED",
  "READY",
  "OBSERVED",
  "SETTLED",
  "EXPIRED",
  "FAILED",
] as const;

export type PublicReceiveInstructionState = (typeof PUBLIC_RECEIVE_INSTRUCTION_STATES)[number];

/** Persisted artifact envelope. Byte-identical to the row written at formation. */
export interface PersistedReceiveExpectedEnvelope {
  readonly purpose: "zp-receive-expected-v1";
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

export interface PublicReceiveInstructionResponse {
  readonly operation_id: string;
  readonly state: PublicReceiveInstructionState;
  readonly expected_amount_zkz: string;
  readonly recipient_wallet_address: string;
  readonly expires_at: string;
  readonly transfer_code: string | null;
  readonly node_id: string;
  readonly node_public_key_pem: string;
  readonly signed_expected_envelope: PersistedReceiveExpectedEnvelope;
}
