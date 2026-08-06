// SplitChain v2 inner shape. Read-only shape for
// projection/predicate consumers (this concern never constructs or signs a payload — the
// fixed-sequence builder construction path is a separate, not-yet-built concern). Field
// sequence here carries no runtime meaning for a TypeScript interface; it is preserved to
// match the spec's fixed-sequence table for review traceability only.
import { createHash } from "node:crypto";

export interface SplitChainStateV2 {
  readonly amount: string;
  readonly metadata?: unknown;
}

export interface SplitChainInnerV2 {
  readonly type: "unique_combinable";
  readonly version: "2";
  readonly unix_time_secs: string;
  readonly signer_steps: 2;
  readonly step_1_signer: "sender";
  readonly step_2_signer: "receiver";
  readonly step_1_key_public__base64urlsafe: string;
  readonly step_2_key_public__base64urlsafe: string;
  readonly step_1_state: SplitChainStateV2;
  readonly step_2_state: SplitChainStateV2;
  readonly previous_step_1_state_signature: string;
  readonly previous_step_2_state_signature: string;
  readonly expiry__unix_time_secs?: string;
  readonly message?: string;
}

// "the already insertion-sequenced in-memory object" plus both SplitChain signatures —
// the settled transaction object. This module always receives it as already-verified input;
// building or signature-verifying one is a separate concern.
export interface SettledSplitChainTransaction {
  readonly inner: SplitChainInnerV2;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
}

// "I — SHA-256 of the exact reconstructed JSON.stringify(inner) preimage." This
// package never rewrites a previously captured signed string; it only re-derives the
// digest of the inner object it was already handed, exactly as verification requires of a
// verifier reconstructing step_1_preimage_text.
export function computeInnerDigest(inner: SplitChainInnerV2): string {
  const preimage = JSON.stringify(inner);
  return createHash("sha256").update(preimage, "utf8").digest("hex");
}
