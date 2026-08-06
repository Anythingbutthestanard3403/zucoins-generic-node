// The pull-cursor authority facts and verifiers. The authoritative pull cursor over the
// node-global hash chain is the sole authority for operation truth; SSE is a low-latency wake
// accelerator that never advances a consumer cursor and is never authoritative. These verifiers
// consume event-sequencing's gap-detection facts and reporting-behavior's tenant-sparsity /
// chain-append rules, binding this census to the earlier frozen slices (which win on any
// conflict). All checks are structural.
//
// CONTRACT_FREEZE.

import { GAP_DETECTION, gapDetectorIsHashChain } from "../event-sequencing/index.js";
import { evaluateTenantSeq } from "../reporting-behavior/index.js";

// The role markers. AUTHORITATIVE_CURSOR_ROLE must equal the pull_events role and SSE_ACCELERATOR_ROLE
// the sse_stream role, both frozen in AUTHORITATIVE_CHANNELS — the census binds to those by value.
export const AUTHORITATIVE_CURSOR_ROLE = "authoritative_cursor" as const;
export const SSE_ACCELERATOR_ROLE = "low_latency_wake_accelerator" as const;

export interface CursorChannelShape {
  readonly channel: string;
  readonly role: string;
}
export interface SseCursorModelShape {
  readonly channel: string;
  readonly advancesCursor: boolean;
}

// True iff exactly one channel — pull_events — holds the authoritative-cursor role and SSE (if
// present) holds only the accelerator role. A model that promotes SSE to the authoritative role is
// rejected (returns false).
export function pullIsSoleCursorAuthority(channels: readonly CursorChannelShape[]): boolean {
  const authoritative = channels.filter((c) => c.role === AUTHORITATIVE_CURSOR_ROLE);
  if (authoritative.length !== 1 || authoritative[0]?.channel !== "pull_events") return false;
  const sse = channels.find((c) => c.channel === "sse_stream");
  return sse === undefined || sse.role === SSE_ACCELERATOR_ROLE;
}

// True iff a candidate SSE model keeps cursor authority — i.e. SSE does NOT advance the cursor. The
// cursor-dimension negative control: an SSE-advances-cursor model is rejected (returns false).
export function sseModelKeepsCursorAuthority(model: SseCursorModelShape): boolean {
  return model.channel === "sse_stream" && model.advancesCursor === false;
}

// True iff the sparse tenant view is complete: the tenant-seq rule advances the cursor on
// any strictly-greater seq, and a skipped seq is another tenant's event (not a gap) under the
// node-global hash chain — so a tenant reading the full pull stream up to its cursor has complete
// truth despite the sparsity.
export function sparseTenantViewIsComplete(cursor: bigint, nextEventSeq: bigint): boolean {
  return (
    evaluateTenantSeq(cursor, nextEventSeq) === "ACCEPT_ADVANCE" &&
    GAP_DETECTION.skippedSeqMeaning === "another_tenants_event_not_a_gap" &&
    gapDetectorIsHashChain(GAP_DETECTION)
  );
}

// True iff the authoritative gap/tamper detector is the node-global hash chain, never seq contiguity
// (event-sequencing's GAP_DETECTION) — so a real gap is chain-detected, and a sparse tenant view is not a gap.
export function gapDetectorIsChainNotContiguity(): boolean {
  return gapDetectorIsHashChain(GAP_DETECTION);
}
