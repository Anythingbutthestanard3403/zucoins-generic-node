// runtime verification of the node-global `zp-node-event-v1` hash-chained
// event stream. This is a LIBRARY, not a route: post- the stream is operator/auditor-only
// and must never be served to any tenant-facing signed reporting credential, so no serving
// surface is wired here — the auditor lane and platform-side independent verification
// consume this module.
//
// Per event, in check sequence: structural verify via the frozen verifier → node_id match →
// event-key resolution with purpose check and historical validity (created_at inside
// [activated_at, retired_at)) → Ed25519 signature → recompute event_hash =
// SHA256(preimage_bytes‖signature_bytes) and require equality with the served claim → when
// exact data text is served, recompute data_sha256 over it (never re-serialized, never nested
// in the preimage) → dedup by (event_id, event_hash) BEFORE any chain/seq evaluation → chain
// append on previous_event_hash via evaluateChainAppend (mismatch = HARD STOP, never a silent
// skip) → seq advance via evaluateTenantSeq (strictly-greater only; a skipped seq is another
// tenant's event, never a gap; seq is a decimal string → bigint, never Number).
//
// A duplicate (same event_id AND event_hash) is a no-op success — this is what makes batch
// overlap and full redelivery safe; same event_id with a different event_hash is an invariant
// breach and hard-stops. The batch is all-or-nothing: any stop appends nothing and the cursor
// never advances (and never regresses).
//
// The stream is a signed pull stream: per-node, gapless, pre-signed seq. Append and tenant-seq
// behavior live in evaluateChainAppend / evaluateTenantSeq.

import {
  decodeCanonicalEd25519Signature,
  decodeCanonicalReportingPublicKey,
  evaluateChainAppend,
  evaluateTenantSeq,
  parseCanonicalRfc3339Ms,
  verifyNodeEventPreimage,
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  type NodeEventPayload,
} from "@zucoins/generic-node-contracts";

import { computeNodeEventHash, sha256HexUtf8, verifyDetachedEd25519 } from "./ed25519.js";
import {
  NODE_EVENT_SIGNING_KEY_PURPOSE,
  type NodeEventCursor,
  type NodeEventVerificationStore,
  type RecordedNodeEvent,
} from "./store.js";

export interface ServedNodeEvent {
  readonly keyId: string;
  readonly preimageText: string;
  readonly signatureEncoded: string;
  readonly servedEventHash: string;
  readonly dataText?: string;
}

export type NodeEventBatchOutcome =
  | {
      readonly kind: "ACCEPTED";
      readonly accepted: number;
      readonly duplicates: number;
      readonly cursor: NodeEventCursor;
    }
  | { readonly kind: "DUPLICATES_ONLY"; readonly duplicates: number; readonly cursor: NodeEventCursor }
  | { readonly kind: "HARD_STOP_CHAIN_BREAK"; readonly eventId: string | null }
  | { readonly kind: "HARD_STOP_CONFLICT"; readonly eventId: string }
  | { readonly kind: "REJECTED"; readonly eventId: string | null; readonly reason: string };

export interface NodeEventVerifier {
  verifyBatch(nodeId: string, events: readonly ServedNodeEvent[]): Promise<NodeEventBatchOutcome>;
}

export interface NodeEventVerifierConfig {
  readonly store: NodeEventVerificationStore;
}

// The structural verifier has already accepted the preimage's canonical byte layout, so this
// parse is the inverse of the frozen builder, never a reinterpretation.
function payloadOf(preimageText: string): NodeEventPayload {
  return JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as NodeEventPayload;
}

export function createNodeEventVerifier(config: NodeEventVerifierConfig): NodeEventVerifier {
  const verifyBatch = async (
    nodeId: string,
    events: readonly ServedNodeEvent[],
  ): Promise<NodeEventBatchOutcome> => {
    const cursor = await config.store.readCursor(nodeId);
    let workingHash: string | null = cursor.lastEventHash;
    let workingSeq: bigint = cursor.lastSeq;
    let workingEventId: string | null = cursor.lastEventId;
    const staged: RecordedNodeEvent[] = [];
    const stagedByEventId = new Map<string, RecordedNodeEvent>();
    let duplicates = 0;

    for (const served of events) {
      const structural = verifyNodeEventPreimage(served.preimageText);
      if (!structural.ok) {
        return { kind: "REJECTED", eventId: null, reason: structural.reason ?? "invalid preimage" };
      }
      const payload = payloadOf(served.preimageText);
      if (payload.node_id !== nodeId) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "cross-node event" };
      }

      const key = await config.store.findEventSigningKey(nodeId, served.keyId);
      if (key === null) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "unknown event signing key" };
      }
      if (
        key.purpose !== NODE_EVENT_SIGNING_KEY_PURPOSE ||
        !(NODE_EVENT_KEY_ALLOWED_PURPOSES as readonly string[]).includes(payload.purpose)
      ) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "event key purpose mismatch" };
      }
      const createdAtMs = parseCanonicalRfc3339Ms(payload.created_at);
      if (
        createdAtMs === null ||
        createdAtMs < key.activatedAtMs ||
        (key.retiredAtMs !== null && createdAtMs >= key.retiredAtMs)
      ) {
        return {
          kind: "REJECTED",
          eventId: payload.event_id,
          reason: "event created outside the key validity window",
        };
      }

      const signatureBytes = decodeCanonicalEd25519Signature(served.signatureEncoded);
      const publicKeyBytes = decodeCanonicalReportingPublicKey(key.publicKeyEncoded);
      if (signatureBytes === null || publicKeyBytes === null) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "non-canonical key or signature bytes" };
      }
      const signatureValid = verifyDetachedEd25519({
        publicKeyBytes,
        preimageText: served.preimageText,
        signatureBytes,
      });
      if (!signatureValid) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "invalid event signature" };
      }

      const eventHash = computeNodeEventHash(served.preimageText, signatureBytes);
      if (eventHash !== served.servedEventHash) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "event hash claim mismatch" };
      }
      if (served.dataText !== undefined && sha256HexUtf8(served.dataText) !== payload.data_sha256) {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "event data digest mismatch" };
      }

      // Dedup BEFORE any chain/seq evaluation: a recorded (or earlier-staged) event with the
      // same id+hash is a no-op duplicate; the same id with a different hash is an invariant
      // breach.
      const recorded =
        stagedByEventId.get(payload.event_id) ??
        (await config.store.findRecordedEvent(nodeId, payload.event_id)) ??
        null;
      if (recorded !== null) {
        if (recorded.eventHash !== eventHash) {
          return { kind: "HARD_STOP_CONFLICT", eventId: payload.event_id };
        }
        duplicates += 1;
        continue;
      }

      if (evaluateChainAppend(workingHash, payload.previous_event_hash) !== "ACCEPT_CHAIN") {
        return { kind: "HARD_STOP_CHAIN_BREAK", eventId: payload.event_id };
      }
      const seq = BigInt(payload.seq);
      if (evaluateTenantSeq(workingSeq, seq) !== "ACCEPT_ADVANCE") {
        return { kind: "REJECTED", eventId: payload.event_id, reason: "seq reorder or replay" };
      }

      const stagedEvent: RecordedNodeEvent = {
        nodeId,
        eventId: payload.event_id,
        eventHash,
        seq,
      };
      staged.push(stagedEvent);
      stagedByEventId.set(payload.event_id, stagedEvent);
      workingHash = eventHash;
      workingSeq = seq;
      workingEventId = payload.event_id;
    }

    if (staged.length === 0) {
      return { kind: "DUPLICATES_ONLY", duplicates, cursor };
    }
    const appended = await config.store.appendVerifiedEvents(nodeId, staged, cursor);
    if (appended.kind === "CURSOR_STALE") {
      return { kind: "REJECTED", eventId: null, reason: "cursor advanced concurrently; retry the batch" };
    }
    return {
      kind: "ACCEPTED",
      accepted: staged.length,
      duplicates,
      cursor: {
        nodeId,
        lastEventHash: workingHash,
        lastSeq: workingSeq,
        lastEventId: workingEventId,
      },
    };
  };

  return { verifyBatch };
}
