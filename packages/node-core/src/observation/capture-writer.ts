// Capture writer for gateway observation rows — the node-side, serialized
// capture-and-persist path that binds the frozen observation primitives to the
// wallet_observation_cursors table and the observers / gateway_observations ledger
// (observation-ledger.sql).
//
// The PURE composition of the byte primitive (decideAppend) and
// the relationship classifier (classifyRelationship) is already frozen as the in-memory
// reducer runObservationSequence (sequence-driver.ts). This module adds the two
// runtime pieces that reducer leaves out: (1) the per-(observer_id, wallet_public_key)
// serialization lock that makes a capture's read-classify-persist a single critical section
// (step 1), and (2) the persistence plan against wallet_observation_cursors +
// gateway_observations (steps 6-10). It REUSES the frozen
// reducer for the dedup + classification, so the exact-byte equality and relationship
// semantics can never drift from their frozen source.
//
// The raw response bytes reach this path exactly as captured before any decode (gateway/capture.ts,
// step 3); this module hashes those bytes (step 4) and never decodes them. Anomaly
// ROWS (step 9) are observation_anomalies table: this path CLASSIFIES the anomaly
// and surfaces anomalyRequired so the composing transaction persists it atomically, but never
// writes that table itself.

import {
  EMPTY_CURSOR,
  isVerifiedParseResult,
  rawResponseDigest,
  runObservationSequence,
  type ObservationRelationship,
  type SequenceCapture,
  type SequenceEvent,
  type StreamCursor,
} from "@zucoins/generic-node-contracts/observation";

// One read stream: the node and platform are different observers, so the lock and the
// cursor are keyed on BOTH the observer and the queried wallet public key. There is no
// cross-observer cursor and no global deduplication.
export interface ObservationStreamKey {
  readonly observerId: string;
  readonly walletPublicKey: string;
}

// A JSON 2-tuple is an injective lock/cursor key: JSON escapes each string, so two distinct
// (observerId, walletPublicKey) pairs can never collide onto one key regardless of their bytes.
const streamKeyId = (key: ObservationStreamKey): string =>
  JSON.stringify([key.observerId, key.walletPublicKey]);

// The cursor mutation for a suppressed sighting (step 7): no new row, next_wallet_seq
// unchanged, only the repeat counter advances (last_seen_at is the persister's clock).
export interface CursorSightingUpdate {
  readonly consecutiveRepeatCount: number;
}

// The gateway_observations row this capture appends (step 8). Only the fields THIS write path
// sets are modelled; the row id is minted by the database and bound by the persister.
export interface PlannedObservationRow {
  readonly walletSeq: number;
  readonly rawResponseSha256: string;
  readonly verified: boolean;
  readonly relationship: ObservationRelationship;
  readonly stateChanged: boolean | null;
  readonly previousRecordedSeq: number | null;
}

// The cursor upsert after an append (step 10): point at the new row, carry its digest and
// only when verified (CURSOR_SEMANTIC_FINGERPRINT_NULLABLE) — its semantic fingerprint, reset
// the sighting counter, and advance next_wallet_seq.
export interface CursorAppendUpdate {
  readonly nextWalletSeq: number;
  readonly consecutiveRepeatCount: 0;
  readonly lastRawResponseSha256: string;
  readonly lastSemanticFingerprint: string | null;
}

export type CaptureWritePlan =
  | { readonly kind: "SUPPRESS_AS_SIGHTING"; readonly cursor: CursorSightingUpdate }
  | {
      readonly kind: "APPEND";
      readonly observation: PlannedObservationRow;
      readonly cursor: CursorAppendUpdate;
      // step 9: a failed verification or an anomalous relationship must append an
      // observation_anomalies row in the SAME transaction. This path does not own that
      // table; it flags the requirement so the composing transaction discharges it atomically.
      readonly anomalyRequired: boolean;
    };

export interface CaptureWriteResult {
  readonly plan: CaptureWritePlan;
  readonly event: SequenceEvent;
  readonly nextCursor: StreamCursor;
}

/**
 * Per-capture planner options. `appendExactRepeat` is the expiry confirm-read seam
 * (ZTR-1275): when the frozen reducer would SUPPRESS_AS_SIGHTING a verified
 * byte-identical repeat, force an APPEND row with relationship DUPLICATE so
 * FRESH_VERIFIED_T0_EXACT can name a post-expiry observation id. Default off —
 * ordinary capture paths keep suppress-as-sighting behaviour unchanged.
 */
export interface PlanCaptureOptions {
  readonly appendExactRepeat?: boolean;
}

// PURE core: fold this one capture through the frozen reducer against the prior stream cursor
// (null = a fresh stream), then map the reducer's decision to a persistence plan. No lock, no
// I/O — the serialization guarantee is the writer's, below.
export const planCapture = (
  prior: StreamCursor | null,
  capture: SequenceCapture,
  options?: PlanCaptureOptions,
): CaptureWriteResult => {
  const base = prior ?? EMPTY_CURSOR;
  const { events, cursor: reducedCursor } = runObservationSequence([capture], base);
  const event = events[0]!;
  const digest = capture.rawResponseSha256Override ?? rawResponseDigest(capture.rawResponseBytes);

  if (event.decision === "SUPPRESS_AS_SIGHTING") {
    // ZTR-1275: confirm-read path needs a durable DUPLICATE row (not a sighting bump).
    // previous_recorded is the cursor tip (base.lastRecordedSeq); no anomaly row.
    if (options?.appendExactRepeat === true) {
      const walletSeq = base.nextWalletSeq;
      const verified = isVerifiedParseResult(capture.parseResult);
      const nextCursor: StreamCursor = {
        nextWalletSeq: walletSeq + 1,
        consecutiveRepeatCount: 0,
        rowCount: base.rowCount + 1,
        anomalyCount: base.anomalyCount,
        lastRecordedSeq: walletSeq,
        lastRecorded: {
          verified,
          rawResponseSha256: digest,
          rawResponseOctets: capture.rawResponseBytes.byteLength,
          rawResponseBytes: capture.rawResponseBytes,
        },
        lastAcceptedState: verified
          ? {
              isGenesis: capture.isGenesis,
              sSignature: capture.sSignature,
              pSignature: capture.pSignature,
              semanticFingerprint: capture.semanticFingerprint,
            }
          : base.lastAcceptedState,
        acceptedStateSignatureHistory: verified
          ? [...base.acceptedStateSignatureHistory, capture.sSignature]
          : base.acceptedStateSignatureHistory,
        priorHistoryHasNonGenesis:
          base.priorHistoryHasNonGenesis || (verified && !capture.isGenesis),
      };
      const syntheticEvent: SequenceEvent = {
        decision: "APPEND",
        walletSeq,
        relationship: "DUPLICATE",
        stateChanged: false,
        anomalyAppended: false,
        previousRecordedSeq: base.lastRecordedSeq,
      };
      return {
        plan: {
          kind: "APPEND",
          observation: {
            walletSeq,
            rawResponseSha256: digest,
            verified,
            relationship: "DUPLICATE",
            stateChanged: false,
            previousRecordedSeq: base.lastRecordedSeq,
          },
          cursor: {
            nextWalletSeq: walletSeq + 1,
            consecutiveRepeatCount: 0,
            lastRawResponseSha256: digest,
            lastSemanticFingerprint: verified ? capture.semanticFingerprint : null,
          },
          anomalyRequired: false,
        },
        event: syntheticEvent,
        nextCursor,
      };
    }
    return {
      plan: {
        kind: "SUPPRESS_AS_SIGHTING",
        cursor: { consecutiveRepeatCount: reducedCursor.consecutiveRepeatCount },
      },
      event,
      nextCursor: reducedCursor,
    };
  }

  const verified = isVerifiedParseResult(capture.parseResult);
  return {
    plan: {
      kind: "APPEND",
      observation: {
        walletSeq: event.walletSeq!,
        rawResponseSha256: digest,
        verified,
        relationship: event.relationship!,
        stateChanged: event.stateChanged,
        previousRecordedSeq: event.previousRecordedSeq,
      },
      cursor: {
        nextWalletSeq: reducedCursor.nextWalletSeq,
        consecutiveRepeatCount: 0,
        lastRawResponseSha256: digest,
        lastSemanticFingerprint: verified ? capture.semanticFingerprint : null,
      },
      anomalyRequired: event.anomalyAppended,
    },
    event,
    nextCursor: reducedCursor,
  };
};

// The persistence effect this write path drives. loadPrior reconstructs the full prior cursor for
// a stream from wallet_observation_cursors + the prior recorded observation + the accepted-state
// history (null for a fresh stream); apply commits the plan (append row / sighting bump, and the
// anomaly row when required) in one transaction. Production implementation: createSqlStreamWriterEffects in stream-writer-sql.ts.
export interface StreamWriterEffects {
  loadPrior(key: ObservationStreamKey): Promise<StreamCursor | null>;
  apply(
    key: ObservationStreamKey,
    result: CaptureWriteResult,
    capture: SequenceCapture,
  ): Promise<void>;
}

/** Options threaded from capture callers into {@link planCapture}. */
export type CaptureOptions = PlanCaptureOptions;

export interface SerializedStreamWriter {
  capture(
    key: ObservationStreamKey,
    capture: SequenceCapture,
    options?: CaptureOptions,
  ): Promise<CaptureWriteResult>;
}

// step 1: acquire a transaction-scoped serialization lock for (observer_id, wallet_public_key)
// before the read-classify-persist cycle. With no database in this phase the lock is an
// application single-flight — the exact "simpler v1" fallback step 1 names — so concurrent
// captures on ONE stream run strictly one-at-a-time and each observes the previous committed
// cursor, yielding gap-free contiguous wallet_seq (property 6). Different streams hold
// different locks and advance independently (property 7).
// ponytail: per-key in-process promise-chain mutex; a Postgres advisory xact lock replaces it in
// the runtime path when the writer runs against a real connection pool. Tails are not evicted
// — the map is bounded by the number of distinct read streams, not by capture volume.
export const createSerializedStreamWriter = (
  effects: StreamWriterEffects,
): SerializedStreamWriter => {
  const tails = new Map<string, Promise<unknown>>();

  const capture = (
    key: ObservationStreamKey,
    input: SequenceCapture,
    options?: CaptureOptions,
  ): Promise<CaptureWriteResult> => {
    const id = streamKeyId(key);
    const run = async (): Promise<CaptureWriteResult> => {
      const prior = await effects.loadPrior(key);
      const result = planCapture(prior, input, options);
      await effects.apply(key, result, input);
      return result;
    };
    // Chain onto this stream's tail so the whole read-classify-persist cycle is serialized per
    // key. `then(run, run)` runs regardless of the prior capture's outcome (serialize even after a
    // failure); the stored tail swallows rejections so one failed persist never poisons the lock
    // for later captures — the caller still receives THIS capture's rejection via `next`.
    const prevTail = tails.get(id) ?? Promise.resolve();
    const next = prevTail.then(run, run);
    tails.set(
      id,
      next.catch(() => undefined),
    );
    return next;
  };

  return { capture };
};
