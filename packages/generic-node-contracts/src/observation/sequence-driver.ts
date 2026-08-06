import {
  isVerifiedParseResult,
  type ObservationParseResult,
  type ObservationRelationship,
} from "./enums.contract.ts";
import {
  decideAppend,
  rawResponseDigest,
  rawResponseOctets,
  type ConsecutiveCandidate,
} from "./dedup-predicate.ts";
import {
  classifyRelationship,
  type AcceptedSemanticState,
} from "./relationship-classifier.ts";

/**
 * A pure, in-memory composition of the observation dedup freeze byte primitive and the observation concern.2 classifier
 * over a single read stream, used to PROVE the frozen contracts compose to the frozen
 * golden sequence outcomes (the mandatory raw-capture and dedup goldens). This is a stateless reducer — no DB, no
 * persistence, no worker. The real-PostgreSQL serialized-write test is a runtime-lane concern
 * outside CONTRACT_FREEZE (no DB seam is permitted in this package); the logical serialization
 * and per-stream sequencing invariants are proven here by passing the cursor as plain data.
 */

export interface SequenceCapture {
  readonly parseResult: ObservationParseResult;
  readonly rawResponseBytes: Uint8Array;
  readonly isGenesis: boolean;
  readonly sSignature: string;
  readonly pSignature: string;
  readonly semanticFingerprint: string;
  // Digest-collision simulation only: force the candidate digest so the exact-byte fallthrough
  // can be exercised at sequence level. When absent, the real SHA-256 of the bytes is used.
  readonly rawResponseSha256Override?: string;
}

interface RecordedRef {
  readonly verified: boolean;
  readonly rawResponseSha256: string;
  readonly rawResponseOctets: number;
  readonly rawResponseBytes: Uint8Array;
}

export interface StreamCursor {
  readonly nextWalletSeq: number;
  readonly consecutiveRepeatCount: number;
  readonly rowCount: number;
  readonly anomalyCount: number;
  readonly lastRecordedSeq: number | null;
  readonly lastRecorded: RecordedRef | null;
  readonly lastAcceptedState: AcceptedSemanticState | null;
  readonly acceptedStateSignatureHistory: readonly string[];
  readonly priorHistoryHasNonGenesis: boolean;
}

export interface SequenceEvent {
  readonly decision: "APPEND" | "SUPPRESS_AS_SIGHTING";
  readonly walletSeq: number | null;
  readonly relationship: ObservationRelationship | null;
  readonly stateChanged: boolean | null;
  readonly anomalyAppended: boolean;
  readonly previousRecordedSeq: number | null;
}

export interface SequenceResult {
  readonly events: readonly SequenceEvent[];
  readonly cursor: StreamCursor;
}

export const EMPTY_CURSOR: StreamCursor = {
  nextWalletSeq: 1,
  consecutiveRepeatCount: 0,
  rowCount: 0,
  anomalyCount: 0,
  lastRecordedSeq: null,
  lastRecorded: null,
  lastAcceptedState: null,
  acceptedStateSignatureHistory: [],
  priorHistoryHasNonGenesis: false,
};

const ANOMALOUS_RELATIONSHIPS: readonly ObservationRelationship[] = [
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
];

const toCandidate = (capture: SequenceCapture): ConsecutiveCandidate => ({
  verified: isVerifiedParseResult(capture.parseResult),
  rawResponseSha256: capture.rawResponseSha256Override ?? rawResponseDigest(capture.rawResponseBytes),
  rawResponseOctets: rawResponseOctets(capture.rawResponseBytes),
  rawResponseBytes: capture.rawResponseBytes,
});

const priorCandidate = (cursor: StreamCursor): ConsecutiveCandidate | null =>
  cursor.lastRecorded === null
    ? null
    : {
        verified: cursor.lastRecorded.verified,
        rawResponseSha256: cursor.lastRecorded.rawResponseSha256,
        rawResponseOctets: cursor.lastRecorded.rawResponseOctets,
        rawResponseBytes: cursor.lastRecorded.rawResponseBytes,
      };

const applyCapture = (cursor: StreamCursor, capture: SequenceCapture): [StreamCursor, SequenceEvent] => {
  const candidate = toCandidate(capture);
  const decision = decideAppend(priorCandidate(cursor), candidate);

  if (decision === "SUPPRESS_AS_SIGHTING") {
    const next = { ...cursor, consecutiveRepeatCount: cursor.consecutiveRepeatCount + 1 };
    return [
      next,
      {
        decision,
        walletSeq: null,
        relationship: null,
        stateChanged: null,
        anomalyAppended: false,
        previousRecordedSeq: cursor.lastRecordedSeq,
      },
    ];
  }

  const walletSeq = cursor.nextWalletSeq;
  const recorded: RecordedRef = {
    verified: candidate.verified,
    rawResponseSha256: candidate.rawResponseSha256,
    rawResponseOctets: candidate.rawResponseOctets,
    rawResponseBytes: capture.rawResponseBytes,
  };

  if (!candidate.verified) {
    const next: StreamCursor = {
      ...cursor,
      nextWalletSeq: walletSeq + 1,
      consecutiveRepeatCount: 0,
      rowCount: cursor.rowCount + 1,
      anomalyCount: cursor.anomalyCount + 1,
      lastRecordedSeq: walletSeq,
      lastRecorded: recorded,
    };
    return [
      next,
      {
        decision,
        walletSeq,
        relationship: "NOT_APPLICABLE",
        stateChanged: null,
        anomalyAppended: true,
        previousRecordedSeq: cursor.lastRecordedSeq,
      },
    ];
  }

  const nextState: AcceptedSemanticState = {
    isGenesis: capture.isGenesis,
    sSignature: capture.sSignature,
    pSignature: capture.pSignature,
    semanticFingerprint: capture.semanticFingerprint,
  };
  const classification = classifyRelationship({
    prior: cursor.lastAcceptedState,
    next: nextState,
    priorHistoryHasNonGenesis: cursor.priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory: cursor.acceptedStateSignatureHistory,
  });
  const anomalyAppended = ANOMALOUS_RELATIONSHIPS.includes(classification.relationship);

  const next: StreamCursor = {
    nextWalletSeq: walletSeq + 1,
    consecutiveRepeatCount: 0,
    rowCount: cursor.rowCount + 1,
    anomalyCount: cursor.anomalyCount + (anomalyAppended ? 1 : 0),
    lastRecordedSeq: walletSeq,
    lastRecorded: recorded,
    lastAcceptedState: nextState,
    acceptedStateSignatureHistory: [...cursor.acceptedStateSignatureHistory, capture.sSignature],
    priorHistoryHasNonGenesis: cursor.priorHistoryHasNonGenesis || !capture.isGenesis,
  };
  return [
    next,
    {
      decision,
      walletSeq,
      relationship: classification.relationship,
      stateChanged: classification.stateChanged,
      anomalyAppended,
      previousRecordedSeq: cursor.lastRecordedSeq,
    },
  ];
};

/**
 * Fold a sequence of captures for one read stream through the frozen primitive + classifier,
 * beginning from `start` (default the empty cursor). Returns the per-capture events and the
 * final cursor. Passing a returned cursor back in as `start` models restart restoration; a
 * separate `start` per stream models independent per-stream serialization.
 */
export const runObservationSequence = (
  captures: readonly SequenceCapture[],
  start: StreamCursor = EMPTY_CURSOR,
): SequenceResult => {
  let cursor = start;
  const events: SequenceEvent[] = [];
  for (const capture of captures) {
    const [nextCursor, event] = applyCapture(cursor, capture);
    cursor = nextCursor;
    events.push(event);
  }
  return { events, cursor };
};

export const appendedRelationships = (result: SequenceResult): readonly ObservationRelationship[] =>
  result.events
    .filter((event) => event.decision === "APPEND")
    .map((event) => event.relationship as ObservationRelationship);
