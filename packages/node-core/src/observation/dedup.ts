// Exact-repeat comparator + anomaly-append for the observation capture pipeline
// (steps 7–10; changed-response observation ledger).
//
// Runs inside locked capture section after the cursor row is locked/created.
// Reuses the frozen contracts primitive `decideAppend` / `rawResponseDigest` — no local
// re-derivation of the digest→length→exact-byte suppression key. Suppression is only for
// consecutive verified byte-identical responses; every byte change and every anomaly
// occurrence is appended permanently, including when the anomalous bytes themselves repeat.

import {
  decideAppend,
  rawResponseDigest,
  type ConsecutiveCandidate,
  type ObservationAnomalyKind,
} from "@zucoins/generic-node-contracts/observation";

export interface ExactRepeatCursorState {
  readonly nextWalletSeq: number;
  readonly consecutiveRepeatCount: number;
  readonly lastRecorded: ConsecutiveCandidate | null;
  readonly lastSemanticFingerprint: string | null;
  readonly lastObservationId: string | null;
}

/**
 * One capture candidate handed to the comparator. Classification (parse_result /
 * relationship) is upstream; this slice only decides append-vs-suppress
 * and writes the observation + matching anomaly row.
 */
export interface ExactRepeatCandidate {
  readonly rawResponseBytes: Uint8Array;
  readonly verified: boolean;
  readonly semanticFingerprint: string | null;
  /**
   * When non-null, an `observation_anomalies` row is appended in the same transaction as
   * the observation row. For non-verified results this is the parse_result kind; for
   * verified-but-anomalous relationships it is the relationship kind (REGRESSION,
   * UNEXPLAINED_JUMP, GENESIS_AFTER_HISTORY, SIGNATURE_COLLISION). EQUIVALENT_STATE /
   * SUCCESSOR / FIRST carry null.
   */
  readonly anomalyKind: ObservationAnomalyKind | null;
  readonly anomalyDetails: string;
}

export type ExactRepeatDecision =
  | {
      readonly kind: "EXACT_REPEAT";
      readonly consecutiveRepeatCount: number;
    }
  | {
      readonly kind: "SEMANTIC_REPEAT";
      readonly walletSeq: number;
      readonly observationId: string;
      readonly rawResponseSha256: string;
    }
  | {
      readonly kind: "NEW_OBSERVATION";
      readonly walletSeq: number;
      readonly observationId: string;
      readonly rawResponseSha256: string;
      readonly anomalyAppended: boolean;
    };

export interface ObservationAppendEntry {
  readonly observationId: string;
  readonly walletSeq: number;
  readonly rawResponseBytes: Uint8Array;
  readonly rawResponseSha256: string;
  readonly verified: boolean;
  readonly semanticFingerprint: string | null;
  /** When set, the observation row is inserted with this relationship (append-only; no post-INSERT rewrite). */
  readonly relationship?:
    | "FIRST"
    | "SUCCESSOR"
    | "COMPLETE_PATH_SUCCESSOR"
    | "DUPLICATE"
    | "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"
    | "REGRESSION"
    | "UNEXPLAINED_JUMP"
    | "GENESIS_AFTER_HISTORY"
    | "SIGNATURE_COLLISION"
    | "NOT_APPLICABLE";
}

export interface AnomalyAppendEntry {
  readonly observationId: string;
  readonly kind: ObservationAnomalyKind;
  readonly priorObservationId: string | null;
  readonly details: string;
  readonly detectedAt: string;
}

/**
 * Persistence seam for the locked capture transaction. Callers (write path)
 * supply a real Postgres-backed store; tests use {@link InMemoryExactRepeatStore}.
 * All mutations for one classify call must commit atomically with the cursor lock.
 */
export interface ExactRepeatStore {
  loadCursor(streamKey: string): Promise<ExactRepeatCursorState | null>;
  recordSighting(streamKey: string, state: ExactRepeatCursorState): Promise<void>;
  appendObservation(streamKey: string, entry: ObservationAppendEntry): Promise<void>;
  appendAnomaly(streamKey: string, entry: AnomalyAppendEntry): Promise<void>;
  /** Stable id for a newly appended observation row (uuid in production). */
  allocateObservationId(): string;
  nowIso(): string;
}

const EMPTY_CURSOR: ExactRepeatCursorState = {
  nextWalletSeq: 1,
  consecutiveRepeatCount: 0,
  lastRecorded: null,
  lastSemanticFingerprint: null,
  lastObservationId: null,
};

export class ExactRepeatService {
  private readonly store: ExactRepeatStore;

  constructor(store: ExactRepeatStore) {
    this.store = store;
  }

  /**
   * Decide suppress vs append for one capture against the immediately prior recorded
   * result on this stream. On suppress: cursor counter only. On append: one
   * gateway_observations row plus, when anomalyKind is set, one observation_anomalies
   * row — even when the anomalous bytes are themselves a consecutive repeat.
   */
  async classify(
    streamKey: string,
    candidate: ExactRepeatCandidate,
  ): Promise<ExactRepeatDecision> {
    const cursor = (await this.store.loadCursor(streamKey)) ?? EMPTY_CURSOR;
    const sha256 = rawResponseDigest(candidate.rawResponseBytes);

    const dedupCandidate: ConsecutiveCandidate = {
      verified: candidate.verified,
      rawResponseSha256: sha256,
      rawResponseOctets: candidate.rawResponseBytes.length,
      rawResponseBytes: candidate.rawResponseBytes,
    };

    // Digest is a candidate index only — decideAppend still falls through to length +
    // exact-byte equality. Suppression requires BOTH sides verified.
    const decision = decideAppend(cursor.lastRecorded, dedupCandidate);

    if (decision === "SUPPRESS_AS_SIGHTING") {
      const updated: ExactRepeatCursorState = {
        ...cursor,
        consecutiveRepeatCount: cursor.consecutiveRepeatCount + 1,
      };
      await this.store.recordSighting(streamKey, updated);
      return { kind: "EXACT_REPEAT", consecutiveRepeatCount: updated.consecutiveRepeatCount };
    }

    const walletSeq = cursor.nextWalletSeq;
    const observationId = this.store.allocateObservationId();

    // Relationship is frozen at INSERT (append-only). Compute SEMANTIC before write so
    // verified A,A′ (same fingerprint, different bytes) lands as
    // EQUIVALENT_STATE_DIFFERENT_ENVELOPE — never SUCCESSOR (AA_PRIME_WRAPPER).
    const isSemanticRepeat =
      candidate.verified &&
      cursor.lastSemanticFingerprint !== null &&
      candidate.semanticFingerprint !== null &&
      candidate.semanticFingerprint === cursor.lastSemanticFingerprint &&
      candidate.anomalyKind === null;

    const relationshipAnomalies = new Set([
      "REGRESSION",
      "UNEXPLAINED_JUMP",
      "GENESIS_AFTER_HISTORY",
      "SIGNATURE_COLLISION",
    ]);
    let relationship: ObservationAppendEntry["relationship"];
    if (candidate.anomalyKind !== null && relationshipAnomalies.has(candidate.anomalyKind)) {
      relationship = candidate.anomalyKind as ObservationAppendEntry["relationship"];
    } else if (!candidate.verified) {
      relationship = "NOT_APPLICABLE";
    } else if (walletSeq === 1) {
      relationship = "FIRST";
    } else if (isSemanticRepeat) {
      relationship = "EQUIVALENT_STATE_DIFFERENT_ENVELOPE";
    } else {
      relationship = "SUCCESSOR";
    }

    await this.store.appendObservation(streamKey, {
      observationId,
      walletSeq,
      rawResponseBytes: candidate.rawResponseBytes,
      rawResponseSha256: sha256,
      verified: candidate.verified,
      semanticFingerprint: candidate.semanticFingerprint,
      relationship,
    });

    let anomalyAppended = false;
    if (candidate.anomalyKind !== null) {
      await this.store.appendAnomaly(streamKey, {
        observationId,
        kind: candidate.anomalyKind,
        priorObservationId: cursor.lastObservationId,
        details: candidate.anomalyDetails,
        detectedAt: this.store.nowIso(),
      });
      anomalyAppended = true;
    }

    // Advance cursor to the appended row (step 10). consecutive_repeat_count resets.
    await this.store.recordSighting(streamKey, {
      nextWalletSeq: walletSeq + 1,
      consecutiveRepeatCount: 0,
      lastRecorded: dedupCandidate,
      lastSemanticFingerprint: candidate.semanticFingerprint,
      lastObservationId: observationId,
    });

    if (isSemanticRepeat) {
      return {
        kind: "SEMANTIC_REPEAT",
        walletSeq,
        observationId,
        rawResponseSha256: sha256,
      };
    }

    return {
      kind: "NEW_OBSERVATION",
      walletSeq,
      observationId,
      rawResponseSha256: sha256,
      anomalyAppended,
    };
  }
}

/** In-memory store for unit tests — models the append-only observation + anomaly ledgers. */
export class InMemoryExactRepeatStore implements ExactRepeatStore {
  private readonly cursors = new Map<string, ExactRepeatCursorState>();
  private readonly observations: Array<ObservationAppendEntry & { streamKey: string }> = [];
  private readonly anomalies: Array<AnomalyAppendEntry & { streamKey: string }> = [];
  private idCounter = 0;
  private readonly clock: () => string;

  constructor(opts: { nowIso?: () => string } = {}) {
    this.clock = opts.nowIso ?? (() => "2026-01-01T00:00:00.000Z");
  }

  loadCursor(streamKey: string): Promise<ExactRepeatCursorState | null> {
    return Promise.resolve(this.cursors.get(streamKey) ?? null);
  }

  recordSighting(streamKey: string, state: ExactRepeatCursorState): Promise<void> {
    this.cursors.set(streamKey, state);
    return Promise.resolve();
  }

  appendObservation(streamKey: string, entry: ObservationAppendEntry): Promise<void> {
    this.observations.push({ streamKey, ...entry });
    return Promise.resolve();
  }

  appendAnomaly(streamKey: string, entry: AnomalyAppendEntry): Promise<void> {
    this.anomalies.push({ streamKey, ...entry });
    return Promise.resolve();
  }

  allocateObservationId(): string {
    this.idCounter += 1;
    return `obs-${this.idCounter}`;
  }

  nowIso(): string {
    return this.clock();
  }

  getObservations(): readonly (ObservationAppendEntry & { streamKey: string })[] {
    return this.observations;
  }

  getAnomalies(): readonly (AnomalyAppendEntry & { streamKey: string })[] {
    return this.anomalies;
  }

  getCursor(streamKey: string): ExactRepeatCursorState | null {
    return this.cursors.get(streamKey) ?? null;
  }
}
