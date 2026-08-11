/**
 * Consumer-owned append-only changed-response ledger (doc 10 §6.2).
 *
 * Consecutive-only exact-byte dedup via the contracts package predicate
 * (`decideAppend`). A returning earlier state (A,B,C,A) always appends the
 * final A — never suppressed as a global duplicate. Anomalies always append.
 */

import {
  decideAppend,
  rawResponseDigest,
  rawResponseOctets,
  type AppendOutcome,
  type ConsecutiveCandidate,
} from "@zucoins/generic-node-contracts/observation";

export type ChangedResponseRecordKind = "RECORDED" | "ANOMALY";

export interface ChangedResponseRecord {
  readonly seq: number;
  readonly kind: ChangedResponseRecordKind;
  readonly rawResponseBytes: Uint8Array;
  readonly rawResponseSha256: string;
  readonly rawResponseOctets: number;
  readonly verified: boolean;
  /** True when this record re-introduces a previously-seen digest after an intervening change. */
  readonly regression: boolean;
  readonly observedAtUnixMs: number;
  readonly anomalyKind?: string;
  readonly anomalyDetail?: string;
}

export interface ChangedResponseAppendInput {
  readonly rawResponseBytes: Uint8Array;
  readonly verified: boolean;
  readonly observedAtUnixMs: number;
  /** When set (or verified=false), the capture always appends as ANOMALY. */
  readonly anomalyKind?: string;
  readonly anomalyDetail?: string;
}

export type ChangedResponseAppendResult =
  | {
      readonly outcome: "APPEND";
      readonly record: ChangedResponseRecord;
      readonly decision: AppendOutcome;
    }
  | {
      readonly outcome: "SUPPRESS_AS_SIGHTING";
      readonly decision: AppendOutcome;
      readonly consecutiveRepeatCount: number;
    };

export interface ChangedResponseLedger {
  /** Append-only history of RECORDED / ANOMALY rows (suppressed sightings are not stored). */
  readonly records: readonly ChangedResponseRecord[];
  append(input: ChangedResponseAppendInput): ChangedResponseAppendResult;
  /** Immediately prior RECORDED row, or null when the stream has none. */
  priorRecorded(): ChangedResponseRecord | null;
}

function toCandidate(input: {
  readonly rawResponseBytes: Uint8Array;
  readonly verified: boolean;
}): ConsecutiveCandidate {
  return {
    verified: input.verified,
    rawResponseSha256: rawResponseDigest(input.rawResponseBytes),
    rawResponseOctets: rawResponseOctets(input.rawResponseBytes),
    rawResponseBytes: input.rawResponseBytes,
  };
}

/**
 * In-memory append-only ledger. Products may reimplement the interface against durable storage;
 * the consecutive-dedup rule must stay byte-identical to `decideAppend`.
 */
export function createInMemoryChangedResponseLedger(): ChangedResponseLedger {
  const records: ChangedResponseRecord[] = [];
  let consecutiveRepeatCount = 0;
  /** Digests ever RECORDED (verified, non-anomaly) — used only to flag regression, never to suppress. */
  const seenVerifiedDigests = new Set<string>();

  const priorRecorded = (): ChangedResponseRecord | null => {
    for (let i = records.length - 1; i >= 0; i -= 1) {
      if (records[i]!.kind === "RECORDED") return records[i]!;
    }
    return null;
  };

  return {
    get records() {
      return records;
    },
    priorRecorded,
    append(input) {
      const next = toCandidate(input);
      const isAnomaly = !input.verified || input.anomalyKind !== undefined;

      // Anomalies always append — even on repeated bytes (RETENTION_RULE.anomalies_always_append).
      if (isAnomaly) {
        consecutiveRepeatCount = 0;
        const record: ChangedResponseRecord = {
          seq: records.length + 1,
          kind: "ANOMALY",
          rawResponseBytes: input.rawResponseBytes,
          rawResponseSha256: next.rawResponseSha256,
          rawResponseOctets: next.rawResponseOctets,
          verified: input.verified,
          regression: false,
          observedAtUnixMs: input.observedAtUnixMs,
          anomalyKind: input.anomalyKind ?? "UNVERIFIED",
          anomalyDetail: input.anomalyDetail,
        };
        records.push(record);
        return { outcome: "APPEND", record, decision: "APPEND" };
      }

      const prior = priorRecorded();
      const priorCandidate: ConsecutiveCandidate | null =
        prior === null
          ? null
          : {
              verified: prior.verified,
              rawResponseSha256: prior.rawResponseSha256,
              rawResponseOctets: prior.rawResponseOctets,
              rawResponseBytes: prior.rawResponseBytes,
            };
      const decision = decideAppend(priorCandidate, next);
      if (decision === "SUPPRESS_AS_SIGHTING") {
        consecutiveRepeatCount += 1;
        return { outcome: "SUPPRESS_AS_SIGHTING", decision, consecutiveRepeatCount };
      }

      consecutiveRepeatCount = 0;
      const regression =
        seenVerifiedDigests.has(next.rawResponseSha256) &&
        (prior === null || prior.rawResponseSha256 !== next.rawResponseSha256);
      seenVerifiedDigests.add(next.rawResponseSha256);
      const record: ChangedResponseRecord = {
        seq: records.length + 1,
        kind: "RECORDED",
        rawResponseBytes: input.rawResponseBytes,
        rawResponseSha256: next.rawResponseSha256,
        rawResponseOctets: next.rawResponseOctets,
        verified: true,
        regression,
        observedAtUnixMs: input.observedAtUnixMs,
      };
      records.push(record);
      return { outcome: "APPEND", record, decision };
    },
  };
}
