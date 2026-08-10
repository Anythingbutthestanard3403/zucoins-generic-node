import { randomUUID } from "node:crypto";

import type { ObservationAnomalyKind, SequenceCapture } from "@zucoins/generic-node-contracts/observation";

import type { CaptureWriteResult, ObservationStreamKey } from "./capture-writer.js";
import type { SqlExecutor } from "./stream-writer-sql.js";

export interface SqlAnomalyRecorderInput {
  readonly key: ObservationStreamKey;
  readonly observationId: string;
  readonly walletId: string | null;
  readonly priorObservationId: string | null;
  readonly result: CaptureWriteResult;
  readonly capture: SequenceCapture;
}

export type SqlAnomalyRecorder = (input: SqlAnomalyRecorderInput) => Promise<void>;

const INSERT_ANOMALY = `
  INSERT INTO observation_anomalies (
    id, observation_id, observer_id, wallet_id, wallet_public_key,
    kind, prior_observation_id, details, detected_at
  ) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5,
    $6, $7::uuid, $8, $9
  )
`;

function requiredKind(input: SqlAnomalyRecorderInput): ObservationAnomalyKind {
  if (input.result.plan.kind !== "APPEND" || !input.result.plan.anomalyRequired) {
    throw new Error("SQL anomaly recorder called for a capture that requires no anomaly");
  }
  const relationship = input.result.plan.observation.relationship;
  if (
    relationship === "REGRESSION" ||
    relationship === "UNEXPLAINED_JUMP" ||
    relationship === "GENESIS_AFTER_HISTORY" ||
    relationship === "SIGNATURE_COLLISION"
  ) {
    return relationship;
  }
  const parseResult = input.capture.parseResult;
  if (
    parseResult === "TRANSPORT_ERROR" ||
    parseResult === "MALFORMED_ENVELOPE" ||
    parseResult === "MALFORMED_TRANSACTION" ||
    parseResult === "UNVERIFIED_SIGNATURE" ||
    parseResult === "WALLET_ROLE_INVALID"
  ) {
    return parseResult;
  }
  throw new Error(
    `anomaly-required capture has no frozen anomaly kind: ${parseResult}/${relationship}`,
  );
}

/**
 * Build the one transaction-scoped anomaly appender used by every SQL observation writer.
 * The supplied executor must be the caller's open transaction; this function never opens a
 * connection. Details deliberately contain classifications and identifiers only, never body bytes.
 */
export function createSqlAnomalyRecorder(
  sql: SqlExecutor,
  allocateId: () => string = () => randomUUID(),
): SqlAnomalyRecorder {
  return async (input) => {
    const kind = requiredKind(input);
    const details =
      `parse_result=${input.capture.parseResult};` +
      `relationship=${
        input.result.plan.kind === "APPEND"
          ? input.result.plan.observation.relationship
          : "NOT_APPLICABLE"
      }`;
    await sql.query(INSERT_ANOMALY, [
      allocateId(),
      input.observationId,
      input.key.observerId,
      input.walletId,
      input.key.walletPublicKey,
      kind,
      input.priorObservationId,
      details,
      new Date(),
    ]);
  };
}

export const ANOMALY_RECORDER_SQL = { INSERT_ANOMALY } as const;
