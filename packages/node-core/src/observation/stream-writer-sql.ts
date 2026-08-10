// Production StreamWriterEffects for.
// Persists planCapture results against wallet_observation_cursors + gateway_observations.
// Changed-response observation ledger.

import { createHash, randomUUID } from "node:crypto";

import {
  isVerifiedParseResult,
  type SequenceCapture,
  type StreamCursor,
} from "@zucoins/generic-node-contracts/observation";

import type {
  CaptureWriteResult,
  ObservationStreamKey,
  StreamWriterEffects,
} from "./capture-writer.js";

export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

export interface ObservationRowProjection {
  readonly endpointFingerprint: string;
  readonly walletId?: string | null;
  readonly httpStatus?: number | null;
  readonly walletRole?: "sender" | "receiver" | "genesis" | null;
  readonly bAmount?: string | null;
  readonly innerPreimageText?: string | null;
  readonly step1Signature?: string | null;
  readonly step2Signature?: string | null;
  readonly completedTransactionText?: string | null;
  readonly completedTransactionSha256?: string | null;
  readonly observedAt?: Date;
}

export interface SqlStreamWriterEffectsOptions {
  readonly sql: SqlExecutor;
  readonly project: (capture: SequenceCapture) => ObservationRowProjection;
  readonly allocateObservationId?: () => string;
  readonly onAnomalyRequired?: (args: {
    readonly key: ObservationStreamKey;
    readonly observationId: string;
    readonly walletId: string | null;
    readonly priorObservationId: string | null;
    readonly result: CaptureWriteResult;
    readonly capture: SequenceCapture;
  }) => Promise<void>;
  readonly takeAdvisoryLock?: boolean;
}

interface CursorJoinRow {
  readonly next_wallet_seq: string;
  readonly consecutive_repeat_count: string;
  readonly last_recorded_observation_id: string;
  readonly last_raw_response_sha256: string;
  readonly last_semantic_fingerprint: string | null;
  readonly wallet_seq: string;
  readonly raw_response_bytes: Buffer | Uint8Array | string;
  readonly raw_response_sha256: string;
  readonly parse_result: string;
  readonly wallet_role: string | null;
  readonly s_signature: string | null;
  readonly p_signature: string | null;
  readonly semantic_fingerprint: string | null;
}

interface HistoryRow {
  readonly wallet_seq: string;
  readonly parse_result: string;
  readonly wallet_role: string | null;
  readonly s_signature: string | null;
  readonly p_signature: string | null;
  readonly semantic_fingerprint: string | null;
  readonly relationship: string;
}

/** Thrown when wallet_observation_cursors.last_recorded points at a foreign observer row. */
export class CrossObserverCursorError extends Error {
  readonly code = "CROSS_OBSERVER_CURSOR" as const;
  constructor(
    readonly observerId: string,
    readonly walletPublicKey: string,
    readonly lastRecordedObservationId: string,
  ) {
    super(
      `CROSS_OBSERVER_CURSOR: observer ${observerId} cursor last_recorded ` +
        `${lastRecordedObservationId} is not owned by this observer ` +
        `(wallet ${walletPublicKey})`,
    );
    this.name = "CrossObserverCursorError";
  }
}

const STATEMENTS = {
  ADVISORY_LOCK: `SELECT pg_advisory_xact_lock(hashtext($1::text), hashtext($2::text))`,
  // Cursor row alone — detects planted last_recorded without trusting its body.
  LOAD_CURSOR_ROW: `
    SELECT
      c.last_recorded_observation_id::text AS last_recorded_observation_id
    FROM wallet_observation_cursors c
    WHERE c.observer_id = $1::uuid
      AND c.wallet_public_key = $2
  `,
  // Same-observer fence: join requires o.observer_id = c.observer_id
  // so a planted cross-observer last_recorded cannot supply prior bytes or chain id.
  LOAD_CURSOR: `
    SELECT
      c.next_wallet_seq::text AS next_wallet_seq,
      c.consecutive_repeat_count::text AS consecutive_repeat_count,
      c.last_recorded_observation_id::text AS last_recorded_observation_id,
      c.last_raw_response_sha256,
      c.last_semantic_fingerprint,
      o.wallet_seq::text AS wallet_seq,
      o.raw_response_bytes,
      o.raw_response_sha256,
      o.parse_result::text AS parse_result,
      o.wallet_role,
      o.s_signature,
      o.p_signature,
      o.semantic_fingerprint
    FROM wallet_observation_cursors c
    JOIN gateway_observations o
      ON o.id = c.last_recorded_observation_id
     AND o.observer_id = c.observer_id
    WHERE c.observer_id = $1::uuid
      AND c.wallet_public_key = $2
  `,
  LOAD_HISTORY: `
    SELECT
      wallet_seq::text AS wallet_seq,
      parse_result::text AS parse_result,
      wallet_role,
      s_signature,
      p_signature,
      semantic_fingerprint,
      relationship::text AS relationship
    FROM gateway_observations
    WHERE observer_id = $1::uuid
      AND wallet_public_key = $2
    ORDER BY wallet_seq ASC -- contract-allow:order:frozen-sql-text
  `,
  INSERT_OBSERVATION: `
    INSERT INTO gateway_observations (
      id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
      observed_at, http_status, raw_response_bytes, raw_response_sha256,
      parse_result, relationship, semantic_fingerprint, state_changed,
      wallet_role, s_signature, p_signature, b_amount,
      inner_preimage_text, step_1_signature, step_2_signature,
      completed_transaction_text, completed_transaction_sha256,
      previous_recorded_observation_id
    ) VALUES (
      $1::uuid, $2::uuid, $3, $4::uuid, $5, $6,
      $7, $8, $9, $10,
      $11::observation_parse_result, $12::observation_relationship, $13, $14,
      $15, $16, $17, $18,
      $19, $20, $21,
      $22, $23,
      $24::uuid
    )
  `,
  UPSERT_CURSOR: `
    INSERT INTO wallet_observation_cursors (
      observer_id, wallet_id, wallet_public_key, last_recorded_observation_id,
      last_raw_response_sha256, last_semantic_fingerprint, last_seen_at,
      consecutive_repeat_count, next_wallet_seq
    ) VALUES (
      $1::uuid, $2::uuid, $3, $4::uuid,
      $5, $6, $7,
      $8, $9
    )
    ON CONFLICT (observer_id, wallet_public_key) DO UPDATE SET
      wallet_id = EXCLUDED.wallet_id,
      last_recorded_observation_id = EXCLUDED.last_recorded_observation_id,
      last_raw_response_sha256 = EXCLUDED.last_raw_response_sha256,
      last_semantic_fingerprint = EXCLUDED.last_semantic_fingerprint,
      last_seen_at = EXCLUDED.last_seen_at,
      consecutive_repeat_count = EXCLUDED.consecutive_repeat_count,
      next_wallet_seq = EXCLUDED.next_wallet_seq
  `,
  UPDATE_SIGHTING: `
    UPDATE wallet_observation_cursors
       SET consecutive_repeat_count = $3,
           last_seen_at = $4
     WHERE observer_id = $1::uuid
       AND wallet_public_key = $2
  `,
} as const;

export const STREAM_WRITER_SQL = STATEMENTS;

function toBytes(value: Buffer | Uint8Array | string): Uint8Array {
  if (typeof value === "string") {
    if (value.startsWith("\\x")) return new Uint8Array(Buffer.from(value.slice(2), "hex"));
    return new Uint8Array(Buffer.from(value, "utf8"));
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

export function createSqlStreamWriterEffects(
  options: SqlStreamWriterEffectsOptions,
): StreamWriterEffects {
  const {
    sql,
    project,
    allocateObservationId = () => randomUUID(),
    onAnomalyRequired,
    takeAdvisoryLock = true,
  } = options;

  const lastObsIdByStream = new Map<string, string>();
  const streamId = (key: ObservationStreamKey): string =>
    `${key.observerId}\0${key.walletPublicKey}`;

  const loadPrior = async (key: ObservationStreamKey): Promise<StreamCursor | null> => {
    if (takeAdvisoryLock) {
      await sql.query(STATEMENTS.ADVISORY_LOCK, [key.observerId, key.walletPublicKey]);
    }

    const cursorRowResult = await sql.query<{ last_recorded_observation_id: string }>(
      STATEMENTS.LOAD_CURSOR_ROW,
      [key.observerId, key.walletPublicKey],
    );
    if (cursorRowResult.rows.length === 0) {
      lastObsIdByStream.delete(streamId(key));
      return null;
    }

    const cursorResult = await sql.query<CursorJoinRow>(STATEMENTS.LOAD_CURSOR, [
      key.observerId,
      key.walletPublicKey,
    ]);
    if (cursorResult.rows.length === 0) {
      // Cursor exists but same-observer join missed — foreign last_recorded (or orphan id).
      lastObsIdByStream.delete(streamId(key));
      const plantedId = cursorRowResult.rows[0]!.last_recorded_observation_id;
      throw new CrossObserverCursorError(key.observerId, key.walletPublicKey, plantedId);
    }
    const row = cursorResult.rows[0]!;
    lastObsIdByStream.set(streamId(key), row.last_recorded_observation_id);

    const historyResult = await sql.query<HistoryRow>(STATEMENTS.LOAD_HISTORY, [
      key.observerId,
      key.walletPublicKey,
    ]);
    const history = historyResult.rows;
    const rawBytes = toBytes(row.raw_response_bytes);
    const verified = isVerifiedParseResult(
      row.parse_result as Parameters<typeof isVerifiedParseResult>[0],
    );

    const acceptedHistory = history.filter((h) =>
      isVerifiedParseResult(h.parse_result as Parameters<typeof isVerifiedParseResult>[0]),
    );
    const lastAccepted = acceptedHistory[acceptedHistory.length - 1];
    const lastAcceptedState =
      lastAccepted && lastAccepted.s_signature !== null && lastAccepted.semantic_fingerprint
        ? {
            isGenesis: lastAccepted.wallet_role === "genesis",
            sSignature: lastAccepted.s_signature,
            pSignature: lastAccepted.p_signature ?? "",
            semanticFingerprint: lastAccepted.semantic_fingerprint,
          }
        : null;

    const anomalyCount = history.filter(
      (h) =>
        h.relationship === "REGRESSION" ||
        h.relationship === "UNEXPLAINED_JUMP" ||
        h.relationship === "GENESIS_AFTER_HISTORY" ||
        h.relationship === "SIGNATURE_COLLISION" ||
        h.relationship === "NOT_APPLICABLE",
    ).length;

    return {
      nextWalletSeq: Number(row.next_wallet_seq),
      consecutiveRepeatCount: Number(row.consecutive_repeat_count),
      rowCount: history.length,
      anomalyCount,
      lastRecordedSeq: Number(row.wallet_seq),
      lastRecorded: {
        verified,
        rawResponseSha256: row.raw_response_sha256,
        rawResponseOctets: rawBytes.byteLength,
        rawResponseBytes: rawBytes,
      },
      lastAcceptedState,
      acceptedStateSignatureHistory: acceptedHistory
        .map((h) => h.s_signature)
        .filter((s): s is string => s !== null),
      priorHistoryHasNonGenesis: acceptedHistory.some((h) => h.wallet_role !== "genesis"),
    };
  };

  const apply = async (
    key: ObservationStreamKey,
    result: CaptureWriteResult,
    capture: SequenceCapture,
  ): Promise<void> => {
    const now = new Date();
    if (result.plan.kind === "SUPPRESS_AS_SIGHTING") {
      await sql.query(STATEMENTS.UPDATE_SIGHTING, [
        key.observerId,
        key.walletPublicKey,
        result.plan.cursor.consecutiveRepeatCount,
        now,
      ]);
      return;
    }

    const plan = result.plan;
    const obsId = allocateObservationId();
    const proj = project(capture);
    const previousId = lastObsIdByStream.get(streamId(key)) ?? null;

    const verified = plan.observation.verified;
    const isGenesis = capture.isGenesis;
    const walletRole =
      proj.walletRole ?? (verified ? (isGenesis ? "genesis" : "sender") : null);
    const semanticFp = verified ? capture.semanticFingerprint : null;
    const stateChanged = plan.observation.stateChanged;

    let sSig: string | null = null;
    let pSig: string | null = null;
    let bAmount: string | null = null;
    let inner: string | null = null;
    let step1: string | null = null;
    let step2: string | null = null;
    let completed: string | null = null;
    let completedSha: string | null = null;

    if (verified && isGenesis) {
      sSig = "";
      pSig = "";
      bAmount = "0";
    } else if (verified) {
      sSig = capture.sSignature;
      pSig = capture.pSignature;
      bAmount = proj.bAmount ?? "0";
      inner = proj.innerPreimageText ?? "{}";
      step1 = proj.step1Signature ?? capture.sSignature;
      step2 = proj.step2Signature ?? capture.sSignature;
      completed = proj.completedTransactionText ?? "{}";
      completedSha =
        proj.completedTransactionSha256 ??
        createHash("sha256").update(completed).digest("hex");
    }

    await sql.query(STATEMENTS.INSERT_OBSERVATION, [
      obsId,
      key.observerId,
      proj.endpointFingerprint,
      proj.walletId ?? null,
      key.walletPublicKey,
      plan.observation.walletSeq,
      proj.observedAt ?? now,
      proj.httpStatus ?? null,
      Buffer.from(capture.rawResponseBytes),
      plan.observation.rawResponseSha256,
      capture.parseResult,
      plan.observation.relationship,
      semanticFp,
      stateChanged,
      walletRole,
      sSig,
      pSig,
      bAmount,
      inner,
      step1,
      step2,
      completed,
      completedSha,
      previousId,
    ]);

    if (plan.anomalyRequired && onAnomalyRequired) {
      await onAnomalyRequired({
        key,
        observationId: obsId,
        walletId: proj.walletId ?? null,
        priorObservationId: previousId,
        result,
        capture,
      });
    }

    await sql.query(STATEMENTS.UPSERT_CURSOR, [
      key.observerId,
      proj.walletId ?? null,
      key.walletPublicKey,
      obsId,
      plan.cursor.lastRawResponseSha256,
      plan.cursor.lastSemanticFingerprint,
      now,
      plan.cursor.consecutiveRepeatCount,
      plan.cursor.nextWalletSeq,
    ]);

    lastObsIdByStream.set(streamId(key), obsId);
  };

  return { loadPrior, apply };
}
