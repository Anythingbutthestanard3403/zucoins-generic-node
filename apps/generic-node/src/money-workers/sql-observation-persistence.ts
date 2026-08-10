import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";

import {
  applyAnomalyAction,
  createSerializedStreamWriter,
  createSqlAnomalyRecorder,
  createSqlStreamWriterEffects,
  planActionForRelationship,
  type AnomalyQuarantineStore,
  type ObservationRowProjection,
  type QuarantineOperationSnapshot,
  type QuarantineWalletSnapshot,
} from "@zucoins/node-core";
import type {
  ObservationRelationship,
  SequenceCapture,
} from "@zucoins/generic-node-contracts/observation";

import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";
import { applyMoneyPathStatementTimeout } from "../db/client.js";

export async function ensureNodeObserver(
  client: PoolClient,
  nodeId: string,
  endpointFingerprint: string,
): Promise<string> {
  const existing = await client.query<{ id: string }>(
    `SELECT id::text AS id FROM observers
      WHERE domain = 'NODE' AND owner_id = $1::uuid LIMIT 1`,
    [nodeId],
  );
  if (existing.rows[0]?.id !== undefined) return existing.rows[0].id;
  const observerId = randomUUID();
  await client.query(
    `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
     VALUES ($1::uuid, 'NODE', $2::uuid, $3, now())
     ON CONFLICT (domain, owner_id) DO NOTHING`,
    [observerId, nodeId, endpointFingerprint],
  );
  const again = await client.query<{ id: string }>(
    `SELECT id::text AS id FROM observers
      WHERE domain = 'NODE' AND owner_id = $1::uuid LIMIT 1`,
    [nodeId],
  );
  return again.rows[0]?.id ?? observerId;
}

function sqlStore(client: PoolClient, nodeId: string): AnomalyQuarantineStore {
  const getWallet = async (walletId: string): Promise<QuarantineWalletSnapshot | null> => {
    const result = await client.query<{
      id: string;
      state: QuarantineWalletSnapshot["state"];
      quarantine_reason: string | null;
      active_lease_id: string | null;
    }>(
      `SELECT w.id::text AS id, w.state::text AS state, w.quarantine_reason,
              l.membership_id::text AS active_lease_id
         FROM wallets w LEFT JOIN wallet_active_leases l ON l.wallet_id = w.id
        WHERE w.id = $1::uuid FOR UPDATE OF w`,
      [walletId],
    );
    const row = result.rows[0];
    return row === undefined
      ? null
      : {
          walletId: row.id,
          state: row.state,
          quarantineReason: row.quarantine_reason,
          activeLeaseId: row.active_lease_id,
          signingHalted: row.state === "QUARANTINED" || row.state === "RETIRED",
        };
  };
  const getOperation = async (operationId: string): Promise<QuarantineOperationSnapshot | null> => {
    const result = await client.query<{
      id: string;
      kind: QuarantineOperationSnapshot["kind"];
      status: QuarantineOperationSnapshot["status"];
      attention_required: boolean;
      attention_reason: QuarantineOperationSnapshot["attentionReason"];
      wallet_id: string | null;
    }>(
      `SELECT o.id::text AS id, o.kind::text AS kind, o.status::text AS status,
              o.attention_required, o.attention_reason,
              COALESCE(o.source_wallet_id, o.receiver_wallet_id)::text AS wallet_id
         FROM operations o WHERE o.id = $1::uuid FOR UPDATE`,
      [operationId],
    );
    const row = result.rows[0];
    return row === undefined
      ? null
      : {
          operationId: row.id,
          walletId: row.wallet_id,
          kind: row.kind,
          status: row.status,
          attentionRequired: row.attention_required,
          attentionReason: row.attention_reason,
          attentionEpisode: row.attention_required ? 1 : 0,
        };
  };
  return {
    getWallet,
    getOperation,
    async quarantineWallet(walletId, reason) {
      await client.query(
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = $2
          WHERE id = $1::uuid AND state <> 'RETIRED'`,
        [walletId, reason],
      );
      const row = await getWallet(walletId);
      if (row === null) throw new Error(`wallet ${walletId} not found`);
      return row;
    },
    async quarantineCandidate(walletId) {
      const row = await getWallet(walletId);
      if (row === null) throw new Error(`wallet ${walletId} not found`);
      return row;
    },
    async haltWalletSigning(walletId) {
      await client.query(
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'GATEWAY_ENDPOINT_DISAGREEMENT'
          WHERE id = $1::uuid AND state <> 'RETIRED'`,
        [walletId],
      );
      const row = await getWallet(walletId);
      if (row === null) throw new Error(`wallet ${walletId} not found`);
      return row;
    },
    async markNeedsAttention(operationId, reason) {
      const prior = await getOperation(operationId);
      if (prior === null) throw new Error(`operation ${operationId} not found`);
      const targetStatus = prior.kind === "RECEIVE_EXTERNAL" ? prior.status : "NEEDS_ATTENTION";
      await client.query(
        `UPDATE operations
            SET status = $2::operation_status, attention_required = true,
                attention_reason = $3, row_version = row_version + 1, updated_at = now()
          WHERE id = $1::uuid
            AND status NOT IN ('RECEIVE_LANDED','INTERNAL_MOVE_LANDED','EXTERNAL_SEND_LANDED','REJECTED')`,
        [operationId, targetStatus, reason],
      );
      const next = await getOperation(operationId);
      if (next === null) throw new Error(`operation ${operationId} not found`);
      return { operation: next, mutated: next.attentionRequired };
    },
    async appendAudit(entry) {
      const details = `anomaly=${entry.anomaly};detail=${entry.detail}`;
      await client.query(
        `INSERT INTO audit_log (
           id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
           details_text, details_sha256, created_at
         ) VALUES ($1::uuid, $2::uuid, 'SYSTEM', NULL, $3, $4::uuid, $5::uuid,
                   $6, $7, $8)`,
        [
          randomUUID(),
          nodeId,
          entry.action,
          entry.operationId,
          entry.walletId,
          details,
          createHash("sha256").update(details).digest("hex"),
          new Date(entry.atMs),
        ],
      );
    },
    async runAtomic(fn) {
      return await fn();
    },
    async listEvidence() {
      return [];
    },
  };
}

export interface PersistSqlObservationInput {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly walletPublicKey: string;
  readonly moneyPathStatementTimeoutMs?: number;
  readonly endpointFingerprint: string;
  readonly httpStatus: number | null;
  readonly capture: SequenceCapture;
  readonly projection: Omit<
    ObservationRowProjection,
    "endpointFingerprint" | "walletId" | "httpStatus" | "observedAt"
  >;
}

export interface PersistSqlObservationResult {
  readonly observationId: string;
  readonly relationship: ObservationRelationship;
}

/** Observation, paired anomaly, quarantine/attention and cursor commit in one PG transaction. */
export async function persistSqlObservation(
  input: PersistSqlObservationInput,
): Promise<PersistSqlObservationResult> {
  const client = await input.pool.connect();
  try {
    await client.query("BEGIN");
    await applyMoneyPathStatementTimeout(
      client,
      input.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT,
    );
    const observerId = await ensureNodeObserver(client, input.nodeId, input.endpointFingerprint);
    const wallet = await client.query<{ id: string }>(
      `SELECT id::text AS id FROM wallets WHERE public_key = $1 LIMIT 1`,
      [input.walletPublicKey],
    );
    const walletId = wallet.rows[0]?.id ?? null;
    const tx = {
      query: async <R>(text: string, params: readonly unknown[]) => {
        const result = await client.query(text, params as never[]);
        return { rows: result.rows as R[] };
      },
    };
    const recordAnomaly = createSqlAnomalyRecorder(tx);
    let allocatedObservationId: string | null = null;
    const effects = createSqlStreamWriterEffects({
      sql: tx,
      project: () => ({
        endpointFingerprint: input.endpointFingerprint,
        walletId,
        httpStatus: input.httpStatus,
        observedAt: new Date(),
        ...input.projection,
      }),
      allocateObservationId: () => {
        allocatedObservationId = randomUUID();
        return allocatedObservationId;
      },
      onAnomalyRequired: async (args) => {
        await recordAnomaly(args);
        if (args.result.plan.kind !== "APPEND" || walletId === null) return;
        const relationship = args.result.plan.observation.relationship;
        if (
          relationship !== "REGRESSION" &&
          relationship !== "UNEXPLAINED_JUMP" &&
          relationship !== "GENESIS_AFTER_HISTORY" &&
          relationship !== "SIGNATURE_COLLISION"
        ) {
          return;
        }
        const lease = await client.query<{ operation_id: string }>(
          `SELECT operation_id::text AS operation_id FROM wallet_active_leases
            WHERE wallet_id = $1::uuid`,
          [walletId],
        );
        await applyAnomalyAction(sqlStore(client, input.nodeId), {
          plan: planActionForRelationship(relationship),
          walletId,
          operationId: lease.rows[0]?.operation_id ?? null,
        });
      },
      takeAdvisoryLock: true,
    });
    const written = await createSerializedStreamWriter(effects).capture(
      { observerId, walletPublicKey: input.walletPublicKey },
      input.capture,
    );
    let observationId: string | null = allocatedObservationId as string | null;
    if (written.plan.kind === "SUPPRESS_AS_SIGHTING") {
      const tip = await client.query<{ id: string }>(
        `SELECT last_recorded_observation_id::text AS id FROM wallet_observation_cursors
          WHERE observer_id = $1::uuid AND wallet_public_key = $2`,
        [observerId, input.walletPublicKey],
      );
      observationId = tip.rows[0]?.id ?? null;
    }
    if (observationId === null) throw new Error("stream writer produced no observation id");
    await client.query("COMMIT");
    return {
      observationId,
      relationship:
        written.plan.kind === "APPEND" ? written.plan.observation.relationship : "NOT_APPLICABLE",
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // preserve original
    }
    throw error;
  } finally {
    client.release();
  }
}
