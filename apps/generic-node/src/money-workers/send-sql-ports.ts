// SQL/composition ports for SEND post-approve formation.
// Mirror send_operations → operations (approval_challenges FK) + claim/lease/partial/form ports.

import type { Pool } from "pg";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";

import {
  CLAIM_AND_OBSERVE_SQL,
  acquireLeases,
  advanceAttemptPhase,
  buildMoveStep2PreimageText,
  createLeaseGroup,
  hashMovePreimageText,
  appendDurableDualChainEvent,
  persistSendPartialSql,
  persistSendSignIntentSql,
  recordPartialDelivery,
  recordWalletSettledLedger,
  writeExactHeadLineagePath,
  SqlExternalSendLandingStore,
  type ApprovedSendClaim,
  type ApprovedSendClaimPort,
  type ApprovalIdLoader,
  type CommitExternalSendLandingCommand,
  type DualChainEventQuota,
  type ExternalSendLandingStore,
  type ExternalSendPartialDelivery,
  type ExternalSendPartialLoader,
  type HeldSourceLease,
  type NodeEventSigner,
  type PartialPersistPort,
  type SignIntentPersistPort,
  type SourceLeasePort,
  type TryAcquireSourceLeaseResult,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { issueLandedAccessWindow } from "./issue-landed-access-window.js";

type SqlTx = {
  query: <R>(
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: R[]; rowCount: number | null }>;
};

export async function withPoolTransaction<T>(
  pool: Pool,
  fn: (tx: SqlTx) => Promise<T>,
  statementTimeoutMs: number = MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await applyMoneyPathStatementTimeout(client, statementTimeoutMs);
    const tx: SqlTx = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await client.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    const out = await fn(tx);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* original */
    }
    throw err;
  } finally {
    client.release();
  }
}

function poolQueryFn(pool: Pool): SqlQueryFn {
  return async (text, params) => {
    const result = await pool.query(text, params as never);
    return result.rows as Record<string, unknown>[];
  };
}

function txQueryFn(tx: SqlTx): SqlQueryFn {
  return async (text, params) => {
    const result = await tx.query(text, params);
    return result.rows as Record<string, unknown>[];
  };
}

/** Mirror CREATED/APPROVED send_operations rows into operations for approval FK + material. */
export async function mirrorSendOperationsToOperations(
  pool: Pool,
  logger: { info(message: string): void },
): Promise<number> {
  const result = await pool.query(
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, amount_zkz,
       source_wallet_id, destination_address,
       references_operation_id, client_reference, description,
       idempotency_key, request_sha256, formation_state,
       verification_mode
     )
     SELECT
       s.operation_id,
       s.node_id,
       s.implementer_id,
       'SEND_EXTERNAL'::operation_kind,
       s.status::operation_status,
       s.amount_zkz,
       s.source_wallet_id,
       s.destination_address,
       s.references_operation_id,
       s.client_reference,
       s.description,
       s.idempotency_key,
       s.request_sha256,
       s.formation_state::external_formation_state,
       s.verification_mode
     FROM send_operations s
     WHERE s.status IN ('CREATED', 'APPROVED', 'AWAITING_REDEMPTION')
       AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.id = s.operation_id)
     ON CONFLICT DO NOTHING`,
  );
  const n = result.rowCount ?? 0;
  if (n > 0) {
    logger.info(`money-workers: mirrored ${n} send_operations → operations`);
  }
  return n;
}

/** Keep operations lockstep status/formation when send_operations advances. */
export async function syncOperationsMirrorFromSend(
  pool: Pool,
  operationId: string,
): Promise<void> {
  await pool.query(
    `UPDATE operations o
        SET status = s.status::operation_status,
            formation_state = s.formation_state::external_formation_state,
            row_version = s.row_version,
            updated_at = now()
       FROM send_operations s
      WHERE s.operation_id = $1::uuid
        AND o.id = s.operation_id
        AND o.kind = 'SEND_EXTERNAL'`,
    [operationId],
  );
}

export async function loadApprovedUnsignedSendIds(pool: Pool): Promise<readonly string[]> {
  // ZTR-1270: park formation until referenced top-up MOVE is INTERNAL_MOVE_LANDED.
  const result = await pool.query<{ operation_id: string }>(
    `SELECT s.operation_id::text AS operation_id
       FROM send_operations s
      WHERE s.status = 'APPROVED'
        AND s.formation_state = 'APPROVED_UNSIGNED'
        AND (
              s.references_operation_id IS NULL
           OR EXISTS (
                SELECT 1
                  FROM operations m
                 WHERE m.id = s.references_operation_id
                   AND m.kind = 'MOVE_INTERNAL'
                   AND m.status = 'INTERNAL_MOVE_LANDED'
              )
            )
      ORDER BY s.created_at ASC, s.operation_id ASC -- contract-allow:order:frozen structural vocabulary
      LIMIT 10`,
  );
  return result.rows.map((r) => r.operation_id);
}

/** CREATED + APPROVAL_PENDING candidates for auto-approve (ZTR-1235). Bounded batch. */
export interface ApprovalPendingSendCandidate {
  readonly operationId: string;
  readonly implementerId: string;
  readonly amountZkz: string;
}

const AUTO_APPROVE_PENDING_BATCH = 100;

export async function loadApprovalPendingSendCandidates(
  pool: Pool,
): Promise<readonly ApprovalPendingSendCandidate[]> {
  // ZTR-1270: auto-approve only after source is known AND top-up MOVE (if any) has landed.
  const result = await pool.query<{
    operation_id: string;
    implementer_id: string;
    amount_zkz: string;
  }>(
    `SELECT s.operation_id::text AS operation_id,
            s.implementer_id::text AS implementer_id,
            s.amount_zkz::text AS amount_zkz
       FROM send_operations s
      WHERE s.status = 'CREATED'
        AND s.formation_state = 'APPROVAL_PENDING'
        AND (
              s.references_operation_id IS NULL
           OR EXISTS (
                SELECT 1
                  FROM operations m
                 WHERE m.id = s.references_operation_id
                   AND m.kind = 'MOVE_INTERNAL'
                   AND m.status = 'INTERNAL_MOVE_LANDED'
              )
            )
      ORDER BY s.created_at ASC, s.operation_id ASC -- contract-allow:order:frozen structural vocabulary
      LIMIT ${AUTO_APPROVE_PENDING_BATCH}`,
  );
  return result.rows.map((r) => ({
    operationId: r.operation_id,
    implementerId: r.implementer_id,
    amountZkz: r.amount_zkz,
  }));
}

export function createSqlApprovedSendClaimPort(pool: Pool): ApprovedSendClaimPort {
  return {
    async claimApproved(operationId: string) {
      return withPoolTransaction(pool, async (tx) => {
        const result = await tx.query<{
          operation_id: string;
          status: string;
          formation_state: string;
          row_version: string | number;
          source_wallet_id: string;
          source_pubkey: string;
          destination_address: string;
          amount_zkz: string;
        }>(CLAIM_AND_OBSERVE_SQL.CLAIM_APPROVED_SEND_OPERATION, [operationId]);
        const row = result.rows[0];
        if (row === undefined) {
          return {
            outcome: "NOT_CLAIMABLE" as const,
            detail: "row not APPROVED/APPROVED_UNSIGNED",
          };
        }
        const claim: ApprovedSendClaim = {
          operationId: row.operation_id,
          status: "APPROVED",
          formationState: "APPROVED_UNSIGNED",
          rowVersion: Number(row.row_version),
          sourceWalletId: row.source_wallet_id,
          sourcePubkey: row.source_pubkey,
          destinationAddress: row.destination_address,
          amountZkz: row.amount_zkz,
        };
        return { outcome: "CLAIMED" as const, claim };
      });
    },
  };
}

export function createSqlSendSourceLeasePort(pool: Pool, ownerInstanceId: string): SourceLeasePort {
  return {
    async tryAcquireSourceLease(input): Promise<TryAcquireSourceLeaseResult> {
      try {
        return await withPoolTransaction(pool, async (tx) => {
          // Already held by this operation?
          const existing = await tx.query<{
            membership_id: string;
            lease_group_id: string;
            lease_epoch: string;
          }>(
            `SELECT membership_id::text AS membership_id,
                    lease_group_id::text AS lease_group_id,
                    lease_epoch::text AS lease_epoch
               FROM wallet_active_leases
              WHERE wallet_id = $1::uuid
                AND operation_id = $2::uuid
                AND lease_role = 'SEND_SOURCE'
              LIMIT 1`,
            [input.sourceWalletId, input.operationId],
          );
          const heldRow = existing.rows[0];
          if (heldRow !== undefined) {
            const held: HeldSourceLease = {
              walletId: input.sourceWalletId,
              membershipId: heldRow.membership_id,
              leaseGroupId: heldRow.lease_group_id,
              leaseEpoch: BigInt(heldRow.lease_epoch),
              operationId: input.operationId,
              lease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
            };
            return { outcome: "ALREADY_HELD", held };
          }

          const busy = await tx.query<{ operation_id: string }>(
            `SELECT operation_id::text AS operation_id
               FROM wallet_active_leases
              WHERE wallet_id = $1::uuid
              LIMIT 1`,
            [input.sourceWalletId],
          );
          if (busy.rows[0] !== undefined && busy.rows[0].operation_id !== input.operationId) {
            return {
              outcome: "BUSY",
              detail: `wallet leased by ${busy.rows[0].operation_id}`,
            };
          }

          const leaseGroupId = await createLeaseGroup(tx, { rootOperationId: input.operationId });
          const [lease] = await acquireLeases(tx, {
            wallets: [{ walletId: input.sourceWalletId, leaseRole: "SEND_SOURCE" }],
            leaseGroupId,
            rootOperationId: input.operationId,
            operationId: input.operationId,
            ownerInstanceId: input.ownerInstanceId || ownerInstanceId,
          });
          if (lease === undefined) {
            return {
              outcome: "REJECTED",
              reason: "acquire_empty",
              detail: "acquireLeases returned no SEND_SOURCE membership",
            };
          }
          const held: HeldSourceLease = {
            walletId: input.sourceWalletId,
            membershipId: lease.membershipId,
            leaseGroupId,
            leaseEpoch: lease.leaseEpoch,
            operationId: input.operationId,
            lease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
          };
          return { outcome: "ACQUIRED", held };
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (/busy|conflict|WALLET_LEASE|unique/i.test(message)) {
          return { outcome: "BUSY", detail: message };
        }
        return { outcome: "REJECTED", reason: "lease_error", detail: message };
      }
    },
  };
}

export function createSqlApprovalIdLoader(pool: Pool): ApprovalIdLoader {
  return {
    async loadConsumedApprovalId(operationId: string) {
      const result = await pool.query<{ id: string }>(
        `SELECT id::text AS id FROM operation_approvals
          WHERE operation_id = $1::uuid LIMIT 1`,
        [operationId],
      );
      return result.rows[0]?.id ?? null;
    },
  };
}

export function createSqlSignIntentPort(pool: Pool): SignIntentPersistPort {
  return {
    async commitSignIntent(input) {
      return withPoolTransaction(pool, async (tx) => {
        const result = await persistSendSignIntentSql(txQueryFn(tx), input);
        if (result.ok) {
          await syncOperationsMirrorFromSendInTx(tx, input.claim.operationId);
        }
        return result;
      });
    },
  };
}

export interface SqlPartialPortDeps {
  readonly pool: Pool;
  /** Node id that owns the dual-chain seq counters. */
  readonly nodeId: string;
  /** Sealed EVENT_SIGNING signer; null refuses the AWAITING_REDEMPTION transition. */
  readonly eventSigner: () => NodeEventSigner | null;
  readonly eventQuota?: DualChainEventQuota;
}

/**
 * Post-sign partial port: persists the partial + CAS to AWAITING_REDEMPTION and appends
 * `external_send.awaiting_redemption` on both signed chains in the same commit (ZTR-1146).
 * The transfer code must not become visible before this commit succeeds.
 */
export function createSqlPartialPort(deps: SqlPartialPortDeps | Pool): PartialPersistPort {
  // Back-compat for unit tests that still pass a bare Pool (no dual-chain append).
  const config: SqlPartialPortDeps =
    typeof (deps as Pool).query === "function" && !("pool" in (deps as object))
      ? {
          pool: deps as Pool,
          nodeId: "",
          eventSigner: () => null,
        }
      : (deps as SqlPartialPortDeps);

  return {
    async commitPartialAndAwaitRedemption(input) {
      return withPoolTransaction(config.pool, async (tx) => {
        const result = await persistSendPartialSql(txQueryFn(tx), input);
        if (!result.ok) return result;

        await syncOperationsMirrorFromSendInTx(tx, input.intent.operationId);

        // Production wiring always supplies nodeId + signer. Empty nodeId is the bare-Pool
        // test path — skip dual-chain so pure SQL drills stay driver-local.
        if (config.nodeId === "") {
          return result;
        }

        const signer = config.eventSigner();
        if (signer === null) {
          throw new Error(
            `money-workers: external_send.awaiting_redemption NOT appended op=${input.intent.operationId} — EVENT_SIGNING signer unavailable; refusing AWAITING_REDEMPTION (Byte-exact)`,
          );
        }

        const owner = await tx.query<{
          implementer_id: string;
          source_wallet_id: string | null;
        }>(
          `SELECT implementer_id::text AS implementer_id,
                  source_wallet_id::text AS source_wallet_id
             FROM send_operations
            WHERE operation_id = $1::uuid`,
          [input.intent.operationId],
        );
        const row = owner.rows[0];
        if (row === undefined) {
          throw new Error(
            `money-workers: external_send.awaiting_redemption NOT appended op=${input.intent.operationId} — send_operations row missing after CAS`,
          );
        }

        const dataText = JSON.stringify({
          operation_id: input.intent.operationId,
          transfer_code_sha256: result.transferCodeSha256,
          redemption_expiry_at: input.intent.redemptionExpiryAt,
          awaiting_at: input.persistedAt,
        });
        await appendDurableDualChainEvent(txQueryFn(tx), {
          nodeId: config.nodeId,
          implementerId: row.implementer_id,
          operationId: input.intent.operationId,
          walletId: row.source_wallet_id,
          eventType: "external_send.awaiting_redemption",
          dataText,
          createdAt: input.persistedAt,
          signer,
          ...(config.eventQuota !== undefined ? { quota: config.eventQuota } : {}),
        });
        return result;
      });
    },
  };
}

async function syncOperationsMirrorFromSendInTx(tx: SqlTx, operationId: string): Promise<void> {
  await tx.query(
    `UPDATE operations o
        SET status = s.status::operation_status,
            formation_state = s.formation_state::external_formation_state,
            row_version = s.row_version,
            updated_at = now()
       FROM send_operations s
      WHERE s.operation_id = $1::uuid
        AND o.id = s.operation_id
        AND o.kind = 'SEND_EXTERNAL'`,
    [operationId],
  );
}

export function createSqlSendPartialLoader(pool: Pool): ExternalSendPartialLoader {
  return {
    async loadPartial(operationId: string): Promise<ExternalSendPartialDelivery | null> {
      const result = await pool.query<{
        transfer_code_text: string;
        transfer_code_sha256: string;
        redemption_expiry_at: Date | string | null;
      }>(
        `SELECT p.transfer_code_text,
                p.transfer_code_sha256,
                i.redemption_expiry_at
           FROM external_send_partials p
           LEFT JOIN external_send_sign_intents i ON i.operation_id = p.operation_id
          WHERE p.operation_id = $1::uuid`,
        [operationId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      const availableUntil =
        row.redemption_expiry_at === null || row.redemption_expiry_at === undefined
          ? null
          : typeof row.redemption_expiry_at === "string"
            ? row.redemption_expiry_at
            : row.redemption_expiry_at.toISOString();
      return {
        transferCodeText: row.transfer_code_text,
        transferCodeSha256: row.transfer_code_sha256,
        availableUntil,
      };
    },
  };
}

export function createSqlPartialDeliveryMarker(pool: Pool) {
  return {
    async markFirstDelivered(operationId: string, deliveredAt: string) {
      const q = poolQueryFn(pool);
      try {
        await recordPartialDelivery(q, operationId, deliveredAt);
        // PARTIAL_DELIVERED lockstep for delivery boundary (allows both).
        await pool.query(
          `UPDATE send_operations
              SET formation_state = 'PARTIAL_DELIVERED',
                  row_version = row_version + 1
            WHERE operation_id = $1::uuid
              AND status = 'AWAITING_REDEMPTION'
              AND formation_state = 'PARTIAL_PERSISTED'`,
          [operationId],
        );
        await syncOperationsMirrorFromSend(pool, operationId);
        return "delivered" as const;
      } catch {
        return "missing" as const;
      }
    },
  };
}

/**
 * The composition-root `ExternalSendLandingStore` for the send landing commit.
 *
 * node-core owns the landing statements (SqlExternalSendLandingStore: guarded status CAS →
 * landing record → event → lease presence check). This wrapper opens ONE pg transaction,
 * runs those statements on it, and adds the one thing the landing commit requires that is not in
 * node-core's slice — the operations mirror sync (status, terminal_observation_id,
 * row_version, updated_at) — inside the same transaction, so the send_operations transition
 * and the operations mirror commit together or not at all (lockstep).
 *
 * The source lease is NOT released here (release is verification-complete).
 */
/**
 * The signer stand-in used when no EVENT_SIGNING key was supplied. See the twin in
 * sql-landing-store.ts: it throws instead of signing, which aborts the landing transaction,
 * because a landed status and its signed node/implementer event rows commit together (Byte-exact).
 */
const UNAVAILABLE_EVENT_SIGNER: NodeEventSigner = {
  signingKeyId: "00000000-0000-0000-0000-000000000000",
  sign(): string {
    throw new Error(
      "external-send landing requires an EVENT_SIGNING signer: the landed status and its " +
        "signed node_events/implementer_events rows commit together (Byte-exact). Pass the " +
        "node's event signer to createSqlExternalSendLandingStore.",
    );
  },
};


/**
 * SEND parks at STEP1_SIGNATURE_PERSISTED (partial only). Landing
 * observes the destination-completed body on-chain and must promote operation_transactions
 * through STEP2_* with that exact body before wallet_settled_ledger / lineage can bind
 * (one-way attempt ladder; ledger writer requires completed_transaction_*).
 *
 * Step-2 preimage is reconstructed from the durable inner + step_1 (same splice as MOVE/RECEIVE);
 * step_2_signature + completed body come from the verified candidate (never re-signed here).
 * Already-advanced rows (replay / prior land attempt) are left alone.
 */
async function promoteSendCompletedBodyOnAttempt(
  query: SqlQueryFn,
  command: CommitExternalSendLandingCommand,
): Promise<void> {
  const candidate = command.candidate;
  const completedText = candidate.completedTransactionText;
  if (completedText === null || completedText.length === 0) {
    throw new Error(
      `send landing: completedTransactionText required to promote operation_transactions for ${command.operationId}`,
    );
  }
  if (candidate.completedTransactionSha256 !== hashMovePreimageText(completedText)) {
    throw new Error(
      `send landing: completedTransactionSha256 mismatch for ${command.operationId}`,
    );
  }

  const phaseRows = await query(
    `SELECT attempt_phase::text AS attempt_phase,
            inner_preimage_text,
            step_1_signature,
            completed_transaction_text,
            completed_transaction_sha256
       FROM operation_transactions
      WHERE operation_id = $1::uuid AND attempt_no = 1`,
    [command.operationId],
  );
  const row = phaseRows[0] as
    | {
        attempt_phase: string;
        inner_preimage_text: string;
        step_1_signature: string | null;
        completed_transaction_text: string | null;
        completed_transaction_sha256: string | null;
      }
    | undefined;
  if (row === undefined) {
    throw new Error(
      `send landing: missing operation_transactions for ${command.operationId}`,
    );
  }

  if (
    row.attempt_phase === "STEP2_SIGNATURE_PERSISTED" ||
    row.attempt_phase === "SETTLED_BODY_PERSISTED"
  ) {
    if (
      row.completed_transaction_text !== null &&
      row.completed_transaction_text !== completedText
    ) {
      throw new Error(
        `send landing: durable completed body disagrees with candidate for ${command.operationId}`,
      );
    }
    return;
  }

  if (row.attempt_phase === "STEP1_SIGNATURE_PERSISTED") {
    if (row.step_1_signature === null) {
      throw new Error(
        `send landing: step_1_signature missing at STEP1 for ${command.operationId}`,
      );
    }
    // Prefer durable attempt bytes for step-2 preimage (Byte-exact); candidate supplies observed E.
    const step2PreimageText = buildMoveStep2PreimageText(
      row.inner_preimage_text,
      row.step_1_signature,
    );
    const step2PreimageSha256 = hashMovePreimageText(step2PreimageText);
    await advanceAttemptPhase(query, command.operationId, "STEP2_PREIMAGE_PERSISTED", {
      step_2_preimage_text: step2PreimageText,
      step_2_preimage_sha256: step2PreimageSha256,
    });
    await advanceAttemptPhase(query, command.operationId, "STEP2_SIGNATURE_PERSISTED", {
      step_2_signature: candidate.step2Signature,
      completed_transaction_text: completedText,
      completed_transaction_sha256: candidate.completedTransactionSha256,
    });
    return;
  }

  if (row.attempt_phase === "STEP2_PREIMAGE_PERSISTED") {
    await advanceAttemptPhase(query, command.operationId, "STEP2_SIGNATURE_PERSISTED", {
      step_2_signature: candidate.step2Signature,
      completed_transaction_text: completedText,
      completed_transaction_sha256: candidate.completedTransactionSha256,
    });
    return;
  }

  throw new Error(
    `send landing: unexpected attempt_phase=${row.attempt_phase} for ${command.operationId}`,
  );
}

export function createSqlExternalSendLandingStore(
  pool: Pool,
  eventSigner: NodeEventSigner | null,
  options: { readonly statementTimeoutMs?: number } = {},
): ExternalSendLandingStore {
  const statementTimeoutMs =
    options.statementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  return {
    async commitLanding(command: CommitExternalSendLandingCommand) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await applyMoneyPathStatementTimeout(client, statementTimeoutMs);
        const inner = new SqlExternalSendLandingStore(
          {
            // Pass-through: node-core's statements run on the transaction opened above.
            // rowCount is required: releaseLease (NODE_VERIFIED same-TX release) fails closed
            // without exact-one-row close/consume/DELETE counts.
            withTransaction: async (fn) =>
              fn({
                query: async <R>(text: string, params: readonly unknown[]) => {
                  const result = await client.query(text, params as never[]);
                  return { rows: result.rows as R[], rowCount: result.rowCount };
                },
              }),
          },
          eventSigner ?? UNAVAILABLE_EVENT_SIGNER,
        );

        const result = await inner.commitLanding(command);
        if (!result.applied) {
          await client.query("ROLLBACK");
          return result;
        }

        // Sync the operations mirror from send_operations in this same
        // DB-TX: status, formation_state, terminal_observation_id, terminal_at,
        // attention clear, row_version, updated_at.
        // terminal_at must land with EXTERNAL_SEND_LANDED so SPA in-flight drops
        // the row (ZTR-1249). Positive land also clears provisional attention
        // (e.g. POST_EXPIRY_RECONCILING) — send_operations already cleared in
        // landing-sql-store; mirror must not leave operations.attention_required
        // sticky (ZTR-1250). Co-presence CHECK: required false iff reason null.
        await client.query(
          `UPDATE operations o
              SET status = s.status::operation_status,
                  formation_state = s.formation_state::external_formation_state,
                  terminal_observation_id = s.terminal_observation_id,
                  verification_material_available_until = s.verification_material_available_until,
                  terminal_at = COALESCE(o.terminal_at, now()),
                  attention_required = false,
                  attention_reason = NULL,
                  attention_detail = NULL,
                  row_version = s.row_version,
                  updated_at = now()
             FROM send_operations s
            WHERE s.operation_id = $1::uuid
              AND o.id = s.operation_id
              AND o.kind = 'SEND_EXTERNAL'`,
          [command.operationId],
        );

        // Derived wallet_settled_ledger SOURCE row. Resolve T0 from the sign
        // intent (SEND has no operations.t0_observation_id).
        const t0Rows = await client.query<{ t0: string }>(
          `SELECT source_t0_observation_id::text AS t0
             FROM external_send_sign_intents
            WHERE operation_id = $1::uuid`,
          [command.operationId],
        );
        const t0ObservationId = t0Rows.rows[0]?.t0;
        if (t0ObservationId === undefined || t0ObservationId === null) {
          throw new Error(
            `send landing: missing source_t0_observation_id for ${command.operationId}`,
          );
        }
        const txQuery: SqlQueryFn = async (text, values) => {
          const r = await client.query(text, values as never[]);
          return r.rows as readonly Record<string, unknown>[];
        };
        // Promote the attempt body before ledger (SEND parks at STEP1 until land observes E).
        await promoteSendCompletedBodyOnAttempt(txQuery, command);
        const settled = await recordWalletSettledLedger(txQuery, {
          operationId: command.operationId,
          landingVerdict: command.sourcePath.kind,
          pathDepth: command.sourcePath.depth,
          t0ObservationId,
          terminalObservationId: command.terminalObservationId,
          requiredPathCount: 1,
          verifiedAtIso: new Date(command.landedAtMs).toISOString(),
        });

        // Lineage path for verification-material ancestor_proofs.
        const srcRows = await txQuery(
          `SELECT o.source_wallet_id::text AS wallet_id,
                  w.public_key AS wallet_public_key,
                  olp.proof_manifest_text,
                  olp.proof_manifest_sha256
             FROM operations o
             LEFT JOIN wallets w ON w.id = o.source_wallet_id
             INNER JOIN operation_landing_proofs olp ON olp.id = $2::uuid
            WHERE o.id = $1::uuid`,
          [command.operationId, settled.landingProofId],
        );
        const src = srcRows[0] as
          | {
              wallet_id: string | null;
              wallet_public_key: string | null;
              proof_manifest_text: string;
              proof_manifest_sha256: string;
            }
          | undefined;
        if (src?.wallet_public_key) {
          await writeExactHeadLineagePath(txQuery, {
            operationId: command.operationId,
            landingProofId: settled.landingProofId,
            pathRole: "SOURCE",
            walletId: src.wallet_id,
            walletPublicKey: src.wallet_public_key,
            t0ObservationId,
            freshHeadObservationId: command.terminalObservationId,
            verdict: command.sourcePath.kind,
            pathDepth: command.sourcePath.depth,
            proofManifestText: src.proof_manifest_text,
            proofManifestSha256: src.proof_manifest_sha256,
            createdAtIso: new Date(command.landedAtMs).toISOString(),
          });
        }

        await issueLandedAccessWindow(txQuery, command.operationId, command.landedAtMs);

        await client.query("COMMIT");
        return result;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* keep the original failure */
        }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
