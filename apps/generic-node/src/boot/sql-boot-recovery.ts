// SQL-backed BootRecoveryStore + BootRecoveryActions for real inventory.
// Replaces the empty greenfield-only store in main.ts with SQL queries against the
// custody pool. Governing: 09-operations-recovery.md boot recovery; One-in-flight.
//
// SQL_LIST_NONTERMINAL_OPS is the LEASE-ELIGIBLE census, not merely the
// nonterminal one: it also carries terminal operations that still hold a lease. See the
// causal note on its WHERE clause; the terminal status list is imported, never restated.

import type { Pool } from "pg";

import {
  deriveEd25519PublicKeyBase64Url,
  SUBMIT_LEDGER_TABLES,
  TERMINAL_OPERATION_STATES,
  VaultOpenError,
  VaultRecordNotFoundError,
  type ActiveLeaseRow,
  type BootRecoveryActions,
  type BootRecoveryStore,
  type BootWalletState,
  type EncryptedWalletKeyStore,
  type KeyCorrespondenceRow,
  type LeaseGroupOperationRow,
  type ObservationCursorHint,
  type OperationPhaseEvidence,
  type OperationKind,
  type LeaseRole,
} from "@zucoins/node-core";
import type { AttentionReason } from "@zucoins/generic-node-contracts/operations/events";

const SQL_LIST_ACTIVE_LEASES = `
  SELECT wal.wallet_id::text AS wallet_id,
         wal.operation_id::text AS operation_id,
         wal.lease_group_id::text AS lease_group_id,
         wal.lease_role::text AS lease_role,
         wal.lease_epoch::bigint AS lease_epoch,
         w.state::text AS wallet_state,
         EXTRACT(EPOCH FROM wal.heartbeat_at) * 1000 AS last_heartbeat_ms
    FROM wallet_active_leases wal
    JOIN wallets w ON w.id = wal.wallet_id
`;

const SQL_LIST_NONTERMINAL_OPS = `
  SELECT o.id::text AS operation_id,
         o.kind::text AS kind,
         o.status::text AS status,
         o.attention_required AS attention_required,
         o.row_version::int AS row_version,
         ot.attempt_phase::text AS attempt_phase,
         ot.inner_preimage_text IS NOT NULL AS exact_preimage_persisted,
         ot.step_1_signature IS NOT NULL AS step1_sig_persisted,
         ot.step_2_signature IS NOT NULL AS step2_sig_persisted,
         EXISTS(SELECT 1 FROM ${SUBMIT_LEDGER_TABLES[0]} sd
                 WHERE sd.operation_id = o.id AND sd.transaction_attempt_no = 1) AS submit_claimed,
         -- The paired invariant (boot-recovery.ts auditPhaseBoundaries) reads this
         -- alongside exact_preimage_persisted above and calls a breach when the signer
         -- was invoked but the exact signed bytes are absent. exact_preimage_persisted
         -- measures operation_transactions.inner_preimage_text, which is the home of
         -- STEP_1/STEP_2 transaction preimages ONLY, so this must count exactly those
         -- purposes or the two sides are not comparing the same signing event.
         --
         -- EXPECTED_ARTIFACT bytes live in operation_expected_artifacts.preimage_text
         -- (insert-only, byte-immutable, written in the same transaction as the signing
         -- call), REPORTING_ENVELOPE and DEVICE_APPROVAL likewise never land in
         -- operation_transactions. Counting them here made every armed receive a
         -- permanent global invariant breach on the next boot: arming signs the expected
         -- artifact and writes a signer_audit row, while operation_transactions stays
         -- empty until a candidate is intaken, so the node quarantined itself and money
         -- engines never started again.
         EXISTS(SELECT 1 FROM signer_audit sa
                 WHERE sa.operation_id = o.id
                   AND sa.purpose IN ('STEP_1', 'STEP_2')) AS signer_audit_present,
         EXISTS(SELECT 1 FROM receive_codes rc
                 WHERE rc.operation_id = o.id) AS formation_complete
    FROM operations o
    LEFT JOIN operation_transactions ot ON ot.operation_id = o.id AND ot.attempt_no = 1
   WHERE o.status NOT IN (${TERMINAL_OPERATION_STATES.map((s) => `'${s}'`).join(", ")})
         -- Mirror of the over-inclusive bug above — under-inclusive this time.
         -- boot-recovery.ts auditActiveLeases resolves each wallet_active_leases row
         -- against this census and calls a missing row lease_operation_missing, a
         -- global invariant breach. But a lease legitimately OUTLIVES its operation's
         -- terminal status: the receiver/source lease is held until the consumer's
         -- verification-complete acknowledgement releases it, proof-backed, and an
         -- EXPIRED receive stays pinned
         -- until the T0-unchanged release proof. A terminal-status row is excluded
         -- above, so every landed receive/move/send quarantined its wallet on the next
         -- boot and the node never started money engines again.
         --
         -- A genuinely orphaned lease — one whose operation_id has no operations row
         -- at all — still produces no census row, so the real orphan detection this
         -- finding exists for is intact.
         OR EXISTS (SELECT 1 FROM wallet_active_leases wal WHERE wal.operation_id = o.id)
`;

const SQL_LIST_LEASE_GROUP_OPS = `
  SELECT lease_group_id::text AS lease_group_id,
         operation_id::text AS operation_id
    FROM lease_group_operations
`;

const SQL_LIST_OBSERVATION_CURSORS = `
  SELECT observer_id::text || ':' || wallet_public_key AS stream_key,
         last_recorded_observation_id::text AS last_recorded_observation_id,
         last_raw_response_sha256::text AS last_raw_response_sha256
    FROM wallet_observation_cursors
`;

const SQL_READ_RAW_RESPONSE_BYTES = `
  SELECT raw_response_bytes FROM gateway_observations WHERE id = $1::uuid
`;

const SQL_LIST_QUEUED_RECEIVE_OP_IDS = `
  SELECT id::text AS operation_id
    FROM operations
   WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED'
   ORDER BY created_at ASC -- contract-allow:order:frozen structural vocabulary
`;

const REQUIRED_ROLES: Readonly<Record<string, readonly LeaseRole[]>> = {
  RECEIVE_EXTERNAL: ["RECEIVE_WINDOW"],
  MOVE_INTERNAL: ["MOVE_SOURCE", "MOVE_DESTINATION"],
  SEND_EXTERNAL: ["SEND_SOURCE"],
};

function createSqlBootRecoveryStore(
  pool: Pool,
  vault: EncryptedWalletKeyStore,
): BootRecoveryStore {
  return {
    async listActiveLeases(): Promise<readonly ActiveLeaseRow[]> {
      const result = await pool.query<{
        wallet_id: string; operation_id: string; lease_group_id: string;
        lease_role: string; lease_epoch: string; wallet_state: string;
        last_heartbeat_ms: string;
      }>(SQL_LIST_ACTIVE_LEASES);
      return result.rows.map((r) => ({
        walletId: r.wallet_id,
        operationId: r.operation_id,
        leaseGroupId: r.lease_group_id,
        role: r.lease_role as LeaseRole,
        epoch: Number(r.lease_epoch),
        walletState: r.wallet_state as BootWalletState,
        lastHeartbeatAtMs: Number(r.last_heartbeat_ms ?? 0),
      }));
    },

    async listNonterminalOperations(): Promise<readonly OperationPhaseEvidence[]> {
      const result = await pool.query<{
        operation_id: string; kind: string; status: string;
        attention_required: boolean; row_version: number;
        attempt_phase: string | null; exact_preimage_persisted: boolean;
        step1_sig_persisted: boolean; step2_sig_persisted: boolean;
        submit_claimed: boolean; signer_audit_present: boolean;
        formation_complete: boolean;
      }>(SQL_LIST_NONTERMINAL_OPS);

      const ops: OperationPhaseEvidence[] = [];
      for (const r of result.rows) {
        // Fetch leased wallet IDs for this operation.
        const leaseRows = await pool.query<{ wallet_id: string }>(
          `SELECT wallet_id::text FROM wallet_active_leases WHERE operation_id = $1::uuid`,
          [r.operation_id],
        );
        const leasedWalletIds = leaseRows.rows.map((lr) => lr.wallet_id);

        // Determine the expected signature field based on operation kind. RECEIVE and
        // MOVE both settle their signature at step 2 (attempt_phase is a single monotonic
        // per-row state machine: step2_sig_persisted implies step1_sig_persisted for the
        // same row). Only SEND's single-signature flow reads step 1.
        const signaturePersisted = r.kind === "SEND_EXTERNAL" ? r.step1_sig_persisted : r.step2_sig_persisted;

        // Get lease epoch from active leases. This scalar is well-defined only for
        // single-wallet ops (RECEIVE/SEND); MOVE_INTERNAL's two wallets carry independent
        // per-wallet epochs (leases/repository.ts nextEpoch()) and the ORDER BY here just // contract-allow:order:frozen structural vocabulary
        // makes the pick deterministic — boot-recovery.ts gates the op-wide equality check
        // to single-wallet ops accordingly.
        const epochRow = await pool.query<{ lease_epoch: string }>(
          `SELECT lease_epoch::text AS lease_epoch FROM wallet_active_leases
            WHERE operation_id = $1::uuid ORDER BY wallet_id LIMIT 1`, // contract-allow:order:frozen structural vocabulary
          [r.operation_id],
        );
        const leaseEpoch = epochRow.rows[0] ? Number(epochRow.rows[0].lease_epoch) : 0;

        ops.push({
          operationId: r.operation_id,
          kind: r.kind as OperationKind,
          status: r.status,
          attentionRequired: r.attention_required ?? false,
          rowVersion: r.row_version,
          leaseEpoch,
          submitBoundaryRecorded: r.submit_claimed,
          signerAuditIndicatesCall: r.signer_audit_present,
          exactPreimagePersisted: r.exact_preimage_persisted,
          signaturePersisted,
          formationComplete: r.formation_complete,
          leasedWalletIds,
          requiredRoles: REQUIRED_ROLES[r.kind] ?? [],
        });
      }
      return ops;
    },

    async listLeaseGroupOperations(): Promise<readonly LeaseGroupOperationRow[]> {
      const result = await pool.query<{ lease_group_id: string; operation_id: string }>(
        SQL_LIST_LEASE_GROUP_OPS,
      );
      return result.rows.map((r) => ({
        leaseGroupId: r.lease_group_id,
        operationId: r.operation_id,
      }));
    },

    async listKeyCorrespondence(): Promise<readonly KeyCorrespondenceRow[]> {
      const result = await pool.query<{
        wallet_id: string;
        node_id: string;
        public_key: string;
        key_origin: string;
        key_version: number | null;
      }>(
        `SELECT w.id::text AS wallet_id,
                w.node_id::text AS node_id,
                w.public_key,
                w.key_origin::text AS key_origin,
                v.key_version
           FROM wallets w
           LEFT JOIN vault v ON v.wallet_id = w.id
          ORDER BY w.id`, // contract-allow:order:frozen structural vocabulary
      );

      const rows: KeyCorrespondenceRow[] = [];
      for (const row of result.rows) {
        let derivedPublicKey: string | null = null;
        let transientFault = false;
        try {
          const secret = await vault.open(
            {
              nodeId: row.node_id,
              walletId: row.wallet_id,
              keyVersion: row.key_version ?? 1,
              publicKey: row.public_key,
              keyOrigin: row.key_origin,
            },
            "BOOT_KEY_CORRESPONDENCE",
          );
          try {
            derivedPublicKey = deriveEd25519PublicKeyBase64Url(secret.bytes);
          } finally {
            secret.wipe();
          }
        } catch (error) {
          if (error instanceof VaultOpenError || error instanceof VaultRecordNotFoundError) {
            // Missing, corrupt, wrong-version, and authoritative-field mismatch are
            // deterministic custody verdicts. Never log the exception: vault errors can
            // describe custody material and boot only needs the quarantine decision.
          } else {
            // Anything else (DB/audit-log IO) is a retryable operational fault, not a
            // custody verdict — fails boot readiness only, never quarantines (the
            // "Retryable / incomplete" recovery class).
            transientFault = true;
          }
        }
        rows.push({
          walletId: row.wallet_id,
          storedPublicKey: row.public_key,
          derivedPublicKey,
          transientFault,
        });
      }
      return rows;
    },

    async listObservationCursors(): Promise<readonly ObservationCursorHint[]> {
      const result = await pool.query<{
        stream_key: string; last_recorded_observation_id: string | null;
        last_raw_response_sha256: string | null;
      }>(SQL_LIST_OBSERVATION_CURSORS);
      return result.rows.map((r) => ({
        streamKey: r.stream_key,
        lastRecordedObservationId: r.last_recorded_observation_id,
        lastRawResponseSha256: r.last_raw_response_sha256,
      }));
    },

    async readRawResponseBytes(observationId: string): Promise<Uint8Array | null> {
      const result = await pool.query<{ raw_response_bytes: Buffer | null }>(
        SQL_READ_RAW_RESPONSE_BYTES,
        [observationId],
      );
      const bytes = result.rows[0]?.raw_response_bytes;
      return bytes ? new Uint8Array(bytes) : null;
    },

    async listQueuedReceiveOperationIds(): Promise<readonly string[]> {
      const result = await pool.query<{ operation_id: string }>(SQL_LIST_QUEUED_RECEIVE_OP_IDS);
      return result.rows.map((r) => r.operation_id);
    },
  };
}

function createSqlBootRecoveryActions(
  pool: Pool,
  logger: { info(message: string): void; error(message: string, err?: unknown): void },
): BootRecoveryActions {
  return {
    async quarantineWallet(walletId: string, reason: string): Promise<void> {
      // wallets_quarantine_reason_iff requires quarantine_reason IS NOT NULL iff
      // state = QUARANTINED — both columns must move together (pattern from
      // receive/expiry-release.ts's QUARANTINE_WALLET). AVAILABLE is a legal restored
      // pre-quarantine state; RETIRED is terminal and boot recovery never reverses it.
      await pool.query(
        `UPDATE wallets
            SET state = 'QUARANTINED',
                quarantine_reason = COALESCE(quarantine_reason, $2)
          WHERE id = $1::uuid AND state IN ('AVAILABLE', 'PINNED', 'QUARANTINED')`,
        [walletId, reason],
      );
      logger.info(`boot-recovery: quarantine wallet=${walletId} reason=${reason}`);
    },

    async repairWalletState(walletId: string, to: BootWalletState): Promise<void> {
      // wallets.state is the wallet_state enum, not text — cast the target explicitly.
      // Boot recovery only ever repairs AVAILABLE -> PINNED (understated restriction);
      // guard the source state so this never fires against a wallet a
      // concurrent path already moved (incl. QUARANTINED). Log only when the
      // write actually changed the row; a no-op must not look like a completed repair.
      const result = await pool.query(
        `UPDATE wallets SET state = $2::wallet_state WHERE id = $1::uuid AND state = 'AVAILABLE'`,
        [walletId, to],
      );
      if (result.rowCount === 0) {
        logger.info(`boot-recovery: repair no-op wallet=${walletId} state=${to}`);
        return;
      }
      logger.info(`boot-recovery: repair wallet=${walletId} state=${to}`);
    },

    async setAttention(operationId: string, reason: AttentionReason, expectedRowVersion: number): Promise<void> {
      // operations' attention CHECK requires attention_required = (attention_reason IS
      // NOT NULL) — write both columns together. row_version is the CAS guard; a
      // zero rowCount means a concurrent writer already moved the row, so log and
      // return rather than silently pretending the write landed.
      const result = await pool.query(
        `UPDATE operations
            SET attention_required = true,
                attention_reason = COALESCE(attention_reason, $3),
                attention_detail = COALESCE(attention_detail, $4)
          WHERE id = $1::uuid AND row_version = $2`,
        [operationId, expectedRowVersion, reason, `boot:${reason}`],
      );
      if (result.rowCount === 0) {
        logger.error(`boot-recovery: attention CAS miss op=${operationId} expectedRowVersion=${expectedRowVersion}`);
        return;
      }
      logger.info(`boot-recovery: attention op=${operationId} reason=${reason}`);
    },

    async resumeAuthorized(action): Promise<void> {
      // The worker picks up the operation on the next tick via loadProgress/loadPending.
      // Boot recovery classifies and authorizes; the money tick executes. No direct submit
      // or sign here — No-blind-retry (never blind-retry a submit) is enforced by the worker's
      // claim-before-submit gate.
      logger.info(`boot-recovery: resume op=${action.operationId} kind=${action.kind}`);
    },

    async seedReconcileCursor(streamKey: string, priorRawBytes: Uint8Array | null): Promise<void> {
      // The observation cursor is seeded by the stream writer on first read.
      // Boot recovery seeds it from the last recorded raw bytes to enable the
      // consecutive-dedup comparison. For now, this is a no-op — the
      // stream writer handles cursor initialization on the first post-restart read.
      logger.info(`boot-recovery: seed cursor stream=${streamKey} bytes=${priorRawBytes ? priorRawBytes.length : 0}`);
    },

    async rebuildReceiveAdmissionQueue(operationIds: readonly string[]): Promise<void> {
      // The receive admission queue is derived from durable state (operations WHERE
      // kind='RECEIVE_EXTERNAL' AND status='CREATED'). The queue promoter re-reads
      // durable state each tick, so no explicit rebuild is needed — the next tick
      // picks up the queued operations automatically.
      logger.info(`boot-recovery: rebuild queue count=${operationIds.length}`);
    },

    async stopMoneyEngines(reason: string): Promise<void> {
      // Money engines are stopped via the halt gate. The boot lane applies the halt
      // before arming money workers, so this is a diagnostic log — the actual halt
      // is applied by the boot lane's halt restoration.
      logger.info(`boot-recovery: STOP money engines reason=${reason}`);
    },
  };
}

export function createSqlBootRecovery(
  pool: Pool,
  logger: { info(message: string): void; error(message: string, err?: unknown): void },
  vault: EncryptedWalletKeyStore,
): { store: BootRecoveryStore; actions: BootRecoveryActions } {
  return {
    store: createSqlBootRecoveryStore(pool, vault),
    actions: createSqlBootRecoveryActions(pool, logger),
  };
}
