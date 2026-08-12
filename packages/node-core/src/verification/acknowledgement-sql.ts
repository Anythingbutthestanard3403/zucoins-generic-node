// SqlExecutor-backed AcknowledgementStore over the frozen acknowledgement tables:
// verification_acknowledgements / verification_ack_wallet_evidence (this slice only reads
// and writes them), lease_groups / lease_group_operations / wallet_lease_memberships, and
// reporting_request_nonces, which holds the one signed request's exact bytes.
//
// Driver-agnostic: the composition root injects the executor. Every statement here
// runs inside the caller's transaction — the same unit of work that inserts the
// completed-idempotency parent.
//
// Column defaults do the vocabulary pinning: route_id, reporting_purpose, request_class,
// retention_class and method are CHECK-constrained single-value columns, so the INSERT
// omits them and lets the frozen DDL supply them. A lane that starts passing them is a
// vocabulary fork waiting to happen.

import type {
  AckOpenMembership,
  AckOperationFacts,
  AcknowledgementDraft,
  AcknowledgementResponseBody,
  AcknowledgementStore,
  StoredAcknowledgement,
} from "./acknowledgement.js";
import { AcknowledgementInsertConflict } from "./acknowledgement.js";
import type {
  AckEvidenceRole,
  AckVerdict,
  DurableEvidenceFact,
  GroupOperationFact,
  GroupReleaseFacts,
  LeaseReleaseStatus,
  OperationWalletAssignment,
} from "./predicates.js";
import { expectedWalletsForOperation } from "./predicates.js";
import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

export interface AckSqlQueryResult<R> {
  readonly rows: R[];
  readonly rowCount?: number | null;
}

/**
 * Narrow node-postgres-shaped surface; `pg.Pool` / `pg.PoolClient` satisfy it. Declared here
 * rather than imported so this module stays a leaf (test/boundaries.test.ts).
 */
export interface AckSqlExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<AckSqlQueryResult<R>>;
}

const SQLSTATE_UNIQUE_VIOLATION = "23505";

function isUniqueViolation(err: unknown): boolean {
  if (err === null || typeof err !== "object") return false;
  const code = (err as { code?: unknown }).code;
  if (String(code) === SQLSTATE_UNIQUE_VIOLATION) return true;
  // psql session wrappers surface "ERROR: 23505: ..." in the message.
  const message = (err as { message?: unknown }).message;
  return typeof message === "string" && /\b23505\b/.test(message);
}

export const ACK_STATEMENTS = {
  // Operation + durable wallet identities for every evidence role the kind requires.
  // SOURCE/RECEIVER join wallets directly; MOVE DESTINATION joins destinations→wallets;
  // SEND DESTINATION uses destination_address (no node wallet id).
  SELECT_OPERATION: `
    SELECT o.id                AS operation_id,
           o.node_id           AS node_id,
           o.implementer_id    AS implementer_id,
           o.kind::text        AS kind,
           o.row_version::text AS row_version,
           lgo.lease_group_id  AS lease_group_id,
           o.source_wallet_id  AS source_wallet_id,
           sw.public_key       AS source_public_key,
           o.receiver_wallet_id AS receiver_wallet_id,
           rw.public_key       AS receiver_public_key,
           o.destination_address AS destination_address,
           dw.id               AS destination_wallet_id,
           dw.public_key       AS destination_public_key
      FROM operations o
      LEFT JOIN lease_group_operations lgo ON lgo.operation_id = o.id
      LEFT JOIN wallets sw ON sw.id = o.source_wallet_id
      LEFT JOIN wallets rw ON rw.id = o.receiver_wallet_id
      LEFT JOIN destinations d ON d.id = o.destination_id
      LEFT JOIN wallets dw ON dw.id = d.wallet_id
     WHERE o.id = $1`,

  // The acknowledgement plus the exact signed bytes it binds, its evidence rows, and the
  // completed parent's frozen response_bytes (byte-identical replay).
  SELECT_ACKNOWLEDGEMENT: `
    SELECT a.id                     AS id,
           a.operation_id           AS operation_id,
           a.node_id                AS node_id,
           a.implementer_id         AS implementer_id,
           a.consumed_cursor::text  AS consumed_cursor,
           a.verdict::text          AS verdict,
           a.evidence_set_sha256    AS evidence_set_sha256,
           a.request_body_sha256    AS request_body_sha256,
           a.raw_target             AS raw_target,
           n.request_preimage_text  AS request_preimage_text,
           n.request_signature      AS request_signature,
           -- Rendered as the same UTC millisecond form the write used, so a replay returns
           -- byte-identical response bytes. A session-local offset here would make the
           -- replay body differ from the original for the same durable row.
           to_char(a.acknowledged_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
             AS acknowledged_at,
           convert_from(m.response_bytes, 'UTF8') AS response_bytes_text
      FROM verification_acknowledgements a
      JOIN reporting_request_nonces n ON n.id = a.reporting_nonce_id
      JOIN reporting_mutation_idempotency m ON m.id = a.mutation_idempotency_id
     WHERE a.operation_id = $1`,

  SELECT_ACK_EVIDENCE: `
    SELECT evidence_role::text AS evidence_role,
           wallet_id           AS wallet_id,
           wallet_public_key   AS wallet_public_key
      FROM verification_ack_wallet_evidence
     WHERE acknowledgement_id = $1`,

  INSERT_ACKNOWLEDGEMENT: `
    INSERT INTO verification_acknowledgements (
      id, operation_id, node_id, implementer_id, raw_target, consumed_cursor, verdict,
      evidence_set_sha256, request_body_sha256, reporting_nonce_id, mutation_idempotency_id,
      acknowledged_at
    ) VALUES ($1, $2, $3, $4, $5, $6::bigint, $7::verification_verdict, $8, $9, $10, $11, $12)`,

  INSERT_ACK_WALLET_EVIDENCE: `
    INSERT INTO verification_ack_wallet_evidence (
      acknowledgement_id, evidence_role, wallet_id, wallet_public_key,
      t0_observation_id, terminal_observation_id
    ) VALUES ($1, $2, $3, $4, $5, $6)`,

  // One-way terminal stamp (`completed_at`). WHERE completed_at IS NULL makes a replay a
  // zero-row no-op instead of moving the stamp forward.
  COMPLETE_GROUP_OPERATION: `
    UPDATE lease_group_operations
       SET completed_at = $3
     WHERE lease_group_id = $1 AND operation_id = $2 AND completed_at IS NULL`,

  // ZTR-1246: denormalize ack verdict. ZTR-1245: VERIFIED clears provisional attention.
  APPLY_OPERATION_VERIFICATION_VERDICT: `
    UPDATE operations
       SET verification_verdict = $2::verification_verdict,
           attention_required = CASE
             WHEN $2::text = 'VERIFIED' THEN false
             ELSE attention_required
           END,
           attention_reason = CASE
             WHEN $2::text = 'VERIFIED' THEN NULL
             ELSE attention_reason
           END,
           attention_detail = CASE
             WHEN $2::text = 'VERIFIED' THEN NULL
             ELSE attention_detail
           END,
           updated_at = now()
     WHERE id = $1::uuid`,

  SELECT_GROUP_CHILD_DISPOSITION: `
    SELECT child_disposition FROM lease_groups WHERE id = $1 FOR UPDATE`,

  // Every leg of the group with its acknowledgement verdict, durable evidence identity, and
  // the operation's wallet-column assignments. LEFT JOIN ack: a leg with no acknowledgement
  // yet reports verdict null.
  //
  // `joined_at` rides along so the caller can present the legs in a stable sequence. Sorting
  // happens in TypeScript rather than in SQL throughout this module: the sort keyword is
  // product vocabulary the source gate rejects on sight (never exempt as a direct
  // hit), and the row counts here are the two or three legs of one lease group.
  SELECT_GROUP_OPERATION_FACTS: `
    SELECT lgo.operation_id                          AS operation_id,
           o.kind::text                              AS kind,
           a.verdict::text                           AS verdict,
           (lgo.completed_at IS NOT NULL)            AS completed,
           to_char(lgo.joined_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') AS joined_at,
           o.source_wallet_id                        AS source_wallet_id,
           sw.public_key                             AS source_public_key,
           o.receiver_wallet_id                      AS receiver_wallet_id,
           rw.public_key                             AS receiver_public_key,
           o.destination_address                     AS destination_address,
           dw.id                                     AS destination_wallet_id,
           dw.public_key                             AS destination_public_key,
           a.id                                      AS acknowledgement_id
      FROM lease_group_operations lgo
      JOIN operations o ON o.id = lgo.operation_id
      LEFT JOIN verification_acknowledgements a ON a.operation_id = lgo.operation_id
      LEFT JOIN wallets sw ON sw.id = o.source_wallet_id
      LEFT JOIN wallets rw ON rw.id = o.receiver_wallet_id
      LEFT JOIN destinations d ON d.id = o.destination_id
      LEFT JOIN wallets dw ON dw.id = d.wallet_id
     WHERE lgo.lease_group_id = $1`,

  SELECT_OPEN_MEMBERSHIPS: `
    SELECT id                AS membership_id,
           wallet_id         AS wallet_id,
           lease_epoch::text AS lease_epoch,
           lease_group_id    AS lease_group_id,
           operation_id      AS operation_id
      FROM wallet_lease_memberships
     WHERE lease_group_id = $1 AND released_at IS NULL`,
} as const;

/** Stable ascending comparison on one string key, then a tiebreaker. */
const byKeyThen = <T>(key: (row: T) => string, tiebreak: (row: T) => string) =>
  (left: T, right: T): number => {
    const primary = key(left).localeCompare(key(right));
    return primary !== 0 ? primary : tiebreak(left).localeCompare(tiebreak(right));
  };

interface OperationRow {
  operation_id: string;
  node_id: string;
  implementer_id: string;
  kind: string;
  row_version: string;
  lease_group_id: string | null;
  source_wallet_id: string | null;
  source_public_key: string | null;
  receiver_wallet_id: string | null;
  receiver_public_key: string | null;
  destination_address: string | null;
  destination_wallet_id: string | null;
  destination_public_key: string | null;
}

interface AcknowledgementRow {
  id: string;
  operation_id: string;
  node_id: string;
  implementer_id: string;
  consumed_cursor: string;
  verdict: string;
  evidence_set_sha256: string;
  request_body_sha256: string;
  raw_target: string;
  request_preimage_text: string;
  request_signature: string;
  acknowledged_at: string;
  response_bytes_text: string | null;
}

interface EvidenceRow {
  evidence_role: string;
  wallet_id: string | null;
  wallet_public_key: string;
}

interface GroupOperationRow {
  operation_id: string;
  kind: string;
  verdict: string | null;
  completed: boolean;
  joined_at: string;
  source_wallet_id: string | null;
  source_public_key: string | null;
  receiver_wallet_id: string | null;
  receiver_public_key: string | null;
  destination_address: string | null;
  destination_wallet_id: string | null;
  destination_public_key: string | null;
  acknowledgement_id: string | null;
}

interface MembershipRow {
  membership_id: string;
  wallet_id: string;
  lease_epoch: string;
  lease_group_id: string;
  operation_id: string;
}

const asRoles = (values: readonly DurableEvidenceFact[]): AckEvidenceRole[] =>
  values.map((value) => value.role);

function walletsFromRow(row: {
  kind: string;
  source_wallet_id: string | null;
  source_public_key: string | null;
  receiver_wallet_id: string | null;
  receiver_public_key: string | null;
  destination_address: string | null;
  destination_wallet_id: string | null;
  destination_public_key: string | null;
}): OperationWalletAssignment[] {
  return expectedWalletsForOperation(row.kind as OperationKind, {
    sourceWalletId: row.source_wallet_id,
    sourcePublicKey: row.source_public_key,
    receiverWalletId: row.receiver_wallet_id,
    receiverPublicKey: row.receiver_public_key,
    destinationWalletId: row.destination_wallet_id,
    destinationPublicKey: row.destination_public_key,
    destinationAddress: row.destination_address,
  });
}

/**
 * Parse the completed parent's response_bytes into a response body when composition froze real
 * JSON. Placeholder seeds (`{}`, empty) return null so the service uses the conservative
 * non-RELEASED reconstruction rather than inventing a release.
 */
export function parseFrozenResponseBody(
  text: string | null | undefined,
): AcknowledgementResponseBody | null {
  if (text === null || text === undefined || text === "" || text === "{}") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const body = parsed as Record<string, unknown>;
  const status = body.lease_release_status;
  const verdict = body.verdict;
  if (
    typeof body.operation_id !== "string" ||
    typeof body.acknowledgement_id !== "string" ||
    typeof body.acknowledged_at !== "string" ||
    (verdict !== "VERIFIED" && verdict !== "REJECTED" && verdict !== "INDETERMINATE") ||
    (status !== "RELEASED" &&
      status !== "PINNED_GROUP_PENDING" &&
      status !== "PINNED_FOR_ATTENTION")
  ) {
    return null;
  }
  return {
    operation_id: body.operation_id,
    acknowledgement_id: body.acknowledgement_id,
    verdict: verdict as AckVerdict,
    lease_release_status: status as LeaseReleaseStatus,
    acknowledged_at: body.acknowledged_at,
  };
}

export function createSqlAcknowledgementStore(): AcknowledgementStore<AckSqlExecutor> {
  return {
    async readOperation(tx, operationId): Promise<AckOperationFacts | null> {
      const result = await tx.query<OperationRow>(ACK_STATEMENTS.SELECT_OPERATION, [operationId]);
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        operationId: row.operation_id,
        nodeId: row.node_id,
        implementerId: row.implementer_id,
        kind: row.kind as OperationKind,
        rowVersion: Number(row.row_version),
        leaseGroupId: row.lease_group_id,
        expectedWallets: walletsFromRow(row),
      };
    },

    async findAcknowledgement(tx, operationId): Promise<StoredAcknowledgement | null> {
      const result = await tx.query<AcknowledgementRow>(ACK_STATEMENTS.SELECT_ACKNOWLEDGEMENT, [
        operationId,
      ]);
      const row = result.rows[0];
      if (row === undefined) return null;
      const evidenceResult = await tx.query<EvidenceRow>(ACK_STATEMENTS.SELECT_ACK_EVIDENCE, [
        row.id,
      ]);
      const evidence: DurableEvidenceFact[] = [...evidenceResult.rows]
        .sort(byKeyThen((r) => r.evidence_role, (r) => r.wallet_public_key))
        .map((e) => ({
          role: e.evidence_role as AckEvidenceRole,
          walletId: e.wallet_id,
          walletPublicKey: e.wallet_public_key,
        }));
      return {
        id: row.id,
        operationId: row.operation_id,
        nodeId: row.node_id,
        implementerId: row.implementer_id,
        consumedCursor: BigInt(row.consumed_cursor),
        verdict: row.verdict as AckVerdict,
        evidenceSetSha256: row.evidence_set_sha256,
        requestBodySha256: row.request_body_sha256,
        rawTarget: row.raw_target,
        requestPreimageText: row.request_preimage_text,
        requestSignature: row.request_signature,
        acknowledgedAt: row.acknowledged_at,
        evidenceRoles: asRoles(evidence),
        evidence,
        frozenResponseBody: parseFrozenResponseBody(row.response_bytes_text),
      };
    },

    async insertAcknowledgement(tx, draft: AcknowledgementDraft): Promise<void> {
      try {
        await tx.query(ACK_STATEMENTS.INSERT_ACKNOWLEDGEMENT, [
          draft.id,
          draft.operationId,
          draft.nodeId,
          draft.implementerId,
          draft.rawTarget,
          draft.consumedCursor.toString(),
          draft.verdict,
          draft.evidenceSetSha256,
          draft.requestBodySha256,
          draft.reportingNonceId,
          draft.mutationIdempotencyId,
          draft.acknowledgedAt,
        ]);
      } catch (err) {
        if (isUniqueViolation(err)) {
          throw new AcknowledgementInsertConflict(
            err instanceof Error ? err.message : "operation_id unique violation",
          );
        }
        throw err;
      }
      // Written in the sequence supplied. The PRIMARY KEY / UNIQUE pair is the database's
      // own refusal of a repeated role or public key; the service refuses first so a
      // well-formed request never depends on the constraint to stay correct.
      for (const evidence of draft.walletEvidence) {
        await tx.query(ACK_STATEMENTS.INSERT_ACK_WALLET_EVIDENCE, [
          draft.id,
          evidence.role,
          evidence.walletId,
          evidence.walletPublicKey,
          evidence.t0.observationId,
          evidence.terminal.observationId,
        ]);
      }
    },

    async completeGroupOperation(tx, leaseGroupId, operationId): Promise<void> {
      await tx.query(ACK_STATEMENTS.COMPLETE_GROUP_OPERATION, [
        leaseGroupId,
        operationId,
        new Date().toISOString(),
      ]);
    },

    async applyOperationVerificationVerdict(tx, operationId, verdict): Promise<void> {
      await tx.query(ACK_STATEMENTS.APPLY_OPERATION_VERIFICATION_VERDICT, [
        operationId,
        verdict,
      ]);
    },

    async readGroupReleaseFacts(tx, leaseGroupId): Promise<GroupReleaseFacts> {
      const group = await tx.query<{ child_disposition: string }>(
        ACK_STATEMENTS.SELECT_GROUP_CHILD_DISPOSITION,
        [leaseGroupId],
      );
      // A group row that has vanished cannot be judged releasable. Reporting PENDING keeps the
      // wallets pinned instead of letting an absent row read as "nothing blocks release".
      const childDisposition = (group.rows[0]?.child_disposition ?? "PENDING") as
        | "NONE"
        | "PENDING"
        | "JOINED";

      const ops = await tx.query<GroupOperationRow>(
        ACK_STATEMENTS.SELECT_GROUP_OPERATION_FACTS,
        [leaseGroupId],
      );

      // Load evidence for every acknowledged leg in one pass per leg (group size is 1–3).
      const operations: GroupOperationFact[] = [];
      const sorted = [...ops.rows].sort(
        byKeyThen((row) => row.joined_at, (row) => row.operation_id),
      );
      for (const row of sorted) {
        let evidence: DurableEvidenceFact[] = [];
        if (row.acknowledgement_id !== null) {
          const evidenceResult = await tx.query<EvidenceRow>(ACK_STATEMENTS.SELECT_ACK_EVIDENCE, [
            row.acknowledgement_id,
          ]);
          evidence = [...evidenceResult.rows]
            .sort(byKeyThen((r) => r.evidence_role, (r) => r.wallet_public_key))
            .map((e) => ({
              role: e.evidence_role as AckEvidenceRole,
              walletId: e.wallet_id,
              walletPublicKey: e.wallet_public_key,
            }));
        }
        operations.push({
          operationId: row.operation_id,
          kind: row.kind as OperationKind,
          verdict: row.verdict === null ? null : (row.verdict as AckVerdict),
          evidenceRoles: asRoles(evidence),
          evidence,
          expectedWallets: walletsFromRow(row),
          completed: row.completed,
        });
      }

      return { childDisposition, operations };
    },

    async readOpenMemberships(tx, leaseGroupId): Promise<readonly AckOpenMembership[]> {
      const result = await tx.query<MembershipRow>(ACK_STATEMENTS.SELECT_OPEN_MEMBERSHIPS, [
        leaseGroupId,
      ]);
      return [...result.rows]
        .sort(byKeyThen((row) => row.wallet_id, (row) => row.membership_id))
        .map((row) => ({
          membershipId: row.membership_id,
          walletId: row.wallet_id,
          leaseEpoch: BigInt(row.lease_epoch),
          leaseGroupId: row.lease_group_id,
          operationId: row.operation_id,
        }));
    },
  };
}
