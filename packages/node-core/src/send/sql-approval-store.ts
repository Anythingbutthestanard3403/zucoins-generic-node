// SQL ApprovalChallengeStore over APPROVAL_SQL catalogue (admin money mount).

import {
  ApprovalStoreUniqueViolation,
  type ApprovalChallenge,
  type ApprovalChallengeStore,
  type CommitApprovalMutationResult,
} from "./approve.js";
import { APPROVAL_SQL, mapApprovalUniqueViolation } from "./approval-store.js";
import type { SqlExecutor } from "./sql-store.js";

interface ChallengeRow {
  readonly id: string;
  readonly node_id: string;
  readonly operation_id: string;
  readonly status: ApprovalChallenge["status"];
  readonly purpose: ApprovalChallenge["purpose"];
  readonly canonical_version: number;
  readonly nonce: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly issued_at: Date | string;
  readonly expires_at: Date | string;
  readonly superseded_by: string | null;
}

function mapChallenge(row: ChallengeRow): ApprovalChallenge {
  return {
    id: row.id,
    nodeId: row.node_id,
    operationId: row.operation_id,
    status: row.status,
    purpose: row.purpose,
    canonicalVersion: 1 as ApprovalChallenge["canonicalVersion"],
    nonce: row.nonce,
    preimageText: row.preimage_text,
    preimageSha256: row.preimage_sha256,
    issuedAt: typeof row.issued_at === "string" ? row.issued_at : row.issued_at.toISOString(),
    expiresAt: typeof row.expires_at === "string" ? row.expires_at : row.expires_at.toISOString(),
    supersededBy: row.superseded_by,
  };
}

function isPgUnique(err: unknown): err is { code: string; constraint?: string } {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code: unknown }).code === "23505"
  );
}

export function createSqlApprovalChallengeStore(sql: SqlExecutor): ApprovalChallengeStore {
  return {
    async findIssuedByOperation(operationId) {
      const result = await sql.query<ChallengeRow>(APPROVAL_SQL.SELECT_ISSUED_BY_OPERATION, [
        operationId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : mapChallenge(row);
    },

    async findByNonce(nonce) {
      const result = await sql.query<ChallengeRow>(APPROVAL_SQL.SELECT_BY_NONCE, [nonce]);
      const row = result.rows[0];
      return row === undefined ? null : mapChallenge(row);
    },

    async insertIssued(challenge, supersedeId) {
      try {
        if (supersedeId !== null) {
          await sql.query(APPROVAL_SQL.INSERT_ISSUED_WITH_SUPERSEDE, [
            challenge.id,
            supersedeId,
            challenge.nodeId,
            challenge.operationId,
            challenge.nonce,
            challenge.preimageText,
            challenge.preimageSha256,
            challenge.issuedAt,
            challenge.expiresAt,
          ]);
        } else {
          await sql.query(APPROVAL_SQL.INSERT_ISSUED_FRESH, [
            challenge.id,
            challenge.nodeId,
            challenge.operationId,
            challenge.nonce,
            challenge.preimageText,
            challenge.preimageSha256,
            challenge.issuedAt,
            challenge.expiresAt,
          ]);
        }
      } catch (err) {
        if (isPgUnique(err)) {
          throw new ApprovalStoreUniqueViolation(mapApprovalUniqueViolation(err.constraint));
        }
        throw err;
      }
    },

    async commitApprovalMutation(challengeId, approval, expectedRowVersion) {
      try {
        const result = await sql.query<{
          approval_id: string;
          row_version: string | number;
        }>(APPROVAL_SQL.COMMIT_APPROVAL_MUTATION, [
          challengeId,
          approval.id,
          approval.method,
          approval.preimageText,
          approval.preimageSha256,
          approval.deviceKeyId,
          approval.deviceSignature,
          approval.totpTimestep,
          approval.consumedAt,
          expectedRowVersion,
          approval.operationId,
        ]);
        const row = result.rows[0];
        if (row === undefined) {
          return { kind: "OPERATION_CONFLICT" } satisfies CommitApprovalMutationResult;
        }
        return {
          kind: "APPLIED",
          rowVersion: Number(row.row_version),
        } satisfies CommitApprovalMutationResult;
      } catch (err) {
        if (isPgUnique(err)) {
          const kind = mapApprovalUniqueViolation(err.constraint);
          if (kind === "totp_timestep") {
            return { kind: "TOTP_REPLAY" } satisfies CommitApprovalMutationResult;
          }
          if (kind === "approval_operation" || kind === "approval_challenge") {
            return { kind: "APPROVAL_EXISTS" } satisfies CommitApprovalMutationResult;
          }
          throw new ApprovalStoreUniqueViolation(kind);
        }
        throw err;
      }
    },
  };
}
