// Durable ReceiveCodeFormationStore over operation_expected_artifacts + receive_codes
// (+ process staging for the unsigned preimage before signature insert).
// operation_expected_artifacts requires signature NOT NULL (insert-only), so unsigned
// preimages stage in-process until persistArtifactSignature. Never invents recovery_verified.

import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
  type ReceiveCodeFormationStore,
} from "@zucoins/node-core";

type StagedPreimage = {
  readonly artifactId: string;
  readonly operationId: string;
  readonly purpose: typeof RECEIVE_EXPECTED_ARTIFACT_PURPOSE;
  readonly canonicalVersion: 1;
  readonly preimageText: string;
  readonly preimageSha256: string;
  signingKeyId: string | null;
  signature: string | null;
};

export function createSqlReceiveCodeFormationStore(pool: Pool): ReceiveCodeFormationStore {
  const staged = new Map<string, StagedPreimage>();

  return {
    async persistArtifactPreimage(input) {
      const existing = staged.get(input.operationId);
      if (existing !== undefined) {
        if (
          existing.preimageText !== input.preimageText ||
          existing.preimageSha256 !== input.preimageSha256
        ) {
          throw new Error("preimage bytes diverged on re-persist");
        }
        return { artifactId: existing.artifactId, alreadyPresent: true };
      }

      const durable = await pool.query<{
        id: string;
        preimage_text: string;
        preimage_sha256: string;
      }>(
        `SELECT id::text AS id, preimage_text, preimage_sha256
           FROM operation_expected_artifacts
          WHERE operation_id = $1::uuid LIMIT 1`,
        [input.operationId],
      );
      const row = durable.rows[0];
      if (row !== undefined) {
        if (
          row.preimage_text !== input.preimageText ||
          row.preimage_sha256 !== input.preimageSha256
        ) {
          throw new Error("preimage bytes diverged vs durable artifact");
        }
        return { artifactId: row.id, alreadyPresent: true };
      }

      staged.set(input.operationId, {
        artifactId: input.artifactId,
        operationId: input.operationId,
        purpose: input.purpose,
        canonicalVersion: input.canonicalVersion,
        preimageText: input.preimageText,
        preimageSha256: input.preimageSha256,
        signingKeyId: null,
        signature: null,
      });
      return { artifactId: input.artifactId, alreadyPresent: false };
    },

    async persistArtifactSignature(input) {
      const entry = staged.get(input.operationId);
      if (entry === undefined) {
        const durable = await pool.query<{ preimage_sha256: string }>(
          `SELECT preimage_sha256 FROM operation_expected_artifacts
            WHERE operation_id = $1::uuid AND id = $2::uuid LIMIT 1`,
          [input.operationId, input.artifactId],
        );
        if (durable.rows[0]?.preimage_sha256 === input.expectedPreimageSha256) return;
        throw new Error("no staged preimage for signature persist");
      }
      if (entry.preimageSha256 !== input.expectedPreimageSha256) {
        throw new Error("signature digest mismatch");
      }

      await pool.query(
        `INSERT INTO operation_expected_artifacts (
           id, operation_id, purpose, canonical_version,
           signing_key_id, preimage_text, preimage_sha256, signature
         ) VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8)
         ON CONFLICT (operation_id) DO NOTHING`,
        [
          input.artifactId,
          input.operationId,
          entry.purpose,
          entry.canonicalVersion,
          input.signingKeyId,
          entry.preimageText,
          entry.preimageSha256,
          input.signature,
        ],
      );

      await pool.query(
        `INSERT INTO signer_audit (
           id, node_id, operation_id, lease_group_id, lease_epoch,
           preimage_sha256, called_at, outcome, purpose
         )
         SELECT $1::uuid, o.node_id, $2::uuid, NULL, NULL, $3, now(), 'SUCCEEDED', 'EXPECTED_ARTIFACT'
           FROM operations o WHERE o.id = $2::uuid
         ON CONFLICT DO NOTHING`,
        [randomUUID(), input.operationId, entry.preimageSha256],
      );

      staged.delete(input.operationId);
    },

    async loadArtifactPreimage(operationId) {
      const entry = staged.get(operationId);
      if (entry !== undefined) {
        return {
          artifactId: entry.artifactId,
          preimageText: entry.preimageText,
          preimageSha256: entry.preimageSha256,
          signingKeyId: entry.signingKeyId,
          signature: entry.signature,
        };
      }
      const result = await pool.query<{
        id: string;
        preimage_text: string;
        preimage_sha256: string;
        signing_key_id: string;
        signature: string;
      }>(
        `SELECT id::text AS id, preimage_text, preimage_sha256,
                signing_key_id::text AS signing_key_id, signature
           FROM operation_expected_artifacts
          WHERE operation_id = $1::uuid LIMIT 1`,
        [operationId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        artifactId: row.id,
        preimageText: row.preimage_text,
        preimageSha256: row.preimage_sha256,
        signingKeyId: row.signing_key_id,
        signature: row.signature,
      };
    },

    async hasSignerAuditForArtifact(operationId) {
      const result = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM signer_audit
          WHERE operation_id = $1::uuid AND purpose = 'EXPECTED_ARTIFACT' AND outcome = 'SUCCEEDED'`,
        [operationId],
      );
      return Number(result.rows[0]?.n ?? 0) > 0;
    },

    async hasCompleteCodeRecord(operationId) {
      const result = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM receive_codes WHERE operation_id = $1::uuid`,
        [operationId],
      );
      return Number(result.rows[0]?.n ?? 0) > 0;
    },
  };
}
