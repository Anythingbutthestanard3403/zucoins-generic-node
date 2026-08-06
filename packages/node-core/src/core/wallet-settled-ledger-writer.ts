// production writer for the canonical wallet ledger `wallet_settled_ledger`, under the
// landing-path oracle.
//
// Derived ledger only: observes a successful land that already reached
// SETTLED_BODY_PERSISTED and has a landing-path oracle positive verdict. Does not gate landing,
// does not mutate operation_transactions beyond what the caller already advanced,
// and never releases leases.
//
// Write point: the landing DB-TX, after SETTLED_BODY_PERSISTED is durable and
// before COMMIT — not a later verification-complete path. Landing is the moment the
// node has both the settled body and the landing-path oracle path verdict; the
// operation_verifications row is recorded here as the VERIFIED fact the ledger trigger
// requires. Backfill of already-landed operations is not required: the table is derived
// and empty-before is indistinguishable from "no
// settlements" only going forward; a separate one-shot backfill can be scheduled if
// operators need historical rows.
//
// Idempotency: ON CONFLICT DO NOTHING on either unique key
// * (operation_id, attempt_no, operation_role)
// * (wallet_public_key, settled_transaction_sha256)
// plus a pre-check that reuses an existing VERIFIED operation_landing_proofs row so
// replaying the land does not mint a second proof/verification pair. The wallet-signature
// unique also means a second land of identical settled bytes for the same pubkey
// (only possible with reused golden vectors in tests) does not abort the land TX.
//
// SEND_EXTERNAL / MOVE_INTERNAL historically never wrote operation_wallets (only
// RECEIVE_EXTERNAL's pool allocator does). The ledger FK requires those participant
// rows, so this writer upserts them from operations.{source_wallet_id,destination_id}
// with ON CONFLICT DO NOTHING — observation of the land, not a new create-time contract.

import { createHash, randomUUID } from "node:crypto";

import {
  ONLY_ATTEMPT_NO,
  advanceAttemptPhase,
} from "./transaction-material-store.js";
import type { SqlQueryFn } from "./sql-query-fn.js";

export type SettledLedgerLandingVerdict = "LANDED_EXACT" | "LANDED_COMPLETE_PATH";

export type SettledLedgerOperationRole = "RECEIVER" | "SOURCE" | "DESTINATION";

export interface RecordWalletSettledLedgerInput {
  readonly operationId: string;
  readonly landingVerdict: SettledLedgerLandingVerdict;
  /** path depth (0 = LANDED_EXACT). */
  readonly pathDepth: number;
  /** Baseline T0 observation that anchors the land (must exist in gateway_observations). */
  readonly t0ObservationId: string;
  /** Terminal/fresh-head observation the path ends at. */
  readonly terminalObservationId: string;
  /**
   * MOVE dual-path lands require required_path_count = 2; RECEIVE/SEND use 1.
   * Defaults to 1.
   */
  readonly requiredPathCount?: 1 | 2;
  /** ISO-8601 instant for proof verified_at / created_at. Defaults to now. */
  readonly verifiedAtIso?: string;
}

export interface RecordWalletSettledLedgerResult {
  readonly landingProofId: string;
  readonly verificationId: string;
  readonly ledgerRolesWritten: readonly SettledLedgerOperationRole[];
  readonly reusedExistingProof: boolean;
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function buildSettledLedgerProofManifest(input: {
  readonly operationId: string;
  readonly expectedBodySha256: string;
  readonly verdict: SettledLedgerLandingVerdict;
  readonly bodyCount: number;
  readonly totalBodyBytes: number;
  readonly requiredPathCount: 1 | 2;
}): { readonly text: string; readonly sha256: string } {
  // Byte-stable field sequence (the byte-exact signing rule). Distinct purpose from the late-landing
  // SOURCE-path manifest so the two surfaces never collide if both fire.
  const text = JSON.stringify({
    purpose: "zp-wallet-settled-ledger-proof-v1",
    operation_id: input.operationId,
    attempt_no: ONLY_ATTEMPT_NO,
    expected_completed_transaction_sha256: input.expectedBodySha256,
    required_path_count: input.requiredPathCount,
    declared_body_count: input.bodyCount,
    declared_total_body_bytes: input.totalBodyBytes,
    verdict: input.verdict,
  });
  return { text, sha256: sha256HexUtf8(text) };
}

/**
 * Ensure operation_wallets carries every participant the landed kind requires.
 * RECEIVE already has RECEIVER from the pool allocator; SEND needs SOURCE; MOVE needs
 * SOURCE + DESTINATION. ON CONFLICT DO NOTHING so a second land is a no-op.
 */
async function ensureOperationWalletParticipants(
  query: SqlQueryFn,
  operationId: string,
): Promise<void> {
  const ops = await query(
    `SELECT kind::text AS kind,
            source_wallet_id::text AS source_wallet_id,
            receiver_wallet_id::text AS receiver_wallet_id,
            destination_id::text AS destination_id
       FROM operations
      WHERE id = $1::uuid`,
    [operationId],
  );
  const op = ops[0] as
    | {
        kind: string;
        source_wallet_id: string | null;
        receiver_wallet_id: string | null;
        destination_id: string | null;
      }
    | undefined;
  if (op === undefined) {
    throw new Error(
      `recordWalletSettledLedger: operation ${operationId} not found while ensuring participants`,
    );
  }

  const upsert = async (walletId: string, role: SettledLedgerOperationRole): Promise<void> => {
    await query(
      `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
       VALUES ($1::uuid, $2::uuid, $3)
       ON CONFLICT DO NOTHING`,
      [operationId, walletId, role],
    );
  };

  if (op.kind === "RECEIVE_EXTERNAL") {
    if (op.receiver_wallet_id !== null) {
      await upsert(op.receiver_wallet_id, "RECEIVER");
    }
    return;
  }
  if (op.kind === "SEND_EXTERNAL") {
    if (op.source_wallet_id === null) {
      throw new Error(
        `recordWalletSettledLedger: SEND_EXTERNAL ${operationId} has no source_wallet_id`,
      );
    }
    await upsert(op.source_wallet_id, "SOURCE");
    return;
  }
  if (op.kind === "MOVE_INTERNAL") {
    if (op.source_wallet_id === null || op.destination_id === null) {
      throw new Error(
        `recordWalletSettledLedger: MOVE_INTERNAL ${operationId} missing source/destination`,
      );
    }
    await upsert(op.source_wallet_id, "SOURCE");
    const dest = await query(
      `SELECT wallet_id::text AS wallet_id FROM destinations WHERE id = $1::uuid`,
      [op.destination_id],
    );
    const destWallet = (dest[0] as { wallet_id: string } | undefined)?.wallet_id;
    if (destWallet === undefined) {
      throw new Error(
        `recordWalletSettledLedger: destination ${op.destination_id} has no wallet`,
      );
    }
    await upsert(destWallet, "DESTINATION");
    return;
  }
  throw new Error(
    `recordWalletSettledLedger: unsupported operation kind ${op.kind} for ${operationId}`,
  );
}

/**
 * Record the landing proof + VERIFIED verification + per-role wallet_settled_ledger
 * rows for a just-landed operation. Caller MUST have advanced operation_transactions to
 * SETTLED_BODY_PERSISTED on this same transaction first.
 */
export async function recordWalletSettledLedger(
  query: SqlQueryFn,
  input: RecordWalletSettledLedgerInput,
): Promise<RecordWalletSettledLedgerResult> {
  const requiredPathCount = input.requiredPathCount ?? 1;
  const bodyCount = input.pathDepth + 1;
  if (
    (input.landingVerdict === "LANDED_EXACT" && input.pathDepth !== 0) ||
    (input.landingVerdict === "LANDED_COMPLETE_PATH" && input.pathDepth < 1)
  ) {
    throw new Error(
      `recordWalletSettledLedger: verdict ${input.landingVerdict} incompatible with pathDepth ${input.pathDepth}`,
    );
  }

  await ensureOperationWalletParticipants(query, input.operationId);

  // RECEIVE already advances to SETTLED_BODY_PERSISTED in sql-landing-store before
  // calling us. SEND/MOVE historically only marked SETTLED_BODY_PERSISTED on their
  // kind-local landing tables; promote operation_transactions here so the ledger
  // trigger's SETTLED_BODY_PERSISTED gate holds. advanceAttemptPhase is one-way and
  // no-ops into a throw only when the prior phase is wrong — we pre-check.
  const attemptsBefore = await query(
    `SELECT completed_transaction_text,
            completed_transaction_sha256,
            settled_at,
            attempt_phase::text AS attempt_phase
       FROM operation_transactions
      WHERE operation_id = $1::uuid AND attempt_no = ${ONLY_ATTEMPT_NO}`,
    [input.operationId],
  );
  const before = attemptsBefore[0] as
    | {
        completed_transaction_text: string | null;
        completed_transaction_sha256: string | null;
        settled_at: Date | string | null;
        attempt_phase: string;
      }
    | undefined;
  if (
    before === undefined ||
    before.completed_transaction_text === null ||
    before.completed_transaction_sha256 === null
  ) {
    throw new Error(
      `recordWalletSettledLedger: operation ${input.operationId} has no completed transaction body`,
    );
  }
  if (before.attempt_phase === "STEP2_SIGNATURE_PERSISTED") {
    await advanceAttemptPhase(query, input.operationId, "SETTLED_BODY_PERSISTED", {
      settled_at: input.verifiedAtIso ?? new Date().toISOString(),
    });
  } else if (before.attempt_phase !== "SETTLED_BODY_PERSISTED") {
    throw new Error(
      `recordWalletSettledLedger: operation ${input.operationId} attempt_phase=` +
        `${before.attempt_phase}; need STEP2_SIGNATURE_PERSISTED or SETTLED_BODY_PERSISTED`,
    );
  }

  const attempts = await query(
    `SELECT completed_transaction_text,
            completed_transaction_sha256,
            settled_at,
            attempt_phase::text AS attempt_phase
       FROM operation_transactions
      WHERE operation_id = $1::uuid AND attempt_no = ${ONLY_ATTEMPT_NO}`,
    [input.operationId],
  );
  const attempt = attempts[0] as
    | {
        completed_transaction_text: string | null;
        completed_transaction_sha256: string | null;
        settled_at: Date | string | null;
        attempt_phase: string;
      }
    | undefined;
  if (
    attempt === undefined ||
    attempt.attempt_phase !== "SETTLED_BODY_PERSISTED" ||
    attempt.completed_transaction_text === null ||
    attempt.completed_transaction_sha256 === null ||
    attempt.settled_at === null
  ) {
    throw new Error(
      `recordWalletSettledLedger: operation ${input.operationId} attempt is not SETTLED_BODY_PERSISTED`,
    );
  }

  const settledText = attempt.completed_transaction_text;
  const settledSha = attempt.completed_transaction_sha256;
  const settledAtIso =
    typeof attempt.settled_at === "string"
      ? attempt.settled_at
      : attempt.settled_at.toISOString();
  const totalBodyBytes = Buffer.byteLength(settledText, "utf8");

  // amount_zkz from the operations row (per-leg amount equals operation amount for all
  // three kinds — one settled body moves one amount).
  const amountRows = await query(
    `SELECT amount_zkz::text AS amount_zkz FROM operations WHERE id = $1::uuid`,
    [input.operationId],
  );
  const amountZkz = (amountRows[0] as { amount_zkz: string } | undefined)?.amount_zkz;
  if (amountZkz === undefined) {
    throw new Error(`recordWalletSettledLedger: amount_zkz missing for ${input.operationId}`);
  }

  // Verifier observer comes from the terminal observation (always a real
  // gateway_observations row after a positive land). T0 may be a synthetic id on
  // operations.t0_observation_id for a genesis baseline that never wrote an observation
  // row — operation_verifications.t0_observation_id is NOT NULL FK, so fall back to the
  // terminal observation when the declared T0 is absent from the ledger.
  const terminalObs = await query(
    `SELECT observer_id::text AS observer_id
       FROM gateway_observations
      WHERE id = $1::uuid`,
    [input.terminalObservationId],
  );
  const verifierObserverId = (terminalObs[0] as { observer_id: string } | undefined)
    ?.observer_id;
  if (verifierObserverId === undefined) {
    throw new Error(
      `recordWalletSettledLedger: terminal observation ${input.terminalObservationId} not found`,
    );
  }
  const t0Exists = await query(
    `SELECT 1 AS ok FROM gateway_observations WHERE id = $1::uuid`,
    [input.t0ObservationId],
  );
  const t0ObservationIdForVerification =
    t0Exists[0] === undefined ? input.terminalObservationId : input.t0ObservationId;

  // Reuse an existing VERIFIED proof for this operation so land-replay is idempotent.
  const existing = await query(
    `SELECT olp.id::text AS landing_proof_id,
            ov.id::text AS verification_id
       FROM operation_landing_proofs olp
       INNER JOIN operation_verifications ov
         ON ov.landing_proof_id = olp.id
        AND ov.operation_id = olp.operation_id
        AND ov.verdict = 'VERIFIED'
      WHERE olp.operation_id = $1::uuid
        AND olp.verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')
      ORDER BY olp.created_at ASC -- contract-allow:order:frozen-sql-text
      LIMIT 1`,
    [input.operationId],
  );
  let landingProofId: string;
  let verificationId: string;
  let reusedExistingProof = false;

  const verifiedAtIso = input.verifiedAtIso ?? new Date().toISOString();

  if (existing[0] !== undefined) {
    const row = existing[0] as { landing_proof_id: string; verification_id: string };
    landingProofId = row.landing_proof_id;
    verificationId = row.verification_id;
    reusedExistingProof = true;
  } else {
    landingProofId = randomUUID();
    verificationId = randomUUID();
    const manifest = buildSettledLedgerProofManifest({
      operationId: input.operationId,
      expectedBodySha256: settledSha,
      verdict: input.landingVerdict,
      bodyCount,
      totalBodyBytes,
      requiredPathCount,
    });

    await query(
      `INSERT INTO operation_landing_proofs (
         id, operation_id, verifier_observer_id, expected_transaction_attempt_no,
         verdict, required_path_count, declared_body_count, declared_total_body_bytes,
         proof_manifest_text, proof_manifest_sha256, verified_at, created_at
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, ${ONLY_ATTEMPT_NO},
         $4::lineage_proof_verdict, $5::integer, $6::bigint, $7::bigint,
         $8, $9, $10::timestamptz, $10::timestamptz
       )`,
      [
        landingProofId,
        input.operationId,
        verifierObserverId,
        input.landingVerdict,
        requiredPathCount,
        bodyCount,
        totalBodyBytes,
        manifest.text,
        manifest.sha256,
        verifiedAtIso,
      ],
    );

    await query(
      `INSERT INTO operation_verifications (
         id, operation_id, verifier_observer_id,
         t0_observation_id, terminal_observation_id, landing_proof_id,
         verdict, reason_code, proof_manifest_text, proof_manifest_sha256, created_at
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid,
         $4::uuid, $5::uuid, $6::uuid,
         'VERIFIED'::verification_verdict, 'LANDED_VERIFIED', $7, $8, $9::timestamptz
       )
       ON CONFLICT (operation_id, verifier_observer_id, t0_observation_id, terminal_observation_id)
       DO NOTHING`,
      [
        verificationId,
        input.operationId,
        verifierObserverId,
        t0ObservationIdForVerification,
        input.terminalObservationId,
        landingProofId,
        manifest.text,
        manifest.sha256,
        verifiedAtIso,
      ],
    );

    // If the unique conflict fired (parallel land), reload the winning verification id.
    const verified = await query(
      `SELECT id::text AS verification_id, landing_proof_id::text AS landing_proof_id
         FROM operation_verifications
        WHERE operation_id = $1::uuid
          AND verdict = 'VERIFIED'
          AND landing_proof_id IS NOT NULL
        ORDER BY created_at ASC -- contract-allow:order:frozen-sql-text
        LIMIT 1`,
      [input.operationId],
    );
    const win = verified[0] as
      | { verification_id: string; landing_proof_id: string }
      | undefined;
    if (win === undefined) {
      throw new Error(
        `recordWalletSettledLedger: VERIFIED verification missing after insert for ${input.operationId}`,
      );
    }
    verificationId = win.verification_id;
    landingProofId = win.landing_proof_id;
  }

  // Participants + pubkey for each role.
  const participants = await query(
    `SELECT ow.wallet_id::text AS wallet_id,
            ow.operation_role AS operation_role,
            w.public_key AS wallet_public_key
       FROM operation_wallets ow
       INNER JOIN wallets w ON w.id = ow.wallet_id
      WHERE ow.operation_id = $1::uuid
      ORDER BY ow.operation_role ASC`, // contract-allow:order:frozen-sql-text
    [input.operationId],
  );
  if (participants.length === 0) {
    throw new Error(
      `recordWalletSettledLedger: no operation_wallets rows for ${input.operationId}`,
    );
  }

  const rolesWritten: SettledLedgerOperationRole[] = [];
  for (const p of participants) {
    const row = p as {
      wallet_id: string;
      operation_role: SettledLedgerOperationRole;
      wallet_public_key: string;
    };
    await query(
      `INSERT INTO wallet_settled_ledger (
         id, wallet_id, wallet_public_key, operation_id, attempt_no, operation_role,
         amount_zkz, settled_transaction_text, settled_transaction_sha256,
         landing_proof_id, landing_verdict, settled_at
       ) VALUES (
         $1::uuid, $2::uuid, $3, $4::uuid, ${ONLY_ATTEMPT_NO}, $5,
         $6, $7, $8,
         $9::uuid, $10, $11::timestamptz
       )
       ON CONFLICT DO NOTHING`,
      [
        randomUUID(),
        row.wallet_id,
        row.wallet_public_key,
        input.operationId,
        row.operation_role,
        amountZkz,
        settledText,
        settledSha,
        landingProofId,
        input.landingVerdict,
        settledAtIso,
      ],
    );
    rolesWritten.push(row.operation_role);
  }

  return {
    landingProofId,
    verificationId,
    ledgerRolesWritten: rolesWritten,
    reusedExistingProof,
  };
}
