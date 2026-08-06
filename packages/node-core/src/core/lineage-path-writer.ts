// Durable lineage_path_proofs / lineage_path_bodies writer.
//
// Verification material reads these rows, and the complete-path oracle adjudicates over
// them. The exposure layer (observation/verification/source-sql) joins
// these tables through operation_landing_proofs; landers must promote the ordered path
// into them in the same TX as the landing proof header.
//
// RECEIVE lands into receive_landing_proofs / receive_landing_path_bodies (kind-local);
// this module promotes that durable path into the lineage verifier tables. SEND/MOVE callers
// pass already-assembled LineagePathBodyRow[] (late-landing / dual-path assembly).
//
// The byte-exact signing rule: completed_transaction_text / inner_preimage_text / signatures are copied
// VERBATIM — never re-serialized from a parsed object.

import { createHash, randomUUID } from "node:crypto";

import type { SqlQueryFn } from "./sql-query-fn.js";
import type { LineagePathRole } from "../verifier/ancestry-walker.js";

/** Positive landed verdicts only — INDETERMINATE/INVARIANT_BREACH never write lineage paths. */
export type LineageLandedVerdict = "LANDED_EXACT" | "LANDED_COMPLETE_PATH";

export type LineageBodySourceKind =
  | "EXPECTED_OPERATION"
  | "CANONICAL_LEDGER"
  | "PROOF_CHANNEL"
  | "FRESH_GATEWAY_HEAD";

export interface LineageBodyInput {
  readonly pathIndex: number;
  readonly sourceKind: LineageBodySourceKind;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
  readonly completedTransactionOctets: number;
  readonly walletRole: "sender" | "receiver";
  readonly sSignature: string;
  readonly pSignature: string;
  readonly bAmount: string;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
  /** Optional precomputed per-body manifest; computed here when omitted. */
  readonly verificationManifestText?: string;
  readonly verificationManifestSha256?: string;
}

export interface WriteLineagePathInput {
  readonly landingProofId: string;
  readonly pathRole: LineagePathRole;
  readonly walletId: string | null;
  readonly walletPublicKey: string;
  readonly t0ObservationId: string;
  readonly freshHeadObservationId: string;
  readonly expectedCompletedTransactionSha256: string;
  readonly freshHeadCompletedTransactionSha256: string;
  readonly verdict: LineageLandedVerdict;
  readonly pathDepth: number;
  /** Path-level manifest (`proof_manifest_*` columns). */
  readonly proofManifestText: string;
  readonly proofManifestSha256: string;
  readonly bodies: readonly LineageBodyInput[];
  readonly createdAtIso?: string;
  /** Stable id for idempotent re-entry; randomUUID when omitted. */
  readonly pathProofId?: string;
}

export interface WriteLineagePathResult {
  readonly pathProofId: string;
  readonly bodyCount: number;
  readonly reusedExisting: boolean;
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function bodyManifest(body: LineageBodyInput): { text: string; sha256: string } {
  if (
    body.verificationManifestText !== undefined &&
    body.verificationManifestSha256 !== undefined
  ) {
    return {
      text: body.verificationManifestText,
      sha256: body.verificationManifestSha256,
    };
  }
  const text = JSON.stringify({
    path_index: body.pathIndex,
    completed_transaction_sha256: body.completedTransactionSha256,
    completed_transaction_octets: body.completedTransactionOctets,
    s_signature: body.sSignature,
    p_signature: body.pSignature,
    b_amount: body.bAmount,
    wallet_role: body.walletRole,
    inner_sha256: body.innerSha256,
  });
  return { text, sha256: sha256HexUtf8(text) };
}

/**
 * Insert one lineage path + ordered bodies under an existing operation_landing_proofs row.
 * Idempotent on (landing_proof_id, path_role): a prior write is reused, bodies not re-inserted.
 */
export async function writeLineagePath(
  query: SqlQueryFn,
  input: WriteLineagePathInput,
): Promise<WriteLineagePathResult> {
  const bodyCount = input.pathDepth + 1;
  if (input.bodies.length !== bodyCount) {
    throw new Error(
      `writeLineagePath: body count ${input.bodies.length} != pathDepth+1 ${bodyCount}`,
    );
  }
  if (
    (input.verdict === "LANDED_EXACT" && input.pathDepth !== 0) ||
    (input.verdict === "LANDED_COMPLETE_PATH" && input.pathDepth < 1)
  ) {
    throw new Error(
      `writeLineagePath: verdict ${input.verdict} incompatible with pathDepth ${input.pathDepth}`,
    );
  }

  const existing = await query(
    `SELECT id::text AS id
       FROM lineage_path_proofs
      WHERE landing_proof_id = $1::uuid AND path_role = $2
      LIMIT 1`,
    [input.landingProofId, input.pathRole],
  );
  if (existing[0] !== undefined) {
    const row = existing[0] as { id: string };
    return {
      pathProofId: row.id,
      bodyCount,
      reusedExisting: true,
    };
  }

  const pathProofId = input.pathProofId ?? randomUUID();
  const createdAt = input.createdAtIso ?? new Date().toISOString();

  await query(
    `INSERT INTO lineage_path_proofs (
       id, landing_proof_id, path_role, wallet_id, wallet_public_key,
       t0_observation_id, fresh_head_observation_id,
       expected_completed_transaction_sha256, fresh_head_completed_transaction_sha256,
       body_count, path_depth, verdict, proof_manifest_text, proof_manifest_sha256, created_at
     ) VALUES (
       $1::uuid, $2::uuid, $3, $4::uuid, $5,
       $6::uuid, $7::uuid,
       $8, $9,
       $10::bigint, $11::bigint, $12::lineage_proof_verdict, $13, $14, $15::timestamptz
     )`,
    [
      pathProofId,
      input.landingProofId,
      input.pathRole,
      input.walletId,
      input.walletPublicKey,
      input.t0ObservationId,
      input.freshHeadObservationId,
      input.expectedCompletedTransactionSha256,
      input.freshHeadCompletedTransactionSha256,
      bodyCount,
      input.pathDepth,
      input.verdict,
      input.proofManifestText,
      input.proofManifestSha256,
      createdAt,
    ],
  );

  const ordered = [...input.bodies].sort((a, b) => a.pathIndex - b.pathIndex);
  for (const body of ordered) {
    const manifest = bodyManifest(body);
    await query(
      `INSERT INTO lineage_path_bodies (
         path_proof_id, path_index, source_kind,
         completed_transaction_text, completed_transaction_sha256, completed_transaction_octets,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, inner_sha256, step_1_signature, step_2_signature,
         verification_manifest_text, verification_manifest_sha256
       ) VALUES (
         $1::uuid, $2::bigint, $3,
         $4, $5, $6::bigint,
         $7, $8, $9, $10,
         $11, $12, $13, $14,
         $15, $16
       )`,
      [
        pathProofId,
        body.pathIndex,
        body.sourceKind,
        body.completedTransactionText,
        body.completedTransactionSha256,
        body.completedTransactionOctets,
        body.walletRole,
        body.sSignature,
        body.pSignature,
        body.bAmount,
        body.innerPreimageText,
        body.innerSha256,
        body.step1Signature,
        body.step2Signature,
        manifest.text,
        manifest.sha256,
      ],
    );
  }

  return { pathProofId, bodyCount, reusedExisting: false };
}

/**
 * Promote a RECEIVE_EXTERNAL kind-local landing path into the lineage tables.
 * Reads receive_landing_proofs + receive_landing_path_bodies for the operation and
 * writes lineage_path_proofs / lineage_path_bodies under the given landingProofId.
 */
export async function promoteReceiveLandingPathToLineage(
  query: SqlQueryFn,
  input: {
    readonly operationId: string;
    readonly landingProofId: string;
    readonly walletId: string | null;
    readonly createdAtIso?: string;
  },
): Promise<WriteLineagePathResult | null> {
  const headers = await query(
    `SELECT path_role,
            wallet_public_key,
            t0_observation_id::text AS t0_observation_id,
            fresh_head_observation_id::text AS fresh_head_observation_id,
            expected_completed_transaction_sha256,
            fresh_head_completed_transaction_sha256,
            verdict,
            body_count::text AS body_count,
            path_depth::text AS path_depth,
            path_manifest_text,
            path_manifest_sha256
       FROM receive_landing_proofs
      WHERE operation_id = $1::uuid`,
    [input.operationId],
  );
  const header = headers[0] as
    | {
        path_role: string;
        wallet_public_key: string;
        t0_observation_id: string;
        fresh_head_observation_id: string;
        expected_completed_transaction_sha256: string;
        fresh_head_completed_transaction_sha256: string;
        verdict: string;
        body_count: string;
        path_depth: string;
        path_manifest_text: string;
        path_manifest_sha256: string;
      }
    | undefined;
  if (header === undefined) return null;

  // operation_verifications already falls back when t0 is missing; lineage FKs must
  // resolve the same way so promotion cannot abort a land that settled-ledger accepted.
  async function resolveObservationId(preferred: string, fallback: string): Promise<string> {
    const hit = await query(
      `SELECT 1 AS ok FROM gateway_observations WHERE id = $1::uuid`,
      [preferred],
    );
    if (hit[0] !== undefined) return preferred;
    const fb = await query(
      `SELECT 1 AS ok FROM gateway_observations WHERE id = $1::uuid`,
      [fallback],
    );
    if (fb[0] !== undefined) return fallback;
    throw new Error(
      `promoteReceiveLandingPathToLineage: neither t0=${preferred} nor terminal=${fallback} exists in gateway_observations`,
    );
  }
  const t0Id = await resolveObservationId(
    header.t0_observation_id,
    header.fresh_head_observation_id,
  );
  const freshId = await resolveObservationId(
    header.fresh_head_observation_id,
    t0Id,
  );

  const bodyRows = await query(
    `SELECT path_index::text AS path_index,
            source_kind,
            completed_transaction_text,
            completed_transaction_sha256,
            completed_transaction_octets::text AS completed_transaction_octets,
            wallet_role,
            s_signature,
            p_signature,
            b_amount,
            inner_preimage_text,
            inner_sha256,
            step_1_signature,
            step_2_signature
       FROM receive_landing_path_bodies
      WHERE operation_id = $1::uuid
      ORDER BY path_index ASC`, // contract-allow:order:frozen-sql-text
    [input.operationId],
  );

  const verdict =
    header.verdict === "LANDED_COMPLETE_PATH"
      ? ("LANDED_COMPLETE_PATH" as const)
      : ("LANDED_EXACT" as const);
  const pathDepth = Number(header.path_depth);
  const bodies: LineageBodyInput[] = bodyRows.map((raw) => {
    const r = raw as {
      path_index: string;
      source_kind: string;
      completed_transaction_text: string;
      completed_transaction_sha256: string;
      completed_transaction_octets: string;
      wallet_role: string;
      s_signature: string;
      p_signature: string;
      b_amount: string;
      inner_preimage_text: string;
      inner_sha256: string;
      step_1_signature: string;
      step_2_signature: string;
    };
    return {
      pathIndex: Number(r.path_index),
      sourceKind: r.source_kind as LineageBodySourceKind,
      completedTransactionText: r.completed_transaction_text,
      completedTransactionSha256: r.completed_transaction_sha256,
      completedTransactionOctets: Number(r.completed_transaction_octets),
      walletRole: r.wallet_role as "sender" | "receiver",
      sSignature: r.s_signature,
      pSignature: r.p_signature,
      bAmount: r.b_amount,
      innerPreimageText: r.inner_preimage_text,
      innerSha256: r.inner_sha256,
      step1Signature: r.step_1_signature,
      step2Signature: r.step_2_signature,
    };
  });

  return writeLineagePath(query, {
    landingProofId: input.landingProofId,
    pathRole: "RECEIVER",
    walletId: input.walletId,
    walletPublicKey: header.wallet_public_key,
    t0ObservationId: t0Id,
    freshHeadObservationId: freshId,
    expectedCompletedTransactionSha256: header.expected_completed_transaction_sha256,
    freshHeadCompletedTransactionSha256: header.fresh_head_completed_transaction_sha256,
    verdict,
    pathDepth,
    proofManifestText: header.path_manifest_text,
    proofManifestSha256: header.path_manifest_sha256,
    bodies,
    createdAtIso: input.createdAtIso,
  });
}

/**
 * Write a depth-0 SOURCE (or single-role) path from the settled operation_transactions body
 * when the lander has no multi-hop path assembly. Used for SEND_EXTERNAL depth-0 lands and
 * as a fallback when only the expected body is durable.
 */
export async function writeExactHeadLineagePath(
  query: SqlQueryFn,
  input: {
    readonly operationId: string;
    readonly landingProofId: string;
    readonly pathRole: LineagePathRole;
    readonly walletId: string | null;
    readonly walletPublicKey: string;
    readonly t0ObservationId: string;
    readonly freshHeadObservationId: string;
    readonly verdict: LineageLandedVerdict;
    readonly pathDepth: number;
    readonly proofManifestText: string;
    readonly proofManifestSha256: string;
    /** Optional ordered bodies; when omitted and pathDepth===0, loads attempt_no=1 settled body. */
    readonly bodies?: readonly LineageBodyInput[];
    readonly createdAtIso?: string;
  },
): Promise<WriteLineagePathResult> {
  let bodies = input.bodies;
  let effectiveDepth = input.pathDepth;
  let effectiveVerdict = input.verdict;
  // Multi-hop body assembly is owned by the ancestry walker / late-landing path store.
  // When only the settled attempt body is durable (common depth-0 land), write a depth-0
  // lineage path so verification-material can serve ancestor_proofs. Callers with full ordered
  // bodies pass them explicitly.
  if (bodies === undefined) {
    effectiveDepth = 0;
    effectiveVerdict = "LANDED_EXACT";
    const rows = await query(
      `SELECT completed_transaction_text,
              completed_transaction_sha256,
              inner_preimage_text,
              inner_sha256,
              step_1_signature,
              step_2_signature
         FROM operation_transactions
        WHERE operation_id = $1::uuid AND attempt_no = 1`,
      [input.operationId],
    );
    const row = rows[0] as
      | {
          completed_transaction_text: string;
          completed_transaction_sha256: string;
          inner_preimage_text: string;
          inner_sha256: string;
          step_1_signature: string;
          step_2_signature: string;
        }
      | undefined;
    if (row === undefined || row.completed_transaction_text === null) {
      throw new Error(
        `writeExactHeadLineagePath: no settled body for operation ${input.operationId}`,
      );
    }
    // Parse projections from settled body without re-serializing the completed text.
    let sSig = row.step_2_signature;
    let pSig = "";
    let bAmount = "0";
    try {
      const parsed = JSON.parse(row.completed_transaction_text) as {
        inner?: {
          previous_step_1_state_signature?: string;
          step_1_state?: { amount?: string };
        };
        step_2_signature?: string;
      };
      if (typeof parsed.step_2_signature === "string") sSig = parsed.step_2_signature;
      const prev = parsed.inner?.previous_step_1_state_signature;
      pSig = typeof prev === "string" ? prev : "";
      const amt = parsed.inner?.step_1_state?.amount;
      if (typeof amt === "string") bAmount = amt;
    } catch {
      /* keep defaults; CHECKs still require valid signatures from columns */
    }
    const octets = Buffer.byteLength(row.completed_transaction_text, "utf8");
    bodies = [
      {
        pathIndex: 0,
        sourceKind: "EXPECTED_OPERATION",
        completedTransactionText: row.completed_transaction_text,
        completedTransactionSha256: row.completed_transaction_sha256,
        completedTransactionOctets: octets,
        walletRole: input.pathRole === "RECEIVER" ? "receiver" : "sender",
        sSignature: sSig,
        pSignature: pSig,
        bAmount,
        innerPreimageText: row.inner_preimage_text,
        innerSha256: row.inner_sha256,
        step1Signature: row.step_1_signature,
        step2Signature: row.step_2_signature,
      },
    ];
  }

  const expectedSha = bodies[0]!.completedTransactionSha256;
  const headSha = bodies[bodies.length - 1]!.completedTransactionSha256;

  async function resolveObs(preferred: string, fallback: string): Promise<string> {
    const hit = await query(
      `SELECT 1 AS ok FROM gateway_observations WHERE id = $1::uuid`,
      [preferred],
    );
    if (hit[0] !== undefined) return preferred;
    const fb = await query(
      `SELECT 1 AS ok FROM gateway_observations WHERE id = $1::uuid`,
      [fallback],
    );
    if (fb[0] !== undefined) return fallback;
    throw new Error(
      `writeExactHeadLineagePath: observation ids missing t0=${preferred} fresh=${fallback}`,
    );
  }
  const t0Id = await resolveObs(input.t0ObservationId, input.freshHeadObservationId);
  const freshId = await resolveObs(input.freshHeadObservationId, t0Id);

  return writeLineagePath(query, {
    landingProofId: input.landingProofId,
    pathRole: input.pathRole,
    walletId: input.walletId,
    walletPublicKey: input.walletPublicKey,
    t0ObservationId: t0Id,
    freshHeadObservationId: freshId,
    expectedCompletedTransactionSha256: expectedSha,
    freshHeadCompletedTransactionSha256: headSha,
    verdict: effectiveVerdict,
    pathDepth: effectiveDepth,
    proofManifestText: input.proofManifestText,
    proofManifestSha256: input.proofManifestSha256,
    bodies,
    createdAtIso: input.createdAtIso,
  });
}
