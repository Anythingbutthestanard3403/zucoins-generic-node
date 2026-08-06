// assemble verification-material from durable tables.
//
// 1 (response shape)
// 14 (independent verification channel; node raw body is non-authoritative
// evidence about what the node observed);, 7.1, 9, 11
// (operation_expected_artifacts, move_observation_evidence / gateway_observations,
// operation_transactions, operation_landing_proofs / lineage_path_proofs /
// lineage_path_bodies).
//
// This is the LOAD + MAP half of the endpoint body. The pure wire assembler is
// `assembleVerificationMaterial` (material.ts). The HTTP 409/200/410
// binder is `handleGetVerificationMaterial` (api/verification-material.ts).
// Access-window RECORDS (issue/authorize/revoke + read audit) are
// (`api/verification-access.ts`) and are composed at the api edge via
// `createGatedTableVerificationMaterialSource`.
//
// Boundary: observation may import only protocol (test/boundaries.test.ts). This
// module never imports api/ — it returns a plain assembled bag the api edge binds.
//
// No private keys, vault ciphertext, or TOTP material ever cross this surface
// (excluded by construction). Signed transaction text and raw observation
// bytes pass through VERBATIM — never parsed and re-serialized.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import {
  asVerificationMaterialFields,
  assembleVerificationMaterial,
  type AncestorClassification,
  type AncestorProofInput,
  type AttemptMaterial,
  type EvidenceRole,
  type ExpectedArtifactMaterial,
  type IndeterminateReason,
  type ObservationEvidenceMaterial,
  type PathManifestEntry,
  type TransactionBodyMaterial,
  type VerificationMaterialPayload,
} from "./material.js";

// --- Durable row shapes (field names match SQL columns) ---------------

/** operations header needed for the gate + wire envelope. Tenant = implementer_id. */
export interface DurableOperationHeader {
  readonly id: string;
  readonly implementer_id: string;
  readonly kind: OperationKind;
  readonly status: string;
  /** Millisecond epoch of `operations.verification_material_available_until`, or null. */
  readonly verification_material_available_until_ms: number | null;
  /**
   * Landed attempt number when known (operation_landing_proofs.expected_transaction_attempt_no
   * or the attempt carrying LANDED_VERIFIED). Null when not yet landed.
   */
  readonly landed_attempt_no: number | null;
}

/** operation_expected_artifacts — wire `key_id` is `signing_key_id`. */
export interface DurableExpectedArtifactRow {
  readonly signing_key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

/**
 * One observation used inside observation_evidence. Raw body is node-captured evidence
 * about what the node observed — not a substitute for the caller's independent gateway
 * read.
 */
export interface DurableObservationRow {
  readonly id: string;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  /** Empty string for genesis S/P. */
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  /**
   * Exact `gateway_observations.raw_response_bytes` as base64 (standard). Empty string
   * when the durable row has no body (should not happen for a correctness observation).
   */
  readonly raw_response_body_base64: string;
}

/** One observation_evidence entry as stored across bindings / evidence tables. */
export interface DurableObservationEvidenceRow {
  readonly evidence_role: EvidenceRole;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  readonly t0: DurableObservationRow;
  /** Null for formation-only counterparties (EXTERNAL_DESTINATION_PARTIAL etc.). */
  readonly terminal: DurableObservationRow | null;
}

/** operation_transactions row projected for attempts[].transaction. */
export interface DurableAttemptRow {
  readonly attempt_no: number;
  /**
   * Recovery classification: LANDED_VERIFIED, PROVEN_NOT_LANDED, etc.
   * Stored alongside the attempt by the recovery/landing writer; never inferred here
   * from phase alone when a determinate classification is available.
   */
  readonly classification: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_preimage_text: string;
  readonly step_2_signature: string;
  /** Prefer completed_transaction_text; fall back only when settled body is the sole column. */
  readonly settled_transaction_text: string;
}

/**
 * lineage_path_proofs (+ ordered lineage_path_bodies) for one wallet role.
 * `path_role` maps 1:1 onto wire `evidence_role` for RECEIVER/SOURCE/DESTINATION
 * (CHECK; EXTERNAL_* roles never appear on lineage paths).
 */
export interface DurableLineagePathRow {
  readonly path_role: "RECEIVER" | "SOURCE" | "DESTINATION";
  readonly wallet_public_key: string;
  /** lineage_proof_verdict — mapped to ancestor classification. */
  readonly verdict: string;
  readonly expected_step_2_signature: string;
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  /**
   * Bodies in ascending path_index. Body 0 is the expected completed transaction
   * Empty when the path was never fully retained (diagnostic / INDETERMINATE).
   */
  readonly bodies: readonly DurableLineageBodyRow[];
  /**
   * When the durable verdict is already INDETERMINATE / INVARIANT_BREACH, the writer
   * may have recorded a reason. Null means the assembler will re-assess completeness.
   */
  readonly indeterminate_reason: IndeterminateReason | null;
}

export interface DurableLineageBodyRow {
  readonly path_index: number;
  readonly step_2_signature: string;
  /** Queried-wallet previous signature = this body's p_signature (predecessor backlink). */
  readonly p_signature: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_text: string;
}

// --- Table port -------------------------------------------------------------------------

/**
 * Read-only port over the durable observation tables. Implementations may be
 * SQL (SqlQueryFn) or an in-memory fixture store. Cross-tenant collapse is the port's
 * job: `loadOperation` MUST return null when implementer_id does not match.
 */
export interface VerificationMaterialTablePort {
  loadOperation(
    operationId: string,
    implementerId: string,
  ): Promise<DurableOperationHeader | null>;
  loadExpectedArtifact(operationId: string): Promise<DurableExpectedArtifactRow | null>;
  loadObservationEvidence(
    operationId: string,
    kind: OperationKind,
  ): Promise<readonly DurableObservationEvidenceRow[]>;
  loadAttempts(operationId: string): Promise<readonly DurableAttemptRow[]>;
  loadAncestorPaths(operationId: string): Promise<readonly DurableLineagePathRow[]>;
}

// --- Mapping ----------------------------------------------------------------------------

function mapExpectedArtifact(row: DurableExpectedArtifactRow): ExpectedArtifactMaterial {
  return {
    key_id: row.signing_key_id,
    preimage_text: row.preimage_text,
    preimage_sha256: row.preimage_sha256,
    signature: row.signature,
  };
}

function mapObservationProjection(obs: DurableObservationRow): {
  observation_id: string;
  projection: { s: string; p: string; b_zkz: string };
} {
  return {
    observation_id: obs.id,
    projection: {
      s: obs.s_signature,
      p: obs.p_signature,
      b_zkz: obs.b_amount,
    },
  };
}

function mapObservationEvidence(
  row: DurableObservationEvidenceRow,
): ObservationEvidenceMaterial {
  // Prefer the terminal observation's raw body when present (landing evidence); otherwise
  // the T0 capture. Labelled non-authoritative on the wire type.
  const raw =
    row.terminal !== null && row.terminal.raw_response_body_base64.length > 0
      ? row.terminal.raw_response_body_base64
      : row.t0.raw_response_body_base64;
  return {
    evidence_role: row.evidence_role,
    wallet_id: row.wallet_id,
    wallet_public_key: row.wallet_public_key,
    t0: mapObservationProjection(row.t0),
    terminal: row.terminal === null ? null : mapObservationProjection(row.terminal),
    node_observation_raw_body_base64: raw,
  };
}

function mapAttempt(row: DurableAttemptRow): AttemptMaterial {
  return {
    attempt_no: row.attempt_no,
    classification: row.classification,
    transaction: {
      inner_preimage_text: row.inner_preimage_text,
      inner_sha256: row.inner_sha256,
      step_1_signature: row.step_1_signature,
      step_2_preimage_text: row.step_2_preimage_text,
      step_2_signature: row.step_2_signature,
      settled_transaction_text: row.settled_transaction_text,
    },
  };
}

/**
 * Map lineage_proof_verdict → ancestor classification.
 * LANDED_EXACT → EXPECTED_AT_HEAD (depth 0); LANDED_COMPLETE_PATH → EXPECTED_ANCESTOR;
 * INDETERMINATE / INVARIANT_BREACH → INDETERMINATE (cannot establish landing).
 */
export function mapLineageVerdictToClassification(
  verdict: string,
  bodyCount: number,
): {
  readonly classification: AncestorClassification;
  readonly indeterminate_reason: IndeterminateReason | null;
} {
  if (verdict === "LANDED_EXACT") {
    return { classification: "EXPECTED_AT_HEAD", indeterminate_reason: null };
  }
  if (verdict === "LANDED_COMPLETE_PATH") {
    return { classification: "EXPECTED_ANCESTOR", indeterminate_reason: null };
  }
  if (verdict === "INDETERMINATE" || verdict === "INVARIANT_BREACH") {
    // Prefer MISSING_BODY when no bodies were retained; otherwise ANOMALY covers
    // INVARIANT_BREACH / unspecified incomplete paths. The assembler may still
    // reclassify from structural completeness if bodies are present.
    const reason: IndeterminateReason =
      bodyCount === 0 ? "MISSING_BODY" : "ANOMALY";
    return { classification: "INDETERMINATE", indeterminate_reason: reason };
  }
  // Unknown verdict cannot authorize a landing claim.
  return {
    classification: "INDETERMINATE",
    indeterminate_reason: "ANOMALY",
  };
}

/**
 * Build path_manifest + transaction_bodies from ordered lineage_path_bodies.
 * Manifest property ordering is fixed by PathManifestEntry / serializePathManifest
 * (position, step_2_signature, queried_wallet_previous_signature, transaction_sha256,
 * body_index) — byte-exact, never re-serialized.
 *
 * `queried_wallet_previous_signature` is the body's own p_signature (the predecessor
 * backlink the consumer re-checks). Position 0's p may be "" at genesis.
 */
export function mapLineageBodiesToManifest(
  bodies: readonly DurableLineageBodyRow[],
): {
  readonly path_manifest: readonly PathManifestEntry[];
  readonly transaction_bodies: readonly TransactionBodyMaterial[];
} {
  // Sort by path_index ascending; never trust insertion ordering alone.
  // Preserve durable path_index as wire position / body_index — never dense-renumber
  // from array index. A hole in path_index (e.g. {0,2}) must survive so
  // assessAncestorProofCompleteness can force INDETERMINATE/LINK_GAP;
  // renumbering would forge EXPECTED_ANCESTOR over a missing intermediate body.
  const ordered = [...bodies].sort((a, b) => a.path_index - b.path_index);
  const path_manifest: PathManifestEntry[] = ordered.map((body) => ({
    position: body.path_index,
    step_2_signature: body.step_2_signature,
    queried_wallet_previous_signature: body.p_signature,
    transaction_sha256: body.completed_transaction_sha256,
    body_index: body.path_index,
  }));
  const transaction_bodies: TransactionBodyMaterial[] = ordered.map((body) => ({
    body_index: body.path_index,
    transaction_sha256: body.completed_transaction_sha256,
    settled_transaction_text: body.completed_transaction_text,
  }));
  return { path_manifest, transaction_bodies };
}

export function mapLineagePath(row: DurableLineagePathRow): AncestorProofInput {
  const { path_manifest, transaction_bodies } = mapLineageBodiesToManifest(row.bodies);
  const mapped = mapLineageVerdictToClassification(row.verdict, row.bodies.length);
  // Durable writer reason wins when already INDETERMINATE; otherwise use the map.
  const classification = mapped.classification;
  const indeterminate_reason =
    classification === "INDETERMINATE"
      ? (row.indeterminate_reason ?? mapped.indeterminate_reason)
      : null;

  return {
    evidence_role: row.path_role,
    wallet_public_key: row.wallet_public_key,
    classification,
    expected_step_2_signature: row.expected_step_2_signature,
    fresh_head_step_2_signature: row.fresh_head_step_2_signature,
    fresh_head_transaction_sha256: row.fresh_head_transaction_sha256,
    path_manifest,
    transaction_bodies,
    indeterminate_reason,
  };
}

// --- Assembly from port -----------------------------------------------------------------

/**
 * Assembled bag ready for the HTTP binder. Mirrors VerificationMaterialRow without
 * importing api/ (observation → api is a boundary violation).
 */
export interface AssembledVerificationMaterial {
  readonly kind: OperationKind;
  readonly status: string;
  readonly verificationMaterialAvailableUntilMs: number | null;
  readonly material: Readonly<Record<string, unknown>>;
  readonly payload: VerificationMaterialPayload;
}

export type AssembleFromTablesResult =
  | { readonly ok: true; readonly row: AssembledVerificationMaterial }
  | { readonly ok: false; readonly reason: "not_found" | "missing_artifact" };

/**
 * Load every durable table for one operation and assemble the material bag.
 * Returns not_found when the operation is absent or cross-tenant. Returns
 * missing_artifact when the operation exists but has no expected artifact (the
 * HTTP layer still gates 409/410 on status/window — callers may treat missing
 * artifact as not_ready).
 */
export async function assembleVerificationMaterialFromTables(
  port: VerificationMaterialTablePort,
  operationId: string,
  implementerId: string,
): Promise<AssembleFromTablesResult> {
  const header = await port.loadOperation(operationId, implementerId);
  if (header === null) {
    return { ok: false, reason: "not_found" };
  }

  const artifact = await port.loadExpectedArtifact(operationId);
  if (artifact === null) {
    return { ok: false, reason: "missing_artifact" };
  }

  const [obsRows, attemptRows, pathRows] = await Promise.all([
    port.loadObservationEvidence(operationId, header.kind),
    port.loadAttempts(operationId),
    port.loadAncestorPaths(operationId),
  ]);

  const payload = assembleVerificationMaterial({
    operation_type: header.kind,
    state: header.status,
    landed_attempt_no: header.landed_attempt_no,
    expected_artifact: mapExpectedArtifact(artifact),
    observation_evidence: obsRows.map(mapObservationEvidence),
    attempts: attemptRows.map(mapAttempt),
    ancestor_proofs: pathRows.map(mapLineagePath),
  });

  return {
    ok: true,
    row: {
      kind: header.kind,
      status: header.status,
      verificationMaterialAvailableUntilMs: header.verification_material_available_until_ms,
      material: asVerificationMaterialFields(payload),
      payload,
    },
  };
}

// --- In-memory fixture port (tests + composition demos) ---------------------------------

export interface InMemoryVerificationMaterialTables {
  operations: Map<string, DurableOperationHeader>;
  artifacts: Map<string, DurableExpectedArtifactRow>;
  observations: Map<string, readonly DurableObservationEvidenceRow[]>;
  attempts: Map<string, readonly DurableAttemptRow[]>;
  paths: Map<string, readonly DurableLineagePathRow[]>;
}

export function createInMemoryVerificationMaterialTables(
  seed: {
    readonly operations?: readonly DurableOperationHeader[];
    readonly artifacts?: ReadonlyArray<readonly [string, DurableExpectedArtifactRow]>;
    readonly observations?: ReadonlyArray<
      readonly [string, readonly DurableObservationEvidenceRow[]]
    >;
    readonly attempts?: ReadonlyArray<readonly [string, readonly DurableAttemptRow[]]>;
    readonly paths?: ReadonlyArray<readonly [string, readonly DurableLineagePathRow[]]>;
  } = {},
): InMemoryVerificationMaterialTables & VerificationMaterialTablePort {
  const operations = new Map((seed.operations ?? []).map((o) => [o.id, o]));
  const artifacts = new Map(seed.artifacts ?? []);
  const observations = new Map(seed.observations ?? []);
  const attempts = new Map(seed.attempts ?? []);
  const paths = new Map(seed.paths ?? []);

  return {
    operations,
    artifacts,
    observations,
    attempts,
    paths,
    async loadOperation(operationId, implementerId) {
      const op = operations.get(operationId) ?? null;
      if (op === null) return null;
      if (op.implementer_id !== implementerId) return null;
      return op;
    },
    async loadExpectedArtifact(operationId) {
      return artifacts.get(operationId) ?? null;
    },
    async loadObservationEvidence(operationId) {
      return observations.get(operationId) ?? [];
    },
    async loadAttempts(operationId) {
      return attempts.get(operationId) ?? [];
    },
    async loadAncestorPaths(operationId) {
      return paths.get(operationId) ?? [];
    },
  };
}
