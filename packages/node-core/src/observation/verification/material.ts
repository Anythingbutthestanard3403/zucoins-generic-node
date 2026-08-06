// serialize minimal independently verifiable proofs.
//
// Governing: (response shape, path_manifest property ordering,
// INDETERMINATE taxonomy); (inclusion/exclusion);
// (operation_landing_proofs / lineage_path_proofs / lineage_path_bodies
// consumed read-only, never recomputed). Canonical override: changed-response observation ledger.
//
// This module is the EXPOSURE layer, not the verifier. It packages already-persisted proof
// rows into the wire shape a consumer re-derives independently. It never holds private
// keys, vault ciphertext, or TOTP material (excluded by construction). Exact signed
// transaction text and raw observation bytes are passed through VERBATIM — never parsed and
// re-serialized.

import { createHash } from "node:crypto";

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

// --- Closed vocabularies ---------------------------------------------------------

// Locked to evidence_role closed set. action-routes wire
// types must use the same tokens — material.test.ts fails if the surfaces drift.
export const EVIDENCE_ROLES = [
  "RECEIVER",
  "SOURCE",
  "DESTINATION",
  "EXTERNAL_SENDER_PREFLIGHT",
  "EXTERNAL_DESTINATION_PARTIAL",
] as const;
export type EvidenceRole = (typeof EVIDENCE_ROLES)[number];

export const ANCESTOR_CLASSIFICATIONS = [
  "EXPECTED_AT_HEAD",
  "EXPECTED_ANCESTOR",
  "INDETERMINATE",
] as const;
export type AncestorClassification = (typeof ANCESTOR_CLASSIFICATIONS)[number];

export const INDETERMINATE_REASONS = [
  "MISSING_BODY",
  "LINK_GAP",
  "ANOMALY",
  "FRESH_HEAD_MISMATCH",
  "BUDGET_EXCEEDED",
] as const;
export type IndeterminateReason = (typeof INDETERMINATE_REASONS)[number];

// --- Projection / evidence shapes ----------------------------------------------------------

export interface StateProjection {
  readonly s: string;
  readonly p: string;
  readonly b_zkz: string;
}

export interface ObservationProjection {
  readonly observation_id: string;
  readonly projection: StateProjection;
}

export interface ExpectedArtifactMaterial {
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

export interface ObservationEvidenceMaterial {
  readonly evidence_role: EvidenceRole;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  readonly t0: ObservationProjection;
  // Null for formation-only counterparties.
  readonly terminal: ObservationProjection | null;
  // Evidence ABOUT what the node observed — not a substitute for the caller's own
  // independent gateway read (note).
  readonly node_observation_raw_body_base64: string;
}

export interface AttemptTransactionMaterial {
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_preimage_text: string;
  readonly step_2_signature: string;
  readonly settled_transaction_text: string;
}

export interface AttemptMaterial {
  readonly attempt_no: number;
  readonly classification: string;
  readonly transaction: AttemptTransactionMaterial;
}

// Frozen path_manifest entry property ordering from. JSON.stringify emits that ordering
// when keys are inserted in this sequence; any reordering breaks independent re-derivation
// of path_manifest_sha256 even when the content is unchanged.
export interface PathManifestEntry {
  readonly position: number;
  readonly step_2_signature: string;
  readonly queried_wallet_previous_signature: string;
  readonly transaction_sha256: string;
  readonly body_index: number;
}

export interface TransactionBodyMaterial {
  readonly body_index: number;
  readonly transaction_sha256: string;
  readonly settled_transaction_text: string;
}

export interface AncestorProofMaterial {
  readonly evidence_role: EvidenceRole;
  readonly wallet_public_key: string;
  readonly classification: AncestorClassification;
  readonly expected_step_2_signature: string;
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  readonly hop_count: number;
  readonly path_manifest_sha256: string;
  readonly path_manifest: readonly PathManifestEntry[];
  readonly transaction_bodies: readonly TransactionBodyMaterial[];
  readonly indeterminate_reason: IndeterminateReason | null;
}

// The fields between `operation_id` and `available_until` — the two outer fields are
// bound by the transport handler (api/verification-material.ts), not this assembler.
export interface VerificationMaterialPayload {
  readonly operation_type: OperationKind;
  readonly state: string;
  readonly landed_attempt_no: number | null;
  readonly expected_artifact: ExpectedArtifactMaterial;
  readonly observation_evidence: readonly ObservationEvidenceMaterial[];
  readonly attempts: readonly AttemptMaterial[];
  readonly ancestor_proofs: readonly AncestorProofMaterial[];
}

// Input records the assembler packages. Callers load them from operation_landing_proofs /
// lineage_path_proofs / lineage_path_bodies / operation_verifications /
// verification_ack_wallet_evidence / expected_artifact stores — this module never recomputes
// a path and never touches storage.
export interface VerificationMaterialInput {
  readonly operation_type: OperationKind;
  readonly state: string;
  readonly landed_attempt_no: number | null;
  readonly expected_artifact: ExpectedArtifactMaterial;
  readonly observation_evidence: readonly ObservationEvidenceMaterial[];
  readonly attempts: readonly AttemptMaterial[];
  readonly ancestor_proofs: readonly AncestorProofInput[];
}

export interface AncestorProofInput {
  readonly evidence_role: EvidenceRole;
  readonly wallet_public_key: string;
  readonly classification: AncestorClassification;
  readonly expected_step_2_signature: string;
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  // Ordered path for the operation and wallet role: expected tx at position 0, every
  // successor to the fresh head. Empty (or a non-authoritative diagnostic prefix) when
  // classification is INDETERMINATE.
  readonly path_manifest: readonly PathManifestEntry[];
  readonly transaction_bodies: readonly TransactionBodyMaterial[];
  readonly indeterminate_reason: IndeterminateReason | null;
}

// Forbidden field / substring markers for the exclusion half. Used by the
// exclusion test and by a defensive surface scan on assembled payloads.
export const FORBIDDEN_MATERIAL_MARKERS = [
  "private_key",
  "privateKey",
  "secret_key",
  "secretKey",
  "vault_ciphertext",
  "vaultCiphertext",
  "totp_secret",
  "totpSecret",
  "totp_seed",
  "master_key",
  "masterKey",
  "seed_phrase",
  "mnemonic",
] as const;

// --- Path-manifest digest --------------------------------------------------------

// Serialize path_manifest with the EXACT property ordering shown in. Built via explicit
// key insertion (not object-spread) so a future field addition cannot reorder silently.
export function serializePathManifest(entries: readonly PathManifestEntry[]): string {
  const ordered = entries.map((entry) => {
    const row: {
      position: number;
      step_2_signature: string;
      queried_wallet_previous_signature: string;
      transaction_sha256: string;
      body_index: number;
    } = {
      position: entry.position,
      step_2_signature: entry.step_2_signature,
      queried_wallet_previous_signature: entry.queried_wallet_previous_signature,
      transaction_sha256: entry.transaction_sha256,
      body_index: entry.body_index,
    };
    return row;
  });
  return JSON.stringify(ordered);
}

// path_manifest_sha256 is SHA-256 of the exact UTF-8 JSON.stringify(path_manifest) text.
export function computePathManifestSha256(entries: readonly PathManifestEntry[]): string {
  return createHash("sha256").update(serializePathManifest(entries), "utf8").digest("hex");
}

// --- Assembly ------------------------------------------------------------------------------

function freezeProjection(p: StateProjection): StateProjection {
  return Object.freeze({ s: p.s, p: p.p, b_zkz: p.b_zkz });
}

function freezeObservation(o: ObservationProjection): ObservationProjection {
  return Object.freeze({
    observation_id: o.observation_id,
    projection: freezeProjection(o.projection),
  });
}

function assembleExpectedArtifact(a: ExpectedArtifactMaterial): ExpectedArtifactMaterial {
  return Object.freeze({
    key_id: a.key_id,
    preimage_text: a.preimage_text,
    preimage_sha256: a.preimage_sha256,
    signature: a.signature,
  });
}

function assembleObservationEvidence(
  e: ObservationEvidenceMaterial,
): ObservationEvidenceMaterial {
  return Object.freeze({
    evidence_role: e.evidence_role,
    wallet_id: e.wallet_id,
    wallet_public_key: e.wallet_public_key,
    t0: freezeObservation(e.t0),
    terminal: e.terminal === null ? null : freezeObservation(e.terminal),
    node_observation_raw_body_base64: e.node_observation_raw_body_base64,
  });
}

function assembleAttempt(a: AttemptMaterial): AttemptMaterial {
  return Object.freeze({
    attempt_no: a.attempt_no,
    classification: a.classification,
    transaction: Object.freeze({
      inner_preimage_text: a.transaction.inner_preimage_text,
      inner_sha256: a.transaction.inner_sha256,
      step_1_signature: a.transaction.step_1_signature,
      step_2_preimage_text: a.transaction.step_2_preimage_text,
      step_2_signature: a.transaction.step_2_signature,
      settled_transaction_text: a.transaction.settled_transaction_text,
    }),
  });
}

function assemblePathEntry(e: PathManifestEntry): PathManifestEntry {
  return Object.freeze({
    position: e.position,
    step_2_signature: e.step_2_signature,
    queried_wallet_previous_signature: e.queried_wallet_previous_signature,
    transaction_sha256: e.transaction_sha256,
    body_index: e.body_index,
  });
}

function assembleBody(b: TransactionBodyMaterial): TransactionBodyMaterial {
  return Object.freeze({
    body_index: b.body_index,
    transaction_sha256: b.transaction_sha256,
    settled_transaction_text: b.settled_transaction_text,
  });
}

/**
 * SHA-256 hex of exact UTF-8 settled transaction text (integrity chain:
 * `transaction_sha256` must bind the paired `settled_transaction_text`).
 */
export function transactionBodySha256(settledTransactionText: string): string {
  return createHash("sha256").update(settledTransactionText, "utf8").digest("hex");
}

/**
 * Structural completeness of a determinate ancestor path.
 * Incomplete or inconsistent material cannot establish landing — force INDETERMINATE
 * even when the caller supplied EXPECTED_AT_HEAD / EXPECTED_ANCESTOR.
 *
 * Priority matches api/routes classifyAncestorProof: MISSING_BODY → LINK_GAP →
 * ANOMALY → FRESH_HEAD_MISMATCH. (BUDGET_EXCEEDED is caller-prelabeled only.)
 *
 * Body-text digest mismatch (`sha256(settled_transaction_text) !== transaction_sha256`)
 * is a predecessor/integrity-chain gap → LINK_GAP ("any manifest/body hash
 * or predecessor link has a gap"). Manifest field vs body field disagreement alone
 * remains ANOMALY.
 */
export function assessAncestorProofCompleteness(input: AncestorProofInput): {
  readonly missingBody: boolean;
  readonly linkGap: boolean;
  readonly anomaly: boolean;
  readonly freshHeadMismatch: boolean;
} {
  const manifest = input.path_manifest;
  const bodies = input.transaction_bodies;
  const bodiesByIndex = new Map<number, TransactionBodyMaterial>();
  for (const body of bodies) {
    bodiesByIndex.set(body.body_index, body);
  }

  let missingBody = false;
  let linkGap = false;
  let anomaly = false;
  let freshHeadMismatch = false;

  if (manifest.length === 0) {
    // Determinate landing claims require at least the expected tx at position 0.
    missingBody = true;
  } else {
    for (let i = 0; i < manifest.length; i++) {
      const entry = manifest[i]!;
      if (entry.position !== i) {
        linkGap = true;
      }
      if (i > 0) {
        const prev = manifest[i - 1]!;
        if (entry.queried_wallet_previous_signature !== prev.step_2_signature) {
          linkGap = true;
        }
      }
      const body = bodiesByIndex.get(entry.body_index);
      if (body === undefined) {
        missingBody = true;
        continue;
      }
      if (body.settled_transaction_text.length === 0) {
        missingBody = true;
      }
      // Integrity chain: stored hash must equal the hash of the exact body text.
      // A corrupted lineage_path_bodies row (text rewritten, hash left stale — or the
      // reverse) must never surface as EXPECTED_* (LINK_GAP).
      if (
        body.settled_transaction_text.length > 0 &&
        transactionBodySha256(body.settled_transaction_text) !== body.transaction_sha256
      ) {
        linkGap = true;
      }
      if (body.transaction_sha256 !== entry.transaction_sha256) {
        anomaly = true;
      }
    }

    // Extra bodies not referenced by the manifest are unrelated history.
    const referenced = new Set(manifest.map((e) => e.body_index));
    for (const body of bodies) {
      if (!referenced.has(body.body_index)) {
        anomaly = true;
      }
    }

    const last = manifest[manifest.length - 1]!;
    if (
      last.step_2_signature !== input.fresh_head_step_2_signature ||
      last.transaction_sha256 !== input.fresh_head_transaction_sha256
    ) {
      freshHeadMismatch = true;
    }
  }

  return { missingBody, linkGap, anomaly, freshHeadMismatch };
}

function classifyFromCompleteness(
  input: AncestorProofInput,
): {
  readonly classification: AncestorClassification;
  readonly indeterminate_reason: IndeterminateReason | null;
} {
  const labeledIndeterminate = input.classification === "INDETERMINATE";

  if (labeledIndeterminate && input.indeterminate_reason === null) {
    throw new Error(
      "ancestor_proofs with classification INDETERMINATE require indeterminate_reason",
    );
  }
  if (!labeledIndeterminate && input.indeterminate_reason !== null) {
    throw new Error(
      "ancestor_proofs with a determinate classification must set indeterminate_reason to null",
    );
  }

  // Caller already labeled incomplete — keep their reason (diagnostic path).
  if (labeledIndeterminate) {
    return {
      classification: "INDETERMINATE",
      indeterminate_reason: input.indeterminate_reason,
    };
  }

  const flags = assessAncestorProofCompleteness(input);
  if (flags.missingBody) {
    return { classification: "INDETERMINATE", indeterminate_reason: "MISSING_BODY" };
  }
  if (flags.linkGap) {
    return { classification: "INDETERMINATE", indeterminate_reason: "LINK_GAP" };
  }
  if (flags.anomaly) {
    return { classification: "INDETERMINATE", indeterminate_reason: "ANOMALY" };
  }
  if (flags.freshHeadMismatch) {
    return { classification: "INDETERMINATE", indeterminate_reason: "FRESH_HEAD_MISMATCH" };
  }

  return {
    classification: input.classification,
    indeterminate_reason: null,
  };
}

function assembleAncestorProof(input: AncestorProofInput): AncestorProofMaterial {
  const { classification, indeterminate_reason } = classifyFromCompleteness(input);

  // hop_count is the number of successor links, so exact head is 0.
  const hop_count =
    input.path_manifest.length === 0 ? 0 : input.path_manifest.length - 1;

  // Digest over the assembled (ordered) manifest so the wire value always matches what
  // a consumer re-derives from the returned path_manifest array.
  const path_manifest = Object.freeze(input.path_manifest.map(assemblePathEntry));
  const path_manifest_sha256 = computePathManifestSha256(path_manifest);

  return Object.freeze({
    evidence_role: input.evidence_role,
    wallet_public_key: input.wallet_public_key,
    classification,
    expected_step_2_signature: input.expected_step_2_signature,
    fresh_head_step_2_signature: input.fresh_head_step_2_signature,
    fresh_head_transaction_sha256: input.fresh_head_transaction_sha256,
    hop_count,
    path_manifest_sha256,
    path_manifest,
    transaction_bodies: Object.freeze(input.transaction_bodies.map(assembleBody)),
    indeterminate_reason,
  });
}

// Assemble the material payload in frozen document field ordering. Pure: same inputs
// always produce the same deep-frozen object. Does NOT bind operation_id or available_until
// — those are the transport handler's responsibility.
export function assembleVerificationMaterial(
  input: VerificationMaterialInput,
): VerificationMaterialPayload {
  // Attempts ordered by attempt_no ascending.
  const attempts = [...input.attempts]
    .sort((a, b) => a.attempt_no - b.attempt_no)
    .map(assembleAttempt);

  return Object.freeze({
    operation_type: input.operation_type,
    state: input.state,
    landed_attempt_no: input.landed_attempt_no,
    expected_artifact: assembleExpectedArtifact(input.expected_artifact),
    observation_evidence: Object.freeze(input.observation_evidence.map(assembleObservationEvidence)),
    attempts: Object.freeze(attempts),
    ancestor_proofs: Object.freeze(input.ancestor_proofs.map(assembleAncestorProof)),
  });
}

// Project the typed payload into the loose `Record` the transport handler
// (`api/verification-material.ts` VerificationMaterialRow.material) expects. The api
// module cannot import observation (boundary), so the composition root does this cast
// once at the source-port boundary. Field ordering is preserved by the assembler's
// explicit key insertion; JSON.stringify over the Record still emits ordering.
export function asVerificationMaterialFields(
  payload: VerificationMaterialPayload,
): Readonly<Record<string, unknown>> {
  return payload as unknown as Readonly<Record<string, unknown>>;
}

// True when a serialized payload contains any excluded custody marker. Used by the
// exclusion test and available to callers that want a defensive post-assembly scan.
export function containsForbiddenMaterial(serialized: string): boolean {
  for (const marker of FORBIDDEN_MATERIAL_MARKERS) {
    if (serialized.includes(marker)) return true;
  }
  return false;
}
