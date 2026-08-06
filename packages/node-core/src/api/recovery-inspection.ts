// admin recovery inspection routes (read-only).
//
//
// GET /admin/v1/operations/needs-attention
// GET /admin/v1/operations/:operation_id/recovery
//
// Pure classification + permitted-action derivation live in
// `../operator/recovery-inspection.js`. This module is the request surface:
// load durable snapshot, issue a fresh single-use recovery nonce (recovery_nonces),
// project the operator-safe wire shape. No mutations of money state; no TOTP.

import { z } from "zod";

import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";

import {
  RECOVERY_CLASSIFICATIONS,
  inspectRecovery,
  type EvidenceManifestEntry,
  type OperatorRecoveryAction,
  type RecoveryClassification,
  type RecoveryFacts,
} from "../operator/recovery-inspection.js";

export {
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_CLASSIFICATIONS,
  classifyRecovery,
  derivePermittedActions,
  inspectRecovery,
  type EvidenceManifestEntry,
  type OperatorRecoveryAction,
  type RecoveryClassification,
  type RecoveryFacts,
} from "../operator/recovery-inspection.js";

export const NEEDS_ATTENTION_PATH = "/admin/v1/operations/needs-attention" as const;
export const RECOVERY_DETAIL_PATH = "/admin/v1/operations/:operation_id/recovery" as const;

export const NeedsAttentionQuerySchema = z
  .object({
    classification: z.enum(RECOVERY_CLASSIFICATIONS).optional(),
    kind: z.enum(OPERATION_KINDS).optional(),
    limit: z.coerce.number().int().min(1).max(200).optional(),
  })
  .strict();

export type NeedsAttentionQuery = z.infer<typeof NeedsAttentionQuerySchema>;

export interface NeedsAttentionListItem {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly status: string;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly classification: RecoveryClassification;
  readonly classification_rationale: string;
  readonly severity: "P0" | "P1" | "P2";
  readonly permitted_actions: readonly OperatorRecoveryAction[];
  readonly row_version: number;
  readonly lease_epoch: number | null;
  readonly attention_since: string | null;
  readonly wallet_ids: readonly string[];
}

export interface NeedsAttentionResponse {
  readonly operations: readonly NeedsAttentionListItem[];
  readonly summary: {
    readonly total: number;
    readonly by_classification: Readonly<Record<RecoveryClassification, number>>;
    readonly p0_invariant_breach: number;
  };
}

export interface IssuedRecoveryNonce {
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export interface RecoveryDetailResponse {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly status: string;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly classification: RecoveryClassification;
  readonly classification_rationale: string;
  readonly permitted_actions: readonly OperatorRecoveryAction[];
  readonly evidence_manifest: readonly EvidenceManifestEntry[];
  readonly held_leases: readonly {
    readonly wallet_id: string;
    readonly lease_epoch: number;
    readonly role: string;
  }[];
  readonly row_version: number;
  readonly lease_epoch: number | null;
  readonly recovery_nonce: string;
  readonly recovery_nonce_issued_at: string;
  readonly recovery_nonce_expires_at: string;
  readonly diagnostics: readonly {
    readonly at: string;
    readonly code: string;
    readonly message: string;
  }[];
}

/**
 * Persistence port. The store loads durable snapshots and issues recovery nonces
 * (signer-support.sql `recovery_nonces`: one ISSUED per operation; prior ISSUED
 * rows become SUPERSEDED). Handlers never open SQL directly.
 */
export interface RecoveryInspectionStore {
  /**
   * Tenant-neutral list of parked operations: attention_required=true OR public
   * status NEEDS_ATTENTION.
   */
  listNeedsAttention(query: NeedsAttentionQuery): Promise<readonly RecoveryFacts[]>;

  /** Full durable snapshot for one operation, or null if absent. */
  loadRecoveryFacts(operationId: string): Promise<RecoveryFacts | null>;

  /**
   * Issue a fresh recovery nonce for the operation. MUST return a new nonce on
   * every call (prior ISSUED superseded). Plaintext nonce is returned once.
   */
  issueRecoveryNonce(operationId: string): Promise<IssuedRecoveryNonce>;
}

const EMPTY_BY_CLASSIFICATION: Record<RecoveryClassification, number> = {
  LANDED_VERIFIED: 0,
  PROVEN_NOT_STARTED: 0,
  PROVEN_NOT_LANDED: 0,
  WAITING: 0,
  INDETERMINATE: 0,
  INVARIANT_BREACH: 0,
};

function severityFor(classification: RecoveryClassification): "P0" | "P1" | "P2" {
  // INVARIANT_BREACH is P0.
  if (classification === "INVARIANT_BREACH") return "P0";
  if (classification === "INDETERMINATE" || classification === "PROVEN_NOT_LANDED") return "P1";
  return "P2";
}

function projectListItem(facts: RecoveryFacts): NeedsAttentionListItem {
  const inspected = inspectRecovery(facts);
  return {
    operation_id: facts.operationId,
    operation_type: facts.kind,
    status: facts.status,
    attention_required: facts.attentionRequired,
    attention_reason: facts.attentionReason,
    classification: inspected.classification,
    classification_rationale: inspected.classificationRationale,
    severity: severityFor(inspected.classification),
    permitted_actions: inspected.permittedActions,
    row_version: inspected.rowVersion,
    lease_epoch: inspected.leaseEpoch,
    attention_since:
      facts.diagnostics.length > 0 ? (facts.diagnostics[0]?.at ?? null) : null,
    wallet_ids: facts.heldLeases.map((l) => l.walletId),
  };
}

function buildSummary(
  items: readonly NeedsAttentionListItem[],
): NeedsAttentionResponse["summary"] {
  const by_classification: Record<RecoveryClassification, number> = {
    ...EMPTY_BY_CLASSIFICATION,
  };
  let p0 = 0;
  for (const item of items) {
    by_classification[item.classification] += 1;
    if (item.severity === "P0") p0 += 1;
  }
  return {
    total: items.length,
    by_classification,
    p0_invariant_breach: p0,
  };
}

/**
 * GET /admin/v1/operations/needs-attention — tenant-neutral parked listing.
 * Re-derives permitted actions per row at read time.
 */
export async function handleNeedsAttention(
  store: RecoveryInspectionStore,
  query: NeedsAttentionQuery = {},
): Promise<NeedsAttentionResponse> {
  const snapshots = await store.listNeedsAttention(query);
  let items = snapshots.map(projectListItem);
  if (query.classification !== undefined) {
    items = items.filter((i) => i.classification === query.classification);
  }
  if (query.kind !== undefined) {
    items = items.filter((i) => i.operation_type === query.kind);
  }
  if (query.limit !== undefined) {
    items = items.slice(0, query.limit);
  }
  return { operations: items, summary: buildSummary(items) };
}

export type GetRecoveryOutcome =
  | { readonly status: "ok"; readonly body: RecoveryDetailResponse }
  | { readonly status: "not_found"; readonly operation_id: string };

/**
 * GET /admin/v1/operations/:operation_id/recovery — per-operation detail with a
 * freshly issued single-use recovery nonce. Two consecutive calls MUST yield two
 * different nonces (store contract + test).
 */
export async function handleGetRecovery(
  store: RecoveryInspectionStore,
  operationId: string,
): Promise<GetRecoveryOutcome> {
  const facts = await store.loadRecoveryFacts(operationId);
  if (facts === null) {
    return { status: "not_found", operation_id: operationId };
  }
  const inspected = inspectRecovery(facts);
  const nonce = await store.issueRecoveryNonce(operationId);
  return {
    status: "ok",
    body: {
      operation_id: facts.operationId,
      operation_type: facts.kind,
      status: facts.status,
      attention_required: facts.attentionRequired,
      attention_reason: facts.attentionReason,
      classification: inspected.classification,
      classification_rationale: inspected.classificationRationale,
      permitted_actions: inspected.permittedActions,
      evidence_manifest: inspected.evidenceManifest,
      held_leases: facts.heldLeases.map((l) => ({
        wallet_id: l.walletId,
        lease_epoch: l.leaseEpoch,
        role: l.role,
      })),
      row_version: inspected.rowVersion,
      lease_epoch: inspected.leaseEpoch,
      recovery_nonce: nonce.nonce,
      recovery_nonce_issued_at: nonce.issued_at,
      recovery_nonce_expires_at: nonce.expires_at,
      diagnostics: facts.diagnostics,
    },
  };
}
