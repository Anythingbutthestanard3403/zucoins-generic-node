/** Live shapes from GET /admin/v1/operations/needs-attention (recovery-inspection). */

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

export type RecoveryClassification =
  | "LANDED_VERIFIED"
  | "PROVEN_NOT_STARTED"
  | "PROVEN_NOT_LANDED"
  | "WAITING"
  | "INDETERMINATE"
  | "INVARIANT_BREACH";

export type { OperationKind };

export interface NeedsAttentionListItem {
  operation_id: string;
  operation_type: OperationKind | string;
  status: string;
  attention_required: boolean;
  attention_reason: string | null;
  classification: RecoveryClassification | string;
  classification_rationale: string;
  severity: "P0" | "P1" | "P2";
  permitted_actions: readonly string[];
  row_version: number;
  lease_epoch: number | null;
  attention_since: string | null;
  wallet_ids: readonly string[];
}

export interface NeedsAttentionResponse {
  operations: readonly NeedsAttentionListItem[];
  summary: {
    total: number;
    by_classification: Readonly<Record<string, number>>;
    p0_invariant_breach: number;
  };
}

export const EMPTY_NEEDS_ATTENTION: NeedsAttentionResponse = {
  operations: [],
  summary: {
    total: 0,
    by_classification: {},
    p0_invariant_breach: 0,
  },
};
