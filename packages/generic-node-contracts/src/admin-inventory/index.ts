/**
 * Public subpath `@zucoins/generic-node-contracts/admin-inventory`.
 *
 * The operator-console wire shapes for admin inventory GETs:
 * - `GET /admin/v1/operations` (summary rows) and `GET /admin/v1/operations/:id` (point read)
 * - `GET /admin/v1/wallets` / `GET /admin/v1/wallets/:id`
 * - `GET /admin/v1/destinations`
 *
 * Both halves of the product resolve the shape here — the node projects rows into it
 * (`apps/generic-node/src/admin-inventory`) and the operator SPA consumes it
 * (`apps/generic-node/admin/src/lib/money.ts`) — so a field one side believes a row carries
 * and the other never sends is a `tsc -b` failure rather than a silent column of dashes.
 *
 * Types and field allowlists only: no I/O, no state, no runtime dependency
 * (CONTRACT.md — "Import and dependency boundary"). The projection is allowlist-driven, so the
 * arrays below are the authority on what a response body may contain — never a private key and
 * never a transfer code.
 */

import type {
  CustodyDenialReason,
  DestinationState,
  WalletKeyOrigin,
  WalletState,
} from "../custody/index.ts";
import type { OperationKind } from "../operations/index.ts";

/**
 * Summary row served by the operations list read. `destination_address` is part of the summary
 * (not detail-only) because the operator scanning view renders a destination column per row.
 */
export interface OperationInventoryListItem {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly status: string;
  readonly amount_zkz: string;
  readonly row_version: number;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly terminal_at: string | null;
  /**
   * Public key only — never a transfer code or private key. Null on operations that have no
   * external destination (RECEIVE_EXTERNAL, MOVE_INTERNAL) and on a SEND_EXTERNAL that has not
   * resolved one yet.
   */
  readonly destination_address: string | null;
}

/** Point read — the summary row plus the fields only a single-operation view needs. */
export interface OperationInventoryDetail extends OperationInventoryListItem {
  readonly source_wallet_id: string | null;
  readonly receiver_wallet_id: string | null;
  readonly destination_id: string | null;
  readonly after_landing: string | null;
  readonly after_landing_destination_id: string | null;
  readonly formation_state: string;
  readonly verification_verdict: string;
  readonly implementer_id: string;
  readonly client_reference: string | null;
}

/** Response field allowlist for the list read — the exact keys a summary row may carry. */
export const OPERATION_INVENTORY_LIST_FIELDS = [
  "operation_id",
  "operation_type",
  "status",
  "amount_zkz",
  "row_version",
  "attention_required",
  "attention_reason",
  "created_at",
  "updated_at",
  "terminal_at",
  "destination_address",
] as const;

/** Response field allowlist for the point read — the summary keys plus the detail-only ones. */
export const OPERATION_INVENTORY_DETAIL_FIELDS = [
  ...OPERATION_INVENTORY_LIST_FIELDS,
  "source_wallet_id",
  "receiver_wallet_id",
  "destination_id",
  "after_landing",
  "after_landing_destination_id",
  "formation_state",
  "verification_verdict",
  "implementer_id",
  "client_reference",
] as const;

/**
 * Linked `wallet_recovery_verifications` evidence on a wallet inventory row.
 * `audit_event_id` is a pointer into `audit_log` only — never re-serves audit bytes or export
 * material behind `export_sha256`.
 */
export interface WalletRecoveryEvidenceView {
  readonly method: string;
  readonly verified_at: string;
  readonly verifier_identity: string;
  readonly audit_event_id: string;
}

/**
 * Operator wallet inventory row — custody standing plus gateway-observed balance.
 * Field names match the HTTP JSON body (snake_case). Never private keys or vault material.
 */
export interface WalletInventoryItem {
  readonly wallet_id: string;
  readonly node_id: string;
  readonly public_key: string;
  readonly key_origin: WalletKeyOrigin;
  readonly state: WalletState;
  readonly created_at: string;
  readonly retired_at: string | null;
  readonly quarantine_reason: string | null;
  /** Presence fact: is this wallet recovery-verified at all. Never inferred. */
  readonly recovery_verified: boolean;
  readonly recovery_verified_at: string | null;
  /** The evidence row behind `recovery_verified_at`, or null when there is none. */
  readonly recovery_verification: WalletRecoveryEvidenceView | null;
  /** Observed balance when known (settled-ledger / observation); never a private key. */
  readonly observed_balance_zkz: string | null;
}

/** Response field allowlist for wallet inventory — never private keys or secret-class tokens. */
export const WALLET_INVENTORY_FIELDS = [
  "wallet_id",
  "node_id",
  "public_key",
  "key_origin",
  "state",
  "created_at",
  "retired_at",
  "quarantine_reason",
  "recovery_verified",
  "recovery_verified_at",
  "recovery_verification",
  "observed_balance_zkz",
] as const;

/**
 * Nested evidence keys under `recovery_verification` when present.
 * Kept separate so the top-level allowlist stays flat (one key per body property).
 */
export const WALLET_RECOVERY_EVIDENCE_FIELDS = [
  "method",
  "verified_at",
  "verifier_identity",
  "audit_event_id",
] as const;

/**
 * Admin session mirror of the destinations list (bless/retire state + eligibility).
 * Eligibility fields are derived at read time, not stored columns.
 */
export interface DestinationInventoryItem {
  readonly destination_id: string;
  readonly node_id: string;
  readonly wallet_id: string;
  readonly wallet_public_key: string;
  readonly state: DestinationState;
  readonly label: string;
  readonly blessed_at: string | null;
  readonly blessed_by_device_key_id: string | null;
  readonly blessing_artifact_id: string | null;
  readonly retired_at: string | null;
  readonly created_at: string;
  readonly move_eligible: boolean;
  readonly ineligibility_reason: CustodyDenialReason | null;
}

/** Response field allowlist for destination inventory. */
export const DESTINATION_INVENTORY_FIELDS = [
  "destination_id",
  "node_id",
  "wallet_id",
  "wallet_public_key",
  "state",
  "label",
  "blessed_at",
  "blessed_by_device_key_id",
  "blessing_artifact_id",
  "retired_at",
  "created_at",
  "move_eligible",
  "ineligibility_reason",
] as const;
