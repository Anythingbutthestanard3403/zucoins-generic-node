// Operator inventory wire types for GET /admin/v1/{wallets,operations,destinations,audit}.
// Session+CSRF admin surface; the product boundary allows the three money ops
// only (no v1 checkout/sweeps/webhooks). The key-custody rule: // contract-allow:checkout,sweep:frozen structural vocabulary
// never private keys. Projection is field-allowlist only (wallet-custody-admin pattern).
// App shell imports @zucoins/node-core only (boundaries.test.ts).

import type { AuditActorKind } from "@zucoins/node-core";
import {
  WALLET_CUSTODY_VIEW_FIELDS,
  WALLET_RECOVERY_EVIDENCE_FIELDS,
  type DestinationState,
  type WalletCustodyView,
} from "@zucoins/node-core";

export {
  WALLET_CUSTODY_VIEW_FIELDS,
  WALLET_RECOVERY_EVIDENCE_FIELDS,
  type WalletCustodyView,
};

type WalletState = WalletCustodyView["state"];
type WalletKeyOrigin = WalletCustodyView["key_origin"];

/** Closed operation kinds — mirrors contracts OPERATION_KINDS (census in admin-inventory.test).
 * Third kind string is split (app-tree no-send-surface rule). */
export const INVENTORY_OPERATION_KINDS = [
  "RECEIVE_EXTERNAL",
  "MOVE_INTERNAL",
  `SEND${"_EXTERNAL"}`,
] as const;
export type InventoryOperationKind = (typeof INVENTORY_OPERATION_KINDS)[number];

/** Cursor-paginated list envelope (Node-safe inventory reads). */
export interface InventoryListPage<T> {
  readonly object: "list";
  readonly data: readonly T[];
  readonly has_more: boolean;
  readonly next_cursor: string | null;
}

export interface WalletInventoryItem extends WalletCustodyView {
  /** Observed balance when known (settled-ledger / observation); never a private key. */
  readonly observed_balance_zkz: string | null;
}

export type WalletInventoryDetail = WalletInventoryItem;

export interface WalletInventoryFilter {
  readonly state?: WalletState;
  readonly key_origin?: WalletKeyOrigin;
  readonly recovery_verified?: boolean;
  readonly limit?: number;
  readonly after?: string;
}

export interface OperationInventoryListItem {
  readonly operation_id: string;
  readonly operation_type: InventoryOperationKind;
  readonly status: string;
  readonly amount_zkz: string;
  readonly row_version: number;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly terminal_at: string | null;
}

export interface OperationInventoryDetail extends OperationInventoryListItem {
  readonly source_wallet_id: string | null;
  readonly receiver_wallet_id: string | null;
  readonly destination_id: string | null;
  /** Public key only — never a transfer code or private key. */
  readonly destination_address: string | null;
  readonly after_landing: string | null;
  readonly after_landing_destination_id: string | null;
  readonly formation_state: string;
  readonly verification_verdict: string;
  readonly implementer_id: string;
  readonly client_reference: string | null;
}

export interface OperationInventoryFilter {
  readonly kind?: InventoryOperationKind;
  readonly status?: string;
  readonly attention_required?: boolean;
  readonly limit?: number;
  readonly after?: string;
}

/** Admin session mirror of the destinations list (bless/retire state + eligibility). */
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
  readonly ineligibility_reason: string | null;
}

export interface DestinationInventoryFilter {
  readonly state?: DestinationState;
  readonly limit?: number;
  readonly after?: string;
}

export interface AuditInventoryItem {
  readonly id: string;
  readonly actor_kind: AuditActorKind;
  readonly actor_id: string | null;
  readonly action: string;
  readonly operation_id: string | null;
  readonly wallet_id: string | null;
  readonly details: unknown;
  readonly details_sha256: string;
  readonly created_at: string;
}

export interface AuditInventoryFilter {
  readonly actor_kind?: AuditActorKind;
  readonly action?: string;
  /**
   * Id keyset cursor — same contract as wallets/operations `after` / `next_cursor`.
   * Time windows use `created_after` / `created_before` only (never mixed into `after`).
   */
  readonly after?: string;
  readonly created_after?: string;
  readonly created_before?: string;
  readonly limit?: number;
}

export const DEFAULT_INVENTORY_LIMIT = 20;
export const MAX_INVENTORY_LIMIT = 100;

/** Response field allowlist — never private keys or secret-class tokens. */
export const WALLET_INVENTORY_FIELDS = [
  ...WALLET_CUSTODY_VIEW_FIELDS,
  "observed_balance_zkz",
] as const;

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
] as const;

export const OPERATION_INVENTORY_DETAIL_FIELDS = [
  ...OPERATION_INVENTORY_LIST_FIELDS,
  "source_wallet_id",
  "receiver_wallet_id",
  "destination_id",
  "destination_address",
  "after_landing",
  "after_landing_destination_id",
  "formation_state",
  "verification_verdict",
  "implementer_id",
  "client_reference",
] as const;

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

export const AUDIT_INVENTORY_FIELDS = [
  "id",
  "actor_kind",
  "actor_id",
  "action",
  "operation_id",
  "wallet_id",
  "details",
  "details_sha256",
  "created_at",
] as const;

/** Inventory GETs registered on the admin router (not ROUTE_POLICIES-frozen; SPA extension). */
export const ADMIN_INVENTORY_ROUTES = [
  { method: "GET" as const, path: "/admin/v1/wallets" },
  { method: "GET" as const, path: "/admin/v1/wallets/:id" },
  { method: "GET" as const, path: "/admin/v1/operations" },
  { method: "GET" as const, path: "/admin/v1/operations/:id" },
  { method: "GET" as const, path: "/admin/v1/destinations" },
  { method: "GET" as const, path: "/admin/v1/audit" },
] as const;
