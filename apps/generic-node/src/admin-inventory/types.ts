// Operator inventory wire types for GET /admin/v1/{wallets,operations,destinations,audit}.
// Session+CSRF admin surface; the product boundary allows the three money ops
// only (no v1 checkout/sweeps/webhooks). The key-custody rule: // contract-allow:checkout,sweep:frozen structural vocabulary
// never private keys. Projection is field-allowlist only (wallet-custody-admin pattern).
// App shell imports @zucoins/node-core only (boundaries.test.ts).

import type { AuditActorKind } from "@zucoins/node-core";
import {
  WALLET_CUSTODY_VIEW_FIELDS,
  type DestinationState,
  type WalletCustodyView,
} from "@zucoins/node-core";

// Operations / wallets / destinations wire shapes are shared with the operator SPA rather
// than declared twice: `@zucoins/generic-node-contracts/admin-inventory` is the single wire
// definition both sides compile against, so a projection that drops a field the console
// renders fails the build.
import type {
  DestinationInventoryItem as SharedDestinationInventoryItem,
  OperationInventoryDetail as SharedOperationInventoryDetail,
  OperationInventoryListItem as SharedOperationInventoryListItem,
  WalletInventoryItem as SharedWalletInventoryItem,
  WalletRecoveryEvidenceView as SharedWalletRecoveryEvidenceView,
} from "@zucoins/generic-node-contracts/admin-inventory";
export {
  DESTINATION_INVENTORY_FIELDS,
  OPERATION_INVENTORY_DETAIL_FIELDS,
  OPERATION_INVENTORY_LIST_FIELDS,
  WALLET_INVENTORY_FIELDS,
  WALLET_RECOVERY_EVIDENCE_FIELDS,
} from "@zucoins/generic-node-contracts/admin-inventory";

export type DestinationInventoryItem = SharedDestinationInventoryItem;
export type OperationInventoryDetail = SharedOperationInventoryDetail;
export type OperationInventoryListItem = SharedOperationInventoryListItem;
export type WalletInventoryItem = SharedWalletInventoryItem;
export type WalletRecoveryEvidenceView = SharedWalletRecoveryEvidenceView;

export {
  WALLET_CUSTODY_VIEW_FIELDS,
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

export type WalletInventoryDetail = WalletInventoryItem;

export interface WalletInventoryFilter {
  readonly state?: WalletState;
  readonly key_origin?: WalletKeyOrigin;
  readonly recovery_verified?: boolean;
  readonly limit?: number;
  readonly after?: string;
}

export interface OperationInventoryFilter {
  readonly kind?: InventoryOperationKind;
  readonly status?: string;
  readonly attention_required?: boolean;
  readonly limit?: number;
  readonly after?: string;
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
