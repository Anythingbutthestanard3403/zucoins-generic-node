/**
 * Public subpath `@zucoins/generic-node-contracts/admin-inventory`.
 *
 * The operator-console wire shapes for `GET /admin/v1/operations` (summary rows) and
 * `GET /admin/v1/operations/:id` (point read). Both halves of the product resolve the shape
 * here — the node projects rows into it (`apps/generic-node/src/admin-inventory`) and the
 * operator SPA consumes it (`apps/generic-node/admin/src/lib/money.ts`) — so a field one side
 * believes a summary row carries and the other never sends is a `tsc -b` failure rather than a
 * silent column of dashes on the screen that shows where money went.
 *
 * Types and field allowlists only: no I/O, no state, no runtime dependency
 * (CONTRACT.md — "Import and dependency boundary"). The projection is allowlist-driven, so the
 * arrays below are the authority on what a response body may contain — never a private key and
 * never a transfer code.
 */

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
