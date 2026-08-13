// Operator mutation: set per-wallet money capability preset (ZTR-1269).
//
// Pure port + SQL/memory implementations. flagsFromMode is the sole matrix
// authority (contracts); schema CHECKs reject illegal triples. row_version CAS
// prevents lost updates; audit_log records before → after mode/flags.

import { createHash, randomUUID } from "node:crypto";

import {
  flagsFromMode,
  isWalletMoneyMode,
  type WalletMoneyCapabilityFlags,
  type WalletMoneyMode,
} from "@zucoins/generic-node-contracts/wallet-state";

/** Minimal SQL port — structural match to send/vault SqlExecutor (no send import; operator↔send edge forbidden). */
export interface WalletMoneyCapabilitySqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: readonly R[] }>;
}

export type { WalletMoneyMode, WalletMoneyCapabilityFlags };

/** audit_log.action for a successful money-capability change. */
export const WALLET_MONEY_CAPABILITY_AUDIT_ACTION =
  "wallet.money_capability_changed" as const;

export interface WalletMoneyCapabilitySnapshot {
  readonly wallet_id: string;
  readonly money_mode: WalletMoneyMode;
  readonly allow_external_receive: boolean;
  readonly allow_external_send: boolean;
  readonly allow_internal_move: boolean;
  readonly row_version: number;
}

export interface WalletMoneyCapabilityFleetWarnings {
  /** True when no wallet on the node still allows external send after the change. */
  readonly zero_send_capable: boolean;
  /** True when no wallet on the node still allows external receive after the change. */
  readonly zero_receive_capable: boolean;
}

export interface WalletMoneyCapabilitySetResult extends WalletMoneyCapabilitySnapshot {
  readonly previous_mode: WalletMoneyMode;
  readonly previous_flags: WalletMoneyCapabilityFlags;
  readonly warnings: WalletMoneyCapabilityFleetWarnings;
}

export type WalletMoneyCapabilitySetRejectReason =
  | "wallet_not_found"
  | "conflict"
  | "invalid_mode";

export type WalletMoneyCapabilitySetOutcome =
  | { readonly ok: true; readonly result: WalletMoneyCapabilitySetResult }
  | { readonly ok: false; readonly reason: WalletMoneyCapabilitySetRejectReason };

export interface WalletMoneyCapabilitySetInput {
  readonly walletId: string;
  readonly mode: WalletMoneyMode;
  readonly expectedRowVersion: number;
  readonly actorId: string;
  readonly nodeId: string;
}

/**
 * Persistence port for PATCH money-capability. Implementations own lock + CAS +
 * audit in one transaction (or outer admin TX client).
 */
export interface WalletMoneyCapabilityStore {
  setMode(input: WalletMoneyCapabilitySetInput): Promise<WalletMoneyCapabilitySetOutcome>;
}

export interface MemoryWalletMoneyCapabilityRow {
  wallet_id: string;
  node_id: string;
  money_mode: WalletMoneyMode;
  allow_external_receive: boolean;
  allow_external_send: boolean;
  allow_internal_move: boolean;
  row_version: number;
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function flagsOf(row: {
  readonly allow_external_receive: boolean;
  readonly allow_external_send: boolean;
  readonly allow_internal_move: boolean;
}): WalletMoneyCapabilityFlags {
  return {
    allow_external_receive: row.allow_external_receive,
    allow_external_send: row.allow_external_send,
    allow_internal_move: row.allow_internal_move,
  };
}

function fleetWarnings(
  rows: readonly {
    readonly allow_external_receive: boolean;
    readonly allow_external_send: boolean;
  }[],
): WalletMoneyCapabilityFleetWarnings {
  let send = 0;
  let receive = 0;
  for (const r of rows) {
    if (r.allow_external_send) send += 1;
    if (r.allow_external_receive) receive += 1;
  }
  return {
    zero_send_capable: send === 0,
    zero_receive_capable: receive === 0,
  };
}

/**
 * In-memory store for unit tests. Seeds default FULL when a wallet is registered.
 */
export class InMemoryWalletMoneyCapabilityStore implements WalletMoneyCapabilityStore {
  readonly rows = new Map<string, MemoryWalletMoneyCapabilityRow>();
  readonly auditEntries: Array<{
    readonly walletId: string;
    readonly previousMode: WalletMoneyMode;
    readonly nextMode: WalletMoneyMode;
    readonly actorId: string;
    readonly nodeId: string;
    readonly details: string;
  }> = [];

  seed(row: MemoryWalletMoneyCapabilityRow): void {
    this.rows.set(row.wallet_id, { ...row });
  }

  async setMode(input: WalletMoneyCapabilitySetInput): Promise<WalletMoneyCapabilitySetOutcome> {
    if (!isWalletMoneyMode(input.mode)) {
      return { ok: false, reason: "invalid_mode" };
    }
    const row = this.rows.get(input.walletId);
    if (row === undefined || row.node_id !== input.nodeId) {
      return { ok: false, reason: "wallet_not_found" };
    }
    if (row.row_version !== input.expectedRowVersion) {
      return { ok: false, reason: "conflict" };
    }

    const previousMode = row.money_mode;
    const previousFlags = flagsOf(row);
    const nextFlags = flagsFromMode(input.mode);

    row.money_mode = input.mode;
    row.allow_external_receive = nextFlags.allow_external_receive;
    row.allow_external_send = nextFlags.allow_external_send;
    row.allow_internal_move = nextFlags.allow_internal_move;
    row.row_version = row.row_version + 1;

    const details =
      `wallet_id=${input.walletId};previous_mode=${previousMode};next_mode=${input.mode}` +
      `;previous_allow_external_receive=${previousFlags.allow_external_receive}` +
      `;previous_allow_external_send=${previousFlags.allow_external_send}` +
      `;previous_allow_internal_move=${previousFlags.allow_internal_move}` +
      `;next_allow_external_receive=${nextFlags.allow_external_receive}` +
      `;next_allow_external_send=${nextFlags.allow_external_send}` +
      `;next_allow_internal_move=${nextFlags.allow_internal_move}` +
      `;previous_row_version=${input.expectedRowVersion}` +
      `;next_row_version=${row.row_version}`;

    this.auditEntries.push({
      walletId: input.walletId,
      previousMode,
      nextMode: input.mode,
      actorId: input.actorId,
      nodeId: input.nodeId,
      details,
    });

    const warnings = fleetWarnings([...this.rows.values()].filter((r) => r.node_id === input.nodeId));

    return {
      ok: true,
      result: {
        wallet_id: row.wallet_id,
        money_mode: row.money_mode,
        allow_external_receive: row.allow_external_receive,
        allow_external_send: row.allow_external_send,
        allow_internal_move: row.allow_internal_move,
        row_version: row.row_version,
        previous_mode: previousMode,
        previous_flags: previousFlags,
        warnings,
      },
    };
  }
}

/**
 * SQL-backed store over `wallets` + `audit_log`.
 *
 * When bound to an admin-mutation PoolClient the CAS + audit ride that outer TX
 * so a later ROLLBACK undoes both with the idempotency row.
 */
export function createSqlWalletMoneyCapabilityStore(
  sql: WalletMoneyCapabilitySqlExecutor,
  opts?: { readonly newId?: () => string },
): WalletMoneyCapabilityStore {
  const newId = opts?.newId ?? (() => randomUUID());

  return {
    async setMode(input: WalletMoneyCapabilitySetInput): Promise<WalletMoneyCapabilitySetOutcome> {
      if (!isWalletMoneyMode(input.mode)) {
        return { ok: false, reason: "invalid_mode" };
      }
      const nextFlags = flagsFromMode(input.mode);

      // Lock the target row first so CAS and previous_* capture one consistent snapshot.
      const locked = await sql.query<{
        id: string;
        money_mode: string;
        allow_external_receive: boolean;
        allow_external_send: boolean;
        allow_internal_move: boolean;
        row_version: string | number;
      }>(
        `SELECT id::text AS id,
                money_mode,
                allow_external_receive,
                allow_external_send,
                allow_internal_move,
                row_version
           FROM wallets
          WHERE id = $1::uuid AND node_id = $2::uuid
          FOR UPDATE`,
        [input.walletId, input.nodeId],
      );
      const row = locked.rows[0];
      if (row === undefined) {
        return { ok: false, reason: "wallet_not_found" };
      }
      const currentVersion = Number(row.row_version);
      if (!Number.isInteger(currentVersion) || currentVersion !== input.expectedRowVersion) {
        return { ok: false, reason: "conflict" };
      }
      if (!isWalletMoneyMode(row.money_mode)) {
        // Corrupt stored mode — refuse rather than invent a previous_* audit field.
        return { ok: false, reason: "conflict" };
      }

      const previousMode: WalletMoneyMode = row.money_mode;
      const previousFlags = flagsOf({
        allow_external_receive: Boolean(row.allow_external_receive),
        allow_external_send: Boolean(row.allow_external_send),
        allow_internal_move: Boolean(row.allow_internal_move),
      });

      const updated = await sql.query<{
        money_mode: string;
        allow_external_receive: boolean;
        allow_external_send: boolean;
        allow_internal_move: boolean;
        row_version: string | number;
      }>(
        `UPDATE wallets
            SET money_mode = $3,
                allow_external_receive = $4,
                allow_external_send = $5,
                allow_internal_move = $6,
                row_version = row_version + 1
          WHERE id = $1::uuid
            AND node_id = $2::uuid
            AND row_version = $7
        RETURNING money_mode,
                  allow_external_receive,
                  allow_external_send,
                  allow_internal_move,
                  row_version`,
        [
          input.walletId,
          input.nodeId,
          input.mode,
          nextFlags.allow_external_receive,
          nextFlags.allow_external_send,
          nextFlags.allow_internal_move,
          input.expectedRowVersion,
        ],
      );
      const next = updated.rows[0];
      if (next === undefined) {
        return { ok: false, reason: "conflict" };
      }

      const nextRowVersion = Number(next.row_version);
      const details =
        `wallet_id=${input.walletId};previous_mode=${previousMode};next_mode=${input.mode}` +
        `;previous_allow_external_receive=${previousFlags.allow_external_receive}` +
        `;previous_allow_external_send=${previousFlags.allow_external_send}` +
        `;previous_allow_internal_move=${previousFlags.allow_internal_move}` +
        `;next_allow_external_receive=${nextFlags.allow_external_receive}` +
        `;next_allow_external_send=${nextFlags.allow_external_send}` +
        `;next_allow_internal_move=${nextFlags.allow_internal_move}` +
        `;previous_row_version=${input.expectedRowVersion}` +
        `;next_row_version=${nextRowVersion}`;

      await sql.query(
        `INSERT INTO audit_log (
           id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
           details_text, details_sha256, created_at
         ) VALUES (
           $1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, $4, NULL, $5::uuid,
           $6, $7, now()
         )`,
        [
          newId(),
          input.nodeId,
          input.actorId,
          WALLET_MONEY_CAPABILITY_AUDIT_ACTION,
          input.walletId,
          details,
          detailsSha256(details),
        ],
      );

      const fleet = await sql.query<{
        allow_external_receive: boolean;
        allow_external_send: boolean;
      }>(
        `SELECT allow_external_receive, allow_external_send
           FROM wallets
          WHERE node_id = $1::uuid`,
        [input.nodeId],
      );

      return {
        ok: true,
        result: {
          wallet_id: input.walletId,
          money_mode: input.mode,
          allow_external_receive: Boolean(next.allow_external_receive),
          allow_external_send: Boolean(next.allow_external_send),
          allow_internal_move: Boolean(next.allow_internal_move),
          row_version: nextRowVersion,
          previous_mode: previousMode,
          previous_flags: previousFlags,
          warnings: fleetWarnings(fleet.rows),
        },
      };
    },
  };
}
