// PG SnapshotStateReader over operations + destinations.
// Non-expired proof-access ops: open (terminal_at IS NULL) OR still inside
// verification_material_available_until.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type { WalletKeyOrigin, WalletState } from "@zucoins/generic-node-contracts/custody";
import { verifyAutomaticSinkEligibility } from "@zucoins/generic-node-contracts/custody";

import type {
  SnapshotAttentionItem,
  SnapshotDestination,
  SnapshotOperation,
  SnapshotStateReader,
} from "./snapshot-service.js";
import type { SqlQueryFn } from "./pg-implementer-event-log.js";

export interface PgSnapshotStateReaderConfig {
  readonly nodeId: string;
  readonly query: SqlQueryFn;
  readonly nowMs?: () => number;
}

const OPS_SELECT = `
SELECT id::text AS operation_id,
       kind::text AS operation_type,
       status::text AS state,
       amount_zkz,
       row_version::bigint AS row_version,
       attention_required,
       attention_reason,
       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
       CASE WHEN terminal_at IS NULL THEN NULL
            ELSE to_char(terminal_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
       END AS terminal_at,
       CASE WHEN verification_material_available_until IS NULL THEN NULL
            ELSE to_char(verification_material_available_until AT TIME ZONE 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
       END AS verification_material_available_until,
       COALESCE(attention_episode, 0)::int AS attention_episode
  FROM operations
 WHERE node_id = $1::uuid
   AND implementer_id = $2::uuid
   AND (
     terminal_at IS NULL
     OR verification_material_available_until IS NULL
     OR verification_material_available_until > $3::timestamptz
   )
 ORDER BY updated_at ASC, id ASC -- contract-allow:order:frozen structural vocabulary
`;

const DEST_SELECT = `
SELECT d.id::text AS destination_id,
       d.state::text AS state,
       w.key_origin::text AS key_origin,
       w.state::text AS wallet_state,
       CASE WHEN w.recovery_verified_at IS NULL THEN NULL
            ELSE to_char(w.recovery_verified_at AT TIME ZONE 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS"Z"')
       END AS recovery_verified_at
  FROM destinations d
  JOIN wallets w ON w.id = d.wallet_id
 WHERE d.node_id = $1::uuid
   AND d.state IN ('PENDING', 'BLESSED', 'RETIRED')
 ORDER BY d.created_at ASC, d.id ASC -- contract-allow:order:frozen structural vocabulary
`;

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Date) return value.toISOString();
  throw new Error(`expected string, got ${typeof value}`);
}

function asNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") return Number(value);
  throw new Error(`expected number, got ${typeof value}`);
}

function asBool(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value === "t" || value === "true") return true;
  if (value === "f" || value === "false") return false;
  throw new Error(`expected boolean, got ${typeof value}`);
}

export function createPgSnapshotStateReader(
  config: PgSnapshotStateReaderConfig,
): SnapshotStateReader {
  const nowMs = config.nowMs ?? (() => Date.now());

  return {
    async readState(
      implementerId: string,
      _watermark: bigint,
    ): Promise<{
      readonly operations: readonly SnapshotOperation[];
      readonly destinations: readonly SnapshotDestination[];
      readonly attentionItems: readonly SnapshotAttentionItem[];
    }> {
      const nowIso = new Date(nowMs()).toISOString();
      const [opRows, destRows] = await Promise.all([
        config.query(OPS_SELECT, [config.nodeId, implementerId, nowIso]),
        config.query(DEST_SELECT, [config.nodeId]),
      ]);

      const operations: SnapshotOperation[] = opRows.map((row) =>
        Object.freeze({
          operationId: asString(row.operation_id),
          operationType: asString(row.operation_type) as OperationKind,
          state: asString(row.state),
          amountZkz: asString(row.amount_zkz),
          rowVersion: asNumber(row.row_version),
          attentionRequired: asBool(row.attention_required),
          attentionReason:
            row.attention_reason === null || row.attention_reason === undefined
              ? null
              : asString(row.attention_reason),
          createdAt: asString(row.created_at),
          updatedAt: asString(row.updated_at),
          terminalAt:
            row.terminal_at === null || row.terminal_at === undefined
              ? null
              : asString(row.terminal_at),
          verificationMaterialAvailableUntil:
            row.verification_material_available_until === null ||
            row.verification_material_available_until === undefined
              ? null
              : asString(row.verification_material_available_until),
        }),
      );

      const attentionItems: SnapshotAttentionItem[] = opRows
        .filter((row) => asBool(row.attention_required))
        .map((row) =>
          Object.freeze({
            operationId: asString(row.operation_id),
            attentionReason: asString(row.attention_reason ?? "UNKNOWN"),
            attentionEpisode: asNumber(row.attention_episode ?? 0),
          }),
        );

      const destinations: SnapshotDestination[] = destRows.map((row) => {
        const state = asString(row.state);
        if (state !== "PENDING" && state !== "BLESSED" && state !== "RETIRED") {
          throw new Error(`unexpected destination state: ${state}`);
        }
        const keyOrigin = asString(row.key_origin) as WalletKeyOrigin;
        const walletState = asString(row.wallet_state) as WalletState;
        const recoveryVerifiedAt =
          row.recovery_verified_at === null || row.recovery_verified_at === undefined
            ? null
            : asString(row.recovery_verified_at);
        const decision = verifyAutomaticSinkEligibility({
          keyOrigin,
          destinationState: state,
          recoveryVerifiedAt,
          walletState,
        });
        return Object.freeze({
          destinationId: asString(row.destination_id),
          state,
          moveEligible: decision.eligible,
        });
      });

      return { operations, destinations, attentionItems };
    },
  };
}
