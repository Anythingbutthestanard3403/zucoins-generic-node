// Inventory persistence ports + empty / in-memory / SQL adapters.
// App shell imports @zucoins/node-core only (boundaries.test.ts).

import {
  AUDIT_WRITER_ACTOR_KINDS,
  buildWalletCustodyView,
  deriveMoveEligibility,
  redactAuditDetails,
  type AuditActorKind,
  type DestinationListItem,
  type DestinationService,
  type DestinationState,
  type WalletCustodyRow,
  type WalletCustodyView,
  type WalletRecoveryVerificationRow,
} from "@zucoins/node-core";

type WalletState = WalletCustodyView["state"];
type WalletKeyOrigin = WalletCustodyView["key_origin"];

import {
  DEFAULT_INVENTORY_LIMIT,
  INVENTORY_OPERATION_KINDS,
  MAX_INVENTORY_LIMIT,
  type AuditInventoryFilter,
  type AuditInventoryItem,
  type DestinationInventoryFilter,
  type DestinationInventoryItem,
  type InventoryListPage,
  type InventoryOperationKind,
  type OperationInventoryDetail,
  type OperationInventoryFilter,
  type OperationInventoryListItem,
  type WalletInventoryDetail,
  type WalletInventoryFilter,
  type WalletInventoryItem,
} from "./types.js";

export interface AdminInventoryStore {
  listWallets(
    nodeId: string,
    filter: WalletInventoryFilter,
  ): Promise<InventoryListPage<WalletInventoryItem>>;
  getWallet(nodeId: string, idOrPubkey: string): Promise<WalletInventoryDetail | null>;
  listOperations(
    nodeId: string,
    filter: OperationInventoryFilter,
  ): Promise<InventoryListPage<OperationInventoryListItem>>;
  getOperation(nodeId: string, operationId: string): Promise<OperationInventoryDetail | null>;
  listDestinations(
    nodeId: string,
    filter: DestinationInventoryFilter,
  ): Promise<InventoryListPage<DestinationInventoryItem>>;
  listAudit(
    nodeId: string,
    filter: AuditInventoryFilter,
  ): Promise<InventoryListPage<AuditInventoryItem>>;
}

const WALLET_STATES_LOCAL = ["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"] as const;
const KEY_ORIGINS_LOCAL = ["node_generated", "imported"] as const;
const DEST_STATES_LOCAL = ["PENDING", "BLESSED", "RETIRED"] as const;

function clampLimit(raw: number | undefined): number {
  if (raw === undefined || !Number.isFinite(raw)) return DEFAULT_INVENTORY_LIMIT;
  return Math.min(MAX_INVENTORY_LIMIT, Math.max(1, Math.trunc(raw)));
}

function emptyPage<T>(): InventoryListPage<T> {
  return { object: "list", data: [], has_more: false, next_cursor: null };
}

function pageOf<T>(
  rows: readonly T[],
  limit: number,
  cursorOf: (row: T) => string,
): InventoryListPage<T> {
  const slice = rows.slice(0, limit);
  const hasMore = rows.length > limit;
  const last = slice[slice.length - 1];
  return {
    object: "list",
    data: slice,
    has_more: hasMore,
    next_cursor: hasMore && last !== undefined ? cursorOf(last) : null,
  };
}

export function createEmptyAdminInventoryStore(): AdminInventoryStore {
  return {
    listWallets: async () => emptyPage(),
    getWallet: async () => null,
    listOperations: async () => emptyPage(),
    getOperation: async () => null,
    listDestinations: async () => emptyPage(),
    listAudit: async () => emptyPage(),
  };
}

// --- In-memory (contract tests) ---

export interface MemoryWalletSeed {
  readonly custody: WalletCustodyRow;
  readonly evidence?: WalletRecoveryVerificationRow | null;
  readonly observed_balance_zkz?: string | null;
  readonly holding?: Partial<
    Pick<
      WalletInventoryItem,
      | "holding_operation_id"
      | "holding_operation_status"
      | "holding_operation_expiry_unix_time_secs"
      | "holding_operation_attention_required"
      | "holding_operation_terminal_at"
      | "holding_lease_role"
      | "holding_operation_type"
    >
  >;
  /** Money capability override; omitted seeds default FULL (ZTR-1267). */
  readonly money_capability?: Partial<
    Pick<
      WalletInventoryItem,
      | "money_mode"
      | "allow_external_receive"
      | "allow_external_send"
      | "allow_internal_move"
      | "row_version"
    >
  >;
}

export interface MemoryOperationSeed {
  readonly list: OperationInventoryListItem;
  readonly detail?: Omit<OperationInventoryDetail, keyof OperationInventoryListItem>;
}

export interface MemoryAuditSeed {
  readonly item: AuditInventoryItem;
}

export interface MemoryInventorySeed {
  readonly wallets?: readonly MemoryWalletSeed[];
  readonly operations?: readonly MemoryOperationSeed[];
  readonly destinations?: readonly DestinationInventoryItem[];
  readonly audit?: readonly MemoryAuditSeed[];
}

function emptyHolding(): Pick<
  WalletInventoryItem,
  | "holding_operation_id"
  | "holding_operation_status"
  | "holding_operation_expiry_unix_time_secs"
  | "holding_operation_attention_required"
  | "holding_operation_terminal_at"
  | "holding_lease_role"
  | "holding_operation_type"
> {
  return {
    holding_operation_id: null,
    holding_operation_status: null,
    holding_operation_expiry_unix_time_secs: null,
    holding_operation_attention_required: false,
    holding_operation_terminal_at: null,
    holding_lease_role: null,
    holding_operation_type: null,
  };
}

/** New-mint / memory default: FULL unrestricted capability (ZTR-1267). */
function defaultMoneyCapability(): Pick<
  WalletInventoryItem,
  | "money_mode"
  | "allow_external_receive"
  | "allow_external_send"
  | "allow_internal_move"
  | "row_version"
> {
  return {
    money_mode: "FULL",
    allow_external_receive: true,
    allow_external_send: true,
    allow_internal_move: true,
    row_version: 1,
  };
}

function walletItem(seed: MemoryWalletSeed): WalletInventoryItem {
  const view = buildWalletCustodyView(seed.custody, seed.evidence ?? null);
  return {
    ...view,
    observed_balance_zkz: seed.observed_balance_zkz ?? null,
    ...emptyHolding(),
    ...(seed.holding ?? {}),
    ...defaultMoneyCapability(),
    ...(seed.money_capability ?? {}),
  };
}

export function createMemoryAdminInventoryStore(
  seed: MemoryInventorySeed = {},
): AdminInventoryStore {
  const wallets = [...(seed.wallets ?? [])];
  const operations = [...(seed.operations ?? [])];
  const destinations = [...(seed.destinations ?? [])];
  const audit = [...(seed.audit ?? [])].map((a) => a.item);

  return {
    async listWallets(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      let rows = wallets
        .map(walletItem)
        .filter((w) => w.node_id === nodeId)
        .sort((a, b) =>
          a.created_at < b.created_at
            ? 1
            : a.created_at > b.created_at
              ? -1
              : a.wallet_id.localeCompare(b.wallet_id),
        );
      if (filter.state !== undefined) rows = rows.filter((w) => w.state === filter.state);
      if (filter.key_origin !== undefined)
        rows = rows.filter((w) => w.key_origin === filter.key_origin);
      if (filter.recovery_verified !== undefined)
        rows = rows.filter((w) => w.recovery_verified === filter.recovery_verified);
      if (filter.after !== undefined) {
        const idx = rows.findIndex((w) => w.wallet_id === filter.after);
        rows = idx >= 0 ? rows.slice(idx + 1) : rows;
      }
      return pageOf(rows.slice(0, limit + 1), limit, (w) => w.wallet_id);
    },

    async getWallet(nodeId, idOrPubkey) {
      const found = wallets.find(
        (w) =>
          w.custody.nodeId === nodeId &&
          (w.custody.walletId === idOrPubkey || w.custody.publicKey === idOrPubkey),
      );
      return found === undefined ? null : walletItem(found);
    },

    async listOperations(nodeId, filter) {
      void nodeId;
      const limit = clampLimit(filter.limit);
      let rows = operations
        .map((o) => o.list)
        .sort((a, b) =>
          a.created_at < b.created_at
            ? 1
            : a.created_at > b.created_at
              ? -1
              : a.operation_id.localeCompare(b.operation_id),
        );
      if (filter.kind !== undefined) rows = rows.filter((o) => o.operation_type === filter.kind);
      if (filter.status !== undefined) rows = rows.filter((o) => o.status === filter.status);
      if (filter.attention_required !== undefined)
        rows = rows.filter((o) => o.attention_required === filter.attention_required);
      if (filter.after !== undefined) {
        const idx = rows.findIndex((o) => o.operation_id === filter.after);
        rows = idx >= 0 ? rows.slice(idx + 1) : rows;
      }
      return pageOf(rows.slice(0, limit + 1), limit, (o) => o.operation_id);
    },

    async getOperation(_nodeId, operationId) {
      const found = operations.find((o) => o.list.operation_id === operationId);
      if (found === undefined) return null;
      const extra = found.detail ?? {
        source_wallet_id: null,
        receiver_wallet_id: null,
        destination_id: null,
        destination_address: null,
        after_landing: null,
        after_landing_destination_id: null,
        formation_state: "NOT_REQUIRED",
        verification_verdict: "PENDING",
        implementer_id: "00000000-0000-4000-8000-000000000000",
        client_reference: null,
      };
      return { ...found.list, ...extra };
    },

    async listDestinations(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      let rows = destinations
        .filter((d) => d.node_id === nodeId)
        .sort((a, b) => a.destination_id.localeCompare(b.destination_id));
      if (filter.state !== undefined) rows = rows.filter((d) => d.state === filter.state);
      if (filter.after !== undefined) {
        const idx = rows.findIndex((d) => d.destination_id === filter.after);
        rows = idx >= 0 ? rows.slice(idx + 1) : rows;
      }
      return pageOf(rows.slice(0, limit + 1), limit, (d) => d.destination_id);
    },

    async listAudit(nodeId, filter) {
      void nodeId;
      const limit = clampLimit(filter.limit);
      let rows = [...audit].sort((a, b) =>
        a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : a.id.localeCompare(b.id),
      );
      if (filter.actor_kind !== undefined)
        rows = rows.filter((a) => a.actor_kind === filter.actor_kind);
      if (filter.action !== undefined && filter.action !== "")
        rows = rows.filter((a) => a.action === filter.action);
      if (filter.created_after !== undefined) {
        const t = Date.parse(filter.created_after);
        if (Number.isFinite(t)) rows = rows.filter((a) => Date.parse(a.created_at) > t);
      }
      if (filter.created_before !== undefined) {
        const t = Date.parse(filter.created_before);
        if (Number.isFinite(t)) rows = rows.filter((a) => Date.parse(a.created_at) < t);
      }
      if (filter.after !== undefined) {
        const idx = rows.findIndex((a) => a.id === filter.after);
        rows = idx >= 0 ? rows.slice(idx + 1) : rows;
      }
      return pageOf(rows.slice(0, limit + 1), limit, (a) => a.id);
    },
  };
}

// --- Destinations via DestinationService (live bless-state mirror) ---

function destinationWire(item: DestinationListItem): DestinationInventoryItem {
  return {
    destination_id: item.destinationId,
    node_id: item.nodeId,
    wallet_id: item.walletId,
    wallet_public_key: item.walletPublicKey,
    state: item.state,
    label: item.label,
    blessed_at: item.blessedAt,
    blessed_by_device_key_id: item.blessedByDeviceKeyId,
    blessing_artifact_id: item.blessingArtifactId,
    retired_at: item.retiredAt,
    created_at: item.createdAt,
    move_eligible: item.move_eligible,
    ineligibility_reason: item.ineligibility_reason,
  };
}

/**
 * Overlay destinations list onto another inventory store by calling DestinationService.
 * Fail-closed services (throws) become empty pages rather than 503 — inventory GETs stay
 * readable while money engines remain unwired.
 */
export function withDestinationServiceInventory(
  base: AdminInventoryStore,
  destinationService: DestinationService,
): AdminInventoryStore {
  return {
    ...base,
    async listDestinations(nodeId, filter) {
      try {
        const page = await destinationService.list(nodeId as never, {
          state: filter.state,
          after: filter.after as never,
          limit: clampLimit(filter.limit),
        });
        const data = page.items.map(destinationWire);
        return {
          object: "list",
          data,
          has_more: page.nextAfter !== null,
          next_cursor: page.nextAfter,
        };
      } catch {
        return emptyPage();
      }
    },
  };
}

// --- SQL adapter ---

export interface InventorySqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

function ts(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

function tsOrNull(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return ts(v);
}

function mapWalletRow(
  row: Record<string, unknown>,
  evidence: WalletRecoveryVerificationRow | null,
  observed: string | null,
): WalletInventoryItem {
  const custody: WalletCustodyRow = {
    walletId: String(row.id) as never,
    nodeId: String(row.node_id) as never,
    publicKey: String(row.public_key) as never,
    keyOrigin: row.key_origin as WalletKeyOrigin,
    state: row.state as WalletState,
    createdAt: ts(row.created_at),
    retiredAt: tsOrNull(row.retired_at),
    quarantineReason:
      row.quarantine_reason === null || row.quarantine_reason === undefined
        ? null
        : String(row.quarantine_reason),
    recoveryVerifiedAt: tsOrNull(row.recovery_verified_at),
    recoveryVerificationId:
      row.recovery_verification_id === null || row.recovery_verification_id === undefined
        ? null
        : (String(row.recovery_verification_id) as never),
  };
  return {
    ...buildWalletCustodyView(custody, evidence),
    observed_balance_zkz: observed,
    holding_operation_id:
      row.holding_operation_id == null ? null : String(row.holding_operation_id),
    holding_operation_status:
      row.holding_operation_status == null ? null : String(row.holding_operation_status),
    holding_operation_expiry_unix_time_secs:
      row.holding_operation_expiry_unix_time_secs == null
        ? null
        : String(row.holding_operation_expiry_unix_time_secs),
    holding_operation_attention_required: Boolean(row.holding_operation_attention_required),
    holding_operation_terminal_at: tsOrNull(row.holding_operation_terminal_at),
    holding_lease_role: row.holding_lease_role == null ? null : String(row.holding_lease_role),
    holding_operation_type:
      row.holding_operation_type == null ? null : String(row.holding_operation_type),
    money_mode: row.money_mode == null ? "FULL" : String(row.money_mode),
    allow_external_receive: Boolean(row.allow_external_receive),
    allow_external_send: Boolean(row.allow_external_send),
    allow_internal_move: Boolean(row.allow_internal_move),
    row_version: Number(row.row_version ?? 1),
  };
}

export function createSqlAdminInventoryStore(sql: InventorySqlExecutor): AdminInventoryStore {
  return {
    async listWallets(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      const params: unknown[] = [nodeId];
      const where: string[] = ["w.node_id = $1"];
      if (filter.state !== undefined && isWalletState(filter.state)) {
        params.push(filter.state);
        where.push(`w.state = $${params.length}`);
      }
      if (filter.key_origin !== undefined && isWalletKeyOrigin(filter.key_origin)) {
        params.push(filter.key_origin);
        where.push(`w.key_origin = $${params.length}`);
      }
      if (filter.recovery_verified === true) {
        where.push("w.recovery_verified_at IS NOT NULL");
      } else if (filter.recovery_verified === false) {
        where.push("w.recovery_verified_at IS NULL");
      }
      if (filter.after !== undefined) {
        params.push(filter.after);
        where.push(
          `(w.created_at, w.id) < (
             SELECT w2.created_at, w2.id FROM wallets w2 WHERE w2.id = $${params.length}::uuid
           )`,
        );
      }
      params.push(limit + 1);
      const result = await sql.query(
        `SELECT w.id, w.node_id, w.public_key, w.key_origin, w.state,
                w.created_at, w.retired_at, w.quarantine_reason,
                w.recovery_verified_at, w.recovery_verification_id,
                w.money_mode, w.allow_external_receive, w.allow_external_send,
                w.allow_internal_move, w.row_version,
                l.operation_id::text AS holding_operation_id,
                l.lease_role::text AS holding_lease_role,
                o.status::text AS holding_operation_status,
                o.kind::text AS holding_operation_type,
                o.expiry_unix_time_secs AS holding_operation_expiry_unix_time_secs,
                COALESCE(o.attention_required, false) AS holding_operation_attention_required,
                o.terminal_at AS holding_operation_terminal_at
           FROM wallets w
           LEFT JOIN LATERAL (
             SELECT wal.operation_id, wal.lease_role
               FROM wallet_active_leases wal
              WHERE wal.wallet_id = w.id
              ORDER BY wal.acquired_at DESC NULLS LAST -- contract-allow:order:frozen structural vocabulary
              LIMIT 1
           ) l ON true
           LEFT JOIN operations o ON o.id = l.operation_id
          WHERE ${where.join(" AND ")}
          ORDER BY w.created_at DESC, w.id DESC -- contract-allow:order:frozen structural vocabulary
          LIMIT $${params.length}`,
        params,
      );
      const items: WalletInventoryItem[] = [];
      for (const row of result.rows) {
        const evidence = await loadEvidence(sql, row.recovery_verification_id);
        const observed = await loadObservedBalance(sql, String(row.id));
        items.push(mapWalletRow(row, evidence, observed));
      }
      return pageOf(items, limit, (w) => w.wallet_id);
    },

    async getWallet(nodeId, idOrPubkey) {
      const byId = await sql.query(
        `SELECT w.id, w.node_id, w.public_key, w.key_origin, w.state, w.created_at, w.retired_at,
                w.quarantine_reason, w.recovery_verified_at, w.recovery_verification_id,
                w.money_mode, w.allow_external_receive, w.allow_external_send,
                w.allow_internal_move, w.row_version,
                l.operation_id::text AS holding_operation_id,
                l.lease_role::text AS holding_lease_role,
                o.status::text AS holding_operation_status,
                o.kind::text AS holding_operation_type,
                o.expiry_unix_time_secs AS holding_operation_expiry_unix_time_secs,
                COALESCE(o.attention_required, false) AS holding_operation_attention_required,
                o.terminal_at AS holding_operation_terminal_at
           FROM wallets w
           LEFT JOIN LATERAL (
             SELECT wal.operation_id, wal.lease_role
               FROM wallet_active_leases wal
              WHERE wal.wallet_id = w.id
              ORDER BY wal.acquired_at DESC NULLS LAST -- contract-allow:order:frozen structural vocabulary
              LIMIT 1
           ) l ON true
           LEFT JOIN operations o ON o.id = l.operation_id
          WHERE w.node_id = $1 AND (w.id::text = $2 OR w.public_key = $2)
          LIMIT 1`,
        [nodeId, idOrPubkey],
      );
      const row = byId.rows[0];
      if (row === undefined) return null;
      const evidence = await loadEvidence(sql, row.recovery_verification_id);
      const observed = await loadObservedBalance(sql, String(row.id));
      return mapWalletRow(row, evidence, observed);
    },

    async listOperations(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      const params: unknown[] = [nodeId];
      const where: string[] = ["o.node_id = $1"];
      if (filter.kind !== undefined && isOperationKind(filter.kind)) {
        params.push(filter.kind);
        where.push(`o.kind = $${params.length}`);
      }
      if (filter.status !== undefined) {
        params.push(filter.status);
        where.push(`o.status = $${params.length}`);
      }
      if (filter.attention_required !== undefined) {
        params.push(filter.attention_required);
        where.push(`o.attention_required = $${params.length}`);
      }
      if (filter.after !== undefined) {
        params.push(filter.after);
        where.push(
          `(o.created_at, o.id) < (
             SELECT o2.created_at, o2.id FROM operations o2 WHERE o2.id = $${params.length}::uuid
           )`,
        );
      }
      params.push(limit + 1);
      const result = await sql.query(
        `SELECT o.id, o.kind, o.status, o.amount_zkz, o.row_version,
                o.attention_required, o.attention_reason,
                o.created_at, o.updated_at, o.terminal_at,
                o.expiry_unix_time_secs,
                o.destination_address
           FROM operations o
          WHERE ${where.join(" AND ")}
          ORDER BY o.created_at DESC, o.id DESC -- contract-allow:order:frozen structural vocabulary
          LIMIT $${params.length}`,
        params,
      );
      const items = result.rows.map((row) => mapOpList(row));
      return pageOf(items, limit, (o) => o.operation_id);
    },

    async getOperation(nodeId, operationId) {
      const result = await sql.query(
        `SELECT o.id, o.kind, o.status, o.amount_zkz, o.row_version,
                o.attention_required, o.attention_reason,
                o.created_at, o.updated_at, o.terminal_at,
                o.expiry_unix_time_secs,
                o.source_wallet_id, o.receiver_wallet_id, o.destination_id,
                o.destination_address, o.after_landing, o.after_landing_destination_id,
                o.formation_state, o.verification_verdict, o.implementer_id,
                o.client_reference
           FROM operations o
          WHERE o.node_id = $1 AND o.id = $2::uuid
          LIMIT 1`,
        [nodeId, operationId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      return mapOpDetail(row);
    },

    async listDestinations(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      const params: unknown[] = [nodeId];
      const where: string[] = ["d.node_id = $1"];
      if (filter.state !== undefined && isDestinationState(filter.state)) {
        params.push(filter.state);
        where.push(`d.state = $${params.length}`);
      }
      if (filter.after !== undefined) {
        params.push(filter.after);
        where.push(`d.id > $${params.length}::uuid`);
      }
      params.push(limit + 1);
      const result = await sql.query(
        `SELECT d.id, d.node_id, d.wallet_id, w.public_key AS wallet_public_key, d.state,
                d.blessed_at, d.blessed_by_device_key_id, d.blessing_artifact_id,
                d.retired_at, d.created_at,
                w.key_origin, w.state AS wallet_state, w.recovery_verified_at
           FROM destinations d
           JOIN wallets w ON w.id = d.wallet_id
          WHERE ${where.join(" AND ")}
          ORDER BY d.id ASC -- contract-allow:order:frozen structural vocabulary
          LIMIT $${params.length}`,
        params,
      );
      const items = result.rows.map((row) => mapDestRow(row));
      return pageOf(items, limit, (d) => d.destination_id);
    },

    async listAudit(nodeId, filter) {
      const limit = clampLimit(filter.limit);
      const params: unknown[] = [nodeId];
      const where: string[] = ["a.node_id = $1"];
      if (filter.actor_kind !== undefined && isAuditActorKind(filter.actor_kind)) {
        params.push(filter.actor_kind);
        where.push(`a.actor_kind = $${params.length}`);
      }
      if (filter.action !== undefined && filter.action !== "") {
        params.push(filter.action);
        where.push(`a.action = $${params.length}`);
      }
      if (filter.created_after !== undefined) {
        params.push(filter.created_after);
        where.push(`a.created_at > $${params.length}::timestamptz`);
      }
      if (filter.created_before !== undefined) {
        params.push(filter.created_before);
        where.push(`a.created_at < $${params.length}::timestamptz`);
      }
      // Id keyset — same shape as wallets/operations `after` / wire `next_cursor`.
      if (filter.after !== undefined) {
        params.push(filter.after);
        where.push(
          `(a.created_at, a.id) < (
             SELECT a2.created_at, a2.id FROM audit_log a2 WHERE a2.id = $${params.length}::uuid
           )`,
        );
      }
      params.push(limit + 1);
      const result = await sql.query(
        `SELECT a.id, a.actor_kind, a.actor_id, a.action, a.operation_id, a.wallet_id,
                a.details_text, a.details_sha256, a.created_at
           FROM audit_log a
          WHERE ${where.join(" AND ")}
          ORDER BY a.created_at DESC, a.id DESC -- contract-allow:order:frozen structural vocabulary
          LIMIT $${params.length}`,
        params,
      );
      const items = result.rows.map((row) => mapAuditRow(row));
      return pageOf(items, limit, (a) => a.id);
    },
  };
}

async function loadEvidence(
  sql: InventorySqlExecutor,
  verificationId: unknown,
): Promise<WalletRecoveryVerificationRow | null> {
  if (verificationId === null || verificationId === undefined) return null;
  const result = await sql.query(
    `SELECT id, wallet_id, method, verified_at, verifier_identity, audit_event_id
       FROM wallet_recovery_verifications WHERE id = $1::uuid`,
    [String(verificationId)],
  );
  const row = result.rows[0];
  if (row === undefined) return null;
  return {
    verificationId: String(row.id) as never,
    walletId: String(row.wallet_id) as never,
    method: String(row.method),
    verifiedAt: ts(row.verified_at),
    verifierIdentity: String(row.verifier_identity),
    auditEventId: String(row.audit_event_id) as never,
  };
}

/**
 * Latest known balance from the append-only observation ledger
 * (`gateway_observations.b_amount`). Null when no verified row has a balance.
 */
export async function loadObservedBalance(
  sql: InventorySqlExecutor,
  walletId: string,
): Promise<string | null> {
  const result = await sql.query(
    `SELECT b_amount
       FROM gateway_observations
      WHERE wallet_id = $1::uuid
        AND b_amount IS NOT NULL
      ORDER BY observed_at DESC, wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
      LIMIT 1`,
    [walletId],
  );
  const v = result.rows[0]?.b_amount;
  return v === null || v === undefined || v === "" ? null : String(v);
}

/** SQL text anchor — unit tests pin the real relation (not a fictional observation_records). */
export const OBSERVED_BALANCE_SQL_FRAGMENT = "FROM gateway_observations";

function mapOpList(row: Record<string, unknown>): OperationInventoryListItem {
  return {
    operation_id: String(row.id),
    operation_type: row.kind as InventoryOperationKind,
    status: String(row.status),
    amount_zkz: String(row.amount_zkz),
    row_version: Number(row.row_version),
    attention_required: Boolean(row.attention_required),
    attention_reason:
      row.attention_reason === null || row.attention_reason === undefined
        ? null
        : String(row.attention_reason),
    created_at: ts(row.created_at),
    updated_at: ts(row.updated_at),
    terminal_at: tsOrNull(row.terminal_at),
    // ZTR-1253: text unix-seconds expiry for operator countdown (null when unarmed).
    expiry_unix_time_secs:
      row.expiry_unix_time_secs === null || row.expiry_unix_time_secs === undefined
        ? null
        : String(row.expiry_unix_time_secs),
    // Summary-row field: the operator scanning view renders a destination per row, so the
    // list SELECT above must keep projecting it (admin-inventory.test.ts pins both).
    destination_address: row.destination_address == null ? null : String(row.destination_address),
  };
}

function mapOpDetail(row: Record<string, unknown>): OperationInventoryDetail {
  return {
    ...mapOpList(row),
    source_wallet_id: row.source_wallet_id == null ? null : String(row.source_wallet_id),
    receiver_wallet_id: row.receiver_wallet_id == null ? null : String(row.receiver_wallet_id),
    destination_id: row.destination_id == null ? null : String(row.destination_id),
    after_landing: row.after_landing == null ? null : String(row.after_landing),
    after_landing_destination_id:
      row.after_landing_destination_id == null ? null : String(row.after_landing_destination_id),
    formation_state: String(row.formation_state),
    verification_verdict: String(row.verification_verdict),
    implementer_id: String(row.implementer_id),
    client_reference: row.client_reference == null ? null : String(row.client_reference),
  };
}

function mapDestRow(row: Record<string, unknown>): DestinationInventoryItem {
  const destRecord = {
    destinationId: String(row.id) as never,
    nodeId: String(row.node_id) as never,
    walletId: String(row.wallet_id) as never,
    walletPublicKey: String(row.wallet_public_key) as never,
    state: String(row.state) as DestinationState,
    label: "",
    blessedAt: tsOrNull(row.blessed_at),
    blessedByDeviceKeyId:
      row.blessed_by_device_key_id == null ? null : (String(row.blessed_by_device_key_id) as never),
    blessingArtifactId:
      row.blessing_artifact_id == null ? null : (String(row.blessing_artifact_id) as never),
    retiredAt: tsOrNull(row.retired_at),
    createdAt: ts(row.created_at),
  };
  const elig = deriveMoveEligibility(destRecord, {
    keyOrigin: String(row.key_origin) as WalletKeyOrigin,
    walletState: String(row.wallet_state) as WalletState,
    recoveryVerifiedAt: tsOrNull(row.recovery_verified_at),
  });
  return {
    destination_id: destRecord.destinationId,
    node_id: destRecord.nodeId,
    wallet_id: destRecord.walletId,
    wallet_public_key: destRecord.walletPublicKey,
    state: destRecord.state,
    label: "",
    blessed_at: destRecord.blessedAt,
    blessed_by_device_key_id: destRecord.blessedByDeviceKeyId,
    blessing_artifact_id: destRecord.blessingArtifactId,
    retired_at: destRecord.retiredAt,
    created_at: destRecord.createdAt,
    move_eligible: elig.move_eligible,
    ineligibility_reason: elig.ineligibility_reason,
  };
}

function mapAuditRow(row: Record<string, unknown>): AuditInventoryItem {
  let details: unknown = {};
  try {
    details = JSON.parse(String(row.details_text));
  } catch {
    details = {};
  }
  details = redactAuditDetails(details as never);
  return {
    id: String(row.id),
    actor_kind: String(row.actor_kind) as AuditActorKind,
    actor_id: row.actor_id == null ? null : String(row.actor_id),
    action: String(row.action),
    operation_id: row.operation_id == null ? null : String(row.operation_id),
    wallet_id: row.wallet_id == null ? null : String(row.wallet_id),
    details,
    details_sha256: String(row.details_sha256),
    created_at: ts(row.created_at),
  };
}

export function isWalletState(v: string): v is WalletState {
  return (WALLET_STATES_LOCAL as readonly string[]).includes(v);
}

export function isWalletKeyOrigin(v: string): v is WalletKeyOrigin {
  return (KEY_ORIGINS_LOCAL as readonly string[]).includes(v);
}

export function isOperationKind(v: string): v is InventoryOperationKind {
  return (INVENTORY_OPERATION_KINDS as readonly string[]).includes(v);
}

export function isDestinationState(v: string): v is DestinationState {
  return (DEST_STATES_LOCAL as readonly string[]).includes(v);
}

export function isAuditActorKind(v: string): v is AuditActorKind {
  return (AUDIT_WRITER_ACTOR_KINDS as readonly string[]).includes(v);
}
