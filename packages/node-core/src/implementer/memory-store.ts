// In-process ImplementerRegistry for unit tests. Mirrors the SQL store's
// audit actions and retire / funding-wallet semantics without a database.

import { createHash, randomUUID } from "node:crypto";

import type { AuditLogRow } from "../core/audit-writer.js";
import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_CUSTOM_ROUTING_CHANGED,
  IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
  IMPLEMENTER_AUDIT_RESERVE_WALLETS_CHANGED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerReserveWallet,
  type ImplementerRetireInput,
  type ImplementerSetCustomRoutingInput,
  type ImplementerSetCustomRoutingOutcome,
  type ImplementerSetFundingWalletInput,
  type ImplementerSetFundingWalletOutcome,
  type ImplementerSetReserveWalletsInput,
  type ImplementerSetReserveWalletsOutcome,
} from "./types.js";

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function normalizeName(raw: string): string {
  const name = raw.trim();
  if (name.length === 0 || name.length > 128) {
    throw new ImplementerRegistryError(
      "name must be 1–128 characters after trim",
      "IMPLEMENTER_NAME_INVALID",
    );
  }
  return name;
}

export interface MemoryFundingWalletSeed {
  readonly id: string;
  readonly public_key: string;
  readonly retired?: boolean;
  readonly nodeId?: string;
  readonly display_label?: string | null;
  /** Defaults true so older funding-pin fixtures stay attachable. */
  readonly allow_internal_move?: boolean;
  readonly state?: string;
  /**
   * Defaults to INTERNAL_ONLY. RECEIVE_ONLY and SEND_ONLY cannot be bound.
   * FULL stays eligible.
   */
  readonly money_mode?: string;
  /** Defaults to BLESSED. Any other destination state cannot be bound. */
  readonly destination_state?: string;
}

function reserveWalletEligible(wallet: MemoryFundingWalletSeed): boolean {
  if (wallet.allow_internal_move === false) return false;
  const mode = wallet.money_mode ?? "INTERNAL_ONLY";
  if (mode !== "INTERNAL_ONLY" && mode !== "FULL") return false;
  return (wallet.destination_state ?? "BLESSED") === "BLESSED";
}

export class InMemoryImplementerRegistry implements ImplementerRegistry {
  readonly rows = new Map<string, ImplementerRecord>();
  readonly audit: AuditLogRow[] = [];
  /** Optional wallet catalog for setFundingWallet WALLET_ID / CREATE attach. */
  readonly wallets = new Map<string, MemoryFundingWalletSeed>();
  private readonly now: () => Date;

  constructor(now: () => Date = () => new Date()) {
    this.now = now;
  }

  /** Seed a row without audit (tests / fixtures). Funding fields default null. */
  seed(
    row: Omit<
      ImplementerRecord,
      "funding_wallet_id" | "funding_wallet_public_key" | "allow_custom_routing" | "reserve_wallets"
    > & {
      readonly funding_wallet_id?: string | null;
      readonly funding_wallet_public_key?: string | null;
      readonly allow_custom_routing?: boolean;
      readonly reserve_wallets?: readonly ImplementerReserveWallet[];
    },
  ): void {
    this.rows.set(row.id, {
      id: row.id,
      name: row.name,
      created_at: row.created_at,
      retired_at: row.retired_at,
      funding_wallet_id: row.funding_wallet_id ?? null,
      funding_wallet_public_key: row.funding_wallet_public_key ?? null,
      allow_custom_routing: row.allow_custom_routing ?? false,
      reserve_wallets: row.reserve_wallets ?? [],
    });
  }

  seedWallet(wallet: MemoryFundingWalletSeed): void {
    this.wallets.set(wallet.id, wallet);
  }

  async list(): Promise<readonly ImplementerRecord[]> {
    return [...this.rows.values()].sort((a, b) => {
      if (a.created_at !== b.created_at) return a.created_at < b.created_at ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
  }

  async get(id: string): Promise<ImplementerRecord | null> {
    return this.rows.get(id) ?? null;
  }

  async getActive(id: string): Promise<ImplementerRecord | null> {
    const row = this.rows.get(id);
    if (row === undefined || row.retired_at !== null) return null;
    return row;
  }

  async resolveGenesisId(): Promise<string | null> {
    const active = (await this.list()).filter((r) => r.retired_at === null);
    return active[0]?.id ?? null;
  }

  async create(input: ImplementerCreateInput): Promise<ImplementerRecord> {
    const name = normalizeName(input.name);
    const createdAt = this.now().toISOString();
    const row: ImplementerRecord = {
      id: randomUUID(),
      name,
      created_at: createdAt,
      retired_at: null,
      funding_wallet_id: null,
      funding_wallet_public_key: null,
      allow_custom_routing: false,
      reserve_wallets: [],
    };
    this.rows.set(row.id, row);
    const detailsText = JSON.stringify({ id: row.id, name: row.name });
    this.audit.push({
      id: randomUUID(),
      nodeId: input.nodeId,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      action: IMPLEMENTER_AUDIT_CREATED,
      operationId: null,
      walletId: null,
      detailsText,
      detailsSha256: detailsSha256(detailsText),
      createdAt,
    });
    return row;
  }

  async retire(input: ImplementerRetireInput): Promise<ImplementerRecord> {
    const existing = this.rows.get(input.id);
    if (existing === undefined) {
      throw new ImplementerRegistryError("implementer not found", "IMPLEMENTER_NOT_FOUND");
    }
    if (existing.retired_at !== null) {
      throw new ImplementerRegistryError(
        "implementer already retired",
        "IMPLEMENTER_ALREADY_RETIRED",
      );
    }
    const retiredAt = this.now().toISOString();
    const row: ImplementerRecord = { ...existing, retired_at: retiredAt };
    this.rows.set(row.id, row);
    const detailsText = JSON.stringify({ id: row.id, name: row.name });
    this.audit.push({
      id: randomUUID(),
      nodeId: input.nodeId,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      action: IMPLEMENTER_AUDIT_RETIRED,
      operationId: null,
      walletId: null,
      detailsText,
      detailsSha256: detailsSha256(detailsText),
      createdAt: retiredAt,
    });
    return row;
  }

  async setFundingWallet(
    input: ImplementerSetFundingWalletInput,
  ): Promise<ImplementerSetFundingWalletOutcome> {
    const mode = input.mode;
    if (mode !== "DEFAULT" && mode !== "WALLET_ID" && mode !== "CREATE") {
      return { ok: false, reason: "invalid_mode" };
    }
    const existing = this.rows.get(input.implementerId);
    if (existing === undefined) {
      return { ok: false, reason: "implementer_not_found" };
    }
    if (existing.retired_at !== null) {
      return { ok: false, reason: "implementer_retired" };
    }

    let nextWalletId: string | null = null;
    let nextPublicKey: string | null = null;

    if (mode === "DEFAULT") {
      nextWalletId = null;
      nextPublicKey = null;
    } else {
      const walletId = input.walletId?.trim() ?? "";
      if (walletId.length === 0) {
        return {
          ok: false,
          reason: mode === "CREATE" ? "create_not_supported" : "wallet_id_required",
        };
      }
      const wallet = this.wallets.get(walletId);
      if (wallet === undefined) {
        return { ok: false, reason: "wallet_not_found" };
      }
      if (wallet.retired === true) {
        return { ok: false, reason: "wallet_retired" };
      }
      nextWalletId = wallet.id;
      nextPublicKey = wallet.public_key;
    }

    const previousId = existing.funding_wallet_id;
    const wallet = nextWalletId === null ? undefined : this.wallets.get(nextWalletId);
    const reserveWallets: ImplementerReserveWallet[] =
      nextWalletId === null
        ? []
        : [
            {
              wallet_id: nextWalletId,
              public_key: nextPublicKey,
              display_label: wallet?.display_label ?? null,
              is_default: true,
            },
          ];
    const row: ImplementerRecord = {
      ...existing,
      funding_wallet_id: nextWalletId,
      funding_wallet_public_key: nextPublicKey,
      reserve_wallets: reserveWallets,
    };
    this.rows.set(row.id, row);
    const createdAt = this.now().toISOString();
    const detailsText = JSON.stringify({
      implementer_id: row.id,
      mode,
      previous_funding_wallet_id: previousId,
      next_funding_wallet_id: nextWalletId,
    });
    this.audit.push({
      id: randomUUID(),
      nodeId: input.nodeId,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      action: IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
      operationId: null,
      walletId: nextWalletId,
      detailsText,
      detailsSha256: detailsSha256(detailsText),
      createdAt,
    });
    return { ok: true, implementer: row };
  }

  async setReserveWallets(
    input: ImplementerSetReserveWalletsInput,
  ): Promise<ImplementerSetReserveWalletsOutcome> {
    const existing = this.rows.get(input.implementerId);
    if (existing === undefined) return { ok: false, reason: "implementer_not_found" };
    if (existing.retired_at !== null) return { ok: false, reason: "implementer_retired" };

    const ids = [...new Set(input.walletIds.map((id) => id.trim()).filter((id) => id.length > 0))];
    if (ids.length === 0) {
      if (input.defaultWalletId !== null) return { ok: false, reason: "default_mismatch" };
      const row: ImplementerRecord = {
        ...existing,
        funding_wallet_id: null,
        funding_wallet_public_key: null,
        reserve_wallets: [],
      };
      this.rows.set(row.id, row);
      this.pushReserveAudit(input, row, existing.funding_wallet_id);
      return { ok: true, implementer: row };
    }
    if (input.defaultWalletId === null || !ids.includes(input.defaultWalletId)) {
      return { ok: false, reason: "default_mismatch" };
    }

    const bound: ImplementerReserveWallet[] = [];
    for (const id of ids) {
      const wallet = this.wallets.get(id);
      if (wallet === undefined || (wallet.nodeId !== undefined && wallet.nodeId !== input.nodeId)) {
        return { ok: false, reason: "wallet_not_found" };
      }
      if (wallet.retired === true || wallet.state === "RETIRED") {
        return { ok: false, reason: "wallet_retired" };
      }
      if (!reserveWalletEligible(wallet)) {
        return { ok: false, reason: "wallet_ineligible" };
      }
      bound.push({
        wallet_id: wallet.id,
        public_key: wallet.public_key,
        display_label: wallet.display_label ?? null,
        is_default: wallet.id === input.defaultWalletId,
      });
    }
    const def = bound.find((w) => w.is_default);
    const row: ImplementerRecord = {
      ...existing,
      funding_wallet_id: def?.wallet_id ?? null,
      funding_wallet_public_key: def?.public_key ?? null,
      reserve_wallets: bound,
    };
    this.rows.set(row.id, row);
    this.pushReserveAudit(input, row, existing.funding_wallet_id);
    return { ok: true, implementer: row };
  }

  async setCustomRouting(
    input: ImplementerSetCustomRoutingInput,
  ): Promise<ImplementerSetCustomRoutingOutcome> {
    const existing = this.rows.get(input.implementerId);
    if (existing === undefined) return { ok: false, reason: "implementer_not_found" };
    if (existing.retired_at !== null) return { ok: false, reason: "implementer_retired" };
    const row: ImplementerRecord = {
      ...existing,
      allow_custom_routing: input.allowCustomRouting,
    };
    this.rows.set(row.id, row);
    const createdAt = this.now().toISOString();
    const detailsText = JSON.stringify({
      implementer_id: row.id,
      allow_custom_routing: input.allowCustomRouting,
    });
    this.audit.push({
      id: randomUUID(),
      nodeId: input.nodeId,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      action: IMPLEMENTER_AUDIT_CUSTOM_ROUTING_CHANGED,
      operationId: null,
      walletId: null,
      detailsText,
      detailsSha256: detailsSha256(detailsText),
      createdAt,
    });
    return { ok: true, implementer: row };
  }

  private pushReserveAudit(
    input: ImplementerSetReserveWalletsInput,
    row: ImplementerRecord,
    previousFundingWalletId: string | null,
  ): void {
    const createdAt = this.now().toISOString();
    const detailsText = JSON.stringify({
      implementer_id: row.id,
      previous_funding_wallet_id: previousFundingWalletId,
      next_funding_wallet_id: row.funding_wallet_id,
      wallet_ids: row.reserve_wallets.map((w) => w.wallet_id),
    });
    this.audit.push({
      id: randomUUID(),
      nodeId: input.nodeId,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      action: IMPLEMENTER_AUDIT_RESERVE_WALLETS_CHANGED,
      operationId: null,
      walletId: row.funding_wallet_id,
      detailsText,
      detailsSha256: detailsSha256(detailsText),
      createdAt,
    });
  }
}
