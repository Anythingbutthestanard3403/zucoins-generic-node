// In-process ImplementerRegistry for unit tests. Mirrors the SQL store's
// audit actions and retire / funding-wallet semantics without a database.

import { createHash, randomUUID } from "node:crypto";

import type { AuditLogRow } from "../core/audit-writer.js";
import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerRetireInput,
  type ImplementerSetFundingWalletInput,
  type ImplementerSetFundingWalletOutcome,
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
    row: Omit<ImplementerRecord, "funding_wallet_id" | "funding_wallet_public_key"> & {
      readonly funding_wallet_id?: string | null;
      readonly funding_wallet_public_key?: string | null;
    },
  ): void {
    this.rows.set(row.id, {
      id: row.id,
      name: row.name,
      created_at: row.created_at,
      retired_at: row.retired_at,
      funding_wallet_id: row.funding_wallet_id ?? null,
      funding_wallet_public_key: row.funding_wallet_public_key ?? null,
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
    const row: ImplementerRecord = {
      ...existing,
      funding_wallet_id: nextWalletId,
      funding_wallet_public_key: nextPublicKey,
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
}
