// In-process ImplementerRegistry for unit tests. Mirrors the SQL store's
// audit actions and retire semantics without a database.

import { createHash, randomUUID } from "node:crypto";

import type { AuditLogRow } from "../core/audit-writer.js";
import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerRetireInput,
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

export class InMemoryImplementerRegistry implements ImplementerRegistry {
  readonly rows = new Map<string, ImplementerRecord>();
  readonly audit: AuditLogRow[] = [];
  private readonly now: () => Date;

  constructor(now: () => Date = () => new Date()) {
    this.now = now;
  }

  /** Seed a row without audit (tests / fixtures). */
  seed(row: ImplementerRecord): void {
    this.rows.set(row.id, row);
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
}
