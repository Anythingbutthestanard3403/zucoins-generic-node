// In-memory IntegrationRequestStore for unit tests (no Postgres).

import { randomUUID } from "node:crypto";

import {
  generateRawKey,
  hashCredential,
  PUBLIC_PREFIX_LENGTH,
  type ImplementerScope,
} from "../credential/types.js";
import { claimTokenHashesEqual } from "./token.js";
import type {
  ClaimOutcome,
  IntegrationRequestIntakeInput,
  IntegrationRequestRow,
  IntegrationRequestStore,
} from "./types.js";

export class InMemoryIntegrationRequestStore implements IntegrationRequestStore {
  private readonly rows = new Map<string, IntegrationRequestRow>();
  /** Test helper: issued credentials by id. */
  readonly issuedCredentials = new Map<
    string,
    { raw_key: string; implementer_id: string; scopes: readonly ImplementerScope[] }
  >();

  async countPending(): Promise<number> {
    let n = 0;
    for (const r of this.rows.values()) {
      if (r.status === "PENDING") n += 1;
    }
    return n;
  }

  async insertPending(input: IntegrationRequestIntakeInput): Promise<IntegrationRequestRow> {
    const now = input.now ?? new Date();
    const ttlMs = input.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    const id = input.requestId ?? randomUUID();
    const row: IntegrationRequestRow = {
      id,
      node_id: input.nodeId,
      display_name: input.displayName,
      requested_scopes: input.requestedScopes as readonly ImplementerScope[],
      proposed_rule_json: input.proposedRuleJson,
      approved_rule_json: null,
      status: "PENDING",
      row_version: 1,
      claim_token_hash: input.claimTokenHash,
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttlMs).toISOString(),
      decided_at: null,
      decided_by: null,
      implementer_id: null,
      issued_credential_id: null,
      claimed_at: null,
    };
    this.rows.set(id, row);
    return row;
  }

  async findById(id: string): Promise<IntegrationRequestRow | null> {
    return this.rows.get(id) ?? null;
  }

  /** Test seed: mark APPROVED with implementer + rule (simulates ZTR-1240). */
  seedApproved(
    id: string,
    opts: {
      implementerId: string;
      approvedRuleJson: string;
      decidedBy?: string;
      rowVersion?: number;
    },
  ): void {
    const cur = this.rows.get(id);
    if (cur === undefined) throw new Error(`seedApproved: missing ${id}`);
    this.rows.set(id, {
      ...cur,
      status: "APPROVED",
      row_version: opts.rowVersion ?? cur.row_version + 1,
      approved_rule_json: opts.approvedRuleJson,
      decided_at: new Date().toISOString(),
      decided_by: opts.decidedBy ?? randomUUID(),
      implementer_id: opts.implementerId,
    });
  }

  async lazyExpire(id: string, now: Date): Promise<IntegrationRequestRow | null> {
    const cur = this.rows.get(id);
    if (cur === undefined) return null;
    if (
      (cur.status === "PENDING" || cur.status === "APPROVED") &&
      Date.parse(cur.expires_at) <= now.getTime() &&
      cur.issued_credential_id === null
    ) {
      const next: IntegrationRequestRow = {
        ...cur,
        status: "EXPIRED",
        row_version: cur.row_version + 1,
      };
      this.rows.set(id, next);
      return next;
    }
    return cur;
  }

  async claimApproved(input: {
    readonly id: string;
    readonly claimTokenHash: string;
    readonly nodeId: string;
    readonly now: Date;
  }): Promise<ClaimOutcome> {
    const existing = this.rows.get(input.id);
    if (existing === undefined) return { kind: "not_found" };
    if (!claimTokenHashesEqual(existing.claim_token_hash, input.claimTokenHash)) {
      return { kind: "not_found" };
    }
    if (existing.status === "CLAIMED") {
      return { kind: "status", status: "CLAIMED" };
    }
    if (existing.status !== "APPROVED" || existing.implementer_id === null) {
      return { kind: "status", status: existing.status };
    }

    // CAS: only one winner when concurrent (re-check map entry).
    const live = this.rows.get(input.id);
    if (live === undefined) return { kind: "not_found" };
    if (live.status !== "APPROVED" || live.row_version !== existing.row_version) {
      return { kind: "status", status: live.status };
    }

    const rawKey = generateRawKey();
    const credentialId = randomUUID();
    const issuedAt = input.now.toISOString();
    const next: IntegrationRequestRow = {
      ...live,
      status: "CLAIMED",
      row_version: live.row_version + 1,
      issued_credential_id: credentialId,
      claimed_at: issuedAt,
    };
    this.rows.set(input.id, next);
    this.issuedCredentials.set(credentialId, {
      raw_key: rawKey,
      implementer_id: existing.implementer_id,
      scopes: existing.requested_scopes,
    });

    let approvedRule: unknown = null;
    try {
      approvedRule = JSON.parse(existing.approved_rule_json ?? "null");
    } catch {
      approvedRule = existing.approved_rule_json;
    }

    return {
      kind: "key",
      status: "CLAIMED",
      api_key: rawKey,
      public_prefix: rawKey.slice(0, PUBLIC_PREFIX_LENGTH),
      scopes: existing.requested_scopes,
      approved_rule: approvedRule,
      implementer_id: existing.implementer_id,
      credential_id: credentialId,
    };
  }

  // Expose hash for tests that need to verify storage.
  hashOf(_raw: string): string {
    return hashCredential(_raw);
  }
}
