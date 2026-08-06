// Break-glass authority store — frozen public keys only (the key-custody rule).
// A break-glass key is only ever an explicitly approved one.
// No private key material is ever stored. Provisioning is host-local (not session/TOTP).

import type { BreakGlassAuthority } from "./types.js";

export interface BreakGlassAuthorityStore {
  findByNodeAndPublicKey(nodeId: string, publicKey: string): BreakGlassAuthority | null;
  findActiveByNodeAndPublicKey(nodeId: string, publicKey: string): BreakGlassAuthority | null;
  findById(id: string): BreakGlassAuthority | null;
  findActiveByNode(nodeId: string): readonly BreakGlassAuthority[];
  insert(authority: BreakGlassAuthority): void;
  revoke(id: string, revokedAt: string): void;
}

export class InMemoryBreakGlassAuthorityStore implements BreakGlassAuthorityStore {
  private readonly byComposite = new Map<string, BreakGlassAuthority>();
  private readonly byId = new Map<string, string>();

  private compositeKey(nodeId: string, publicKey: string): string {
    return `${nodeId}:${publicKey}`;
  }

  findByNodeAndPublicKey(nodeId: string, publicKey: string): BreakGlassAuthority | null {
    return this.byComposite.get(this.compositeKey(nodeId, publicKey)) ?? null;
  }

  findActiveByNodeAndPublicKey(nodeId: string, publicKey: string): BreakGlassAuthority | null {
    const row = this.findByNodeAndPublicKey(nodeId, publicKey);
    if (row === null || row.revokedAt !== null) return null;
    return row;
  }

  findById(id: string): BreakGlassAuthority | null {
    const ck = this.byId.get(id);
    if (ck === undefined) return null;
    return this.byComposite.get(ck) ?? null;
  }

  findActiveByNode(nodeId: string): readonly BreakGlassAuthority[] {
    const out: BreakGlassAuthority[] = [];
    for (const row of this.byComposite.values()) {
      if (row.nodeId === nodeId && row.revokedAt === null) out.push(row);
    }
    return out;
  }

  insert(authority: BreakGlassAuthority): void {
    const ck = this.compositeKey(authority.nodeId, authority.publicKey);
    if (this.byComposite.has(ck)) {
      throw new Error(`duplicate break-glass authority: (${authority.nodeId}, ${authority.publicKey})`);
    }
    if (this.byId.has(authority.id)) {
      throw new Error(`duplicate break-glass authority id: ${authority.id}`);
    }
    this.byComposite.set(ck, authority);
    this.byId.set(authority.id, ck);
  }

  revoke(id: string, revokedAt: string): void {
    const ck = this.byId.get(id);
    if (ck === undefined) return;
    const row = this.byComposite.get(ck);
    if (row === undefined) return;
    // Idempotent: never clear a prior revoked_at; never delete the row.
    if (row.revokedAt !== null) return;
    this.byComposite.set(ck, { ...row, revokedAt });
  }
}
