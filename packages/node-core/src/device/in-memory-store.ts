// In-memory reference adapter for the device key store seam.
// Single-process; the durable Postgres adapter (durable adapter) provides row-lock atomicity.

import type { EnrolledDeviceKey } from "./types.js";
import type { DeviceKeyStore } from "./store.js";

export class InMemoryDeviceKeyStore implements DeviceKeyStore {
  private readonly keys = new Map<string, EnrolledDeviceKey>();
  private readonly byId = new Map<string, string>();

  private compositeKey(nodeId: string, publicKey: string): string {
    return `${nodeId}:${publicKey}`;
  }

  findByNodeAndPublicKey(nodeId: string, publicKey: string): EnrolledDeviceKey | null {
    return this.keys.get(this.compositeKey(nodeId, publicKey)) ?? null;
  }

  findActiveByNodeAndPublicKey(nodeId: string, publicKey: string): EnrolledDeviceKey | null {
    const key = this.findByNodeAndPublicKey(nodeId, publicKey);
    if (key === null || key.revokedAt !== null) return null;
    return key;
  }

  findById(id: string): EnrolledDeviceKey | null {
    const ck = this.byId.get(id);
    if (ck === undefined) return null;
    return this.keys.get(ck) ?? null;
  }

  listActiveByNode(nodeId: string): EnrolledDeviceKey[] {
    return [...this.keys.values()]
      .filter((key) => key.nodeId === nodeId && key.revokedAt === null)
      .sort((left, right) =>
        left.enrolledAt.localeCompare(right.enrolledAt) || left.id.localeCompare(right.id),
      );
  }

  insert(deviceKey: EnrolledDeviceKey): void {
    const ck = this.compositeKey(deviceKey.nodeId, deviceKey.publicKey);
    if (this.keys.has(ck)) {
      throw new Error(`duplicate device key: (${deviceKey.nodeId}, ${deviceKey.publicKey})`);
    }
    if (this.byId.has(deviceKey.id)) {
      throw new Error(`duplicate device key id: ${deviceKey.id}`);
    }
    this.keys.set(ck, deviceKey);
    this.byId.set(deviceKey.id, ck);
  }

  revoke(id: string, revokedAt: string): void {
    const ck = this.byId.get(id);
    if (ck === undefined) return;
    const key = this.keys.get(ck);
    if (key === undefined) return;
    // Idempotent + non-deleting: never clear a prior revoked_at; never remove the row.
    if (key.revokedAt !== null) return;
    this.keys.set(ck, { ...key, revokedAt });
  }
}
