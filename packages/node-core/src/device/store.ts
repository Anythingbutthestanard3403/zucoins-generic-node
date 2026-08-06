// Device key store seam — enrollment + signature verification read/write through
// this interface. In-memory adapter is the reference; durable Postgres (durable adapter) swaps in.

import type { EnrolledDeviceKey } from "./types.js";

export interface DeviceKeyStore {
  findByNodeAndPublicKey(nodeId: string, publicKey: string): EnrolledDeviceKey | null;
  findActiveByNodeAndPublicKey(nodeId: string, publicKey: string): EnrolledDeviceKey | null;
  findById(id: string): EnrolledDeviceKey | null;
  listActiveByNode(nodeId: string): EnrolledDeviceKey[];
  insert(deviceKey: EnrolledDeviceKey): void;
  revoke(id: string, revokedAt: string): void;
}
