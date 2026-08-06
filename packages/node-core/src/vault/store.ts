// Encrypted wallet-key storage service. Seals a wallet's Ed25519 secret into a per-wallet
// envelope row and opens it only through an audited path: every decrypt attempt (success or
// fail-closed) is recorded before any plaintext is released. The service holds the root key in
// process memory only and never persists or logs key material (the key-custody rule: the platform
// never touches private keys — this runs on the self-hosted node).
//

import {
  openWalletSecret,
  sealWalletSecret,
  VaultOpenError,
  type SecureBuffer,
  type SealedEnvelope,
  type WalletIdentity,
} from "./envelope.js";

// The persisted envelope row (table `vault`). Bytea fields are stored as returned by the
// envelope; timestamps are owned by the persistence adapter.
export interface VaultRecord extends SealedEnvelope {
  readonly createdAt: Date;
  readonly rotatedAt: Date | null;
}

// Persistence seam for the `vault` table. A concrete adapter (Postgres) lives outside this
// package; the in-memory implementation below backs tests.
export interface VaultStore {
  insert(record: VaultRecord): Promise<void>;
  findByWalletId(walletId: string): Promise<VaultRecord | null>;
  update(record: VaultRecord): Promise<void>;
}

export type VaultAccessOutcome = "OPEN_OK" | "NOT_FOUND" | VaultOpenError["code"];

// Typed NOT_FOUND signal so callers (e.g. boot key-correspondence) can tell a missing vault
// row (a deterministic custody verdict) apart from an operational store/audit fault.
export class VaultRecordNotFoundError extends Error {
  constructor(walletId: string) {
    super(`no vault row for wallet ${walletId}`);
    this.name = "VaultRecordNotFoundError";
  }
}

// One audit row per decrypt attempt. No key material, AAD, or plaintext is ever recorded.
export interface VaultAccessAuditEntry {
  readonly walletId: string;
  readonly keyVersion: number;
  readonly purpose: string;
  readonly outcome: VaultAccessOutcome;
  readonly at: Date;
}

export interface VaultAccessAuditLog {
  record(entry: VaultAccessAuditEntry): Promise<void>;
}

export interface EncryptedWalletKeyStoreDeps {
  readonly rootKey: Uint8Array;
  readonly store: VaultStore;
  readonly auditLog: VaultAccessAuditLog;
  readonly now?: () => Date;
}

export class EncryptedWalletKeyStore {
  private readonly rootKey: Uint8Array;
  private readonly store: VaultStore;
  private readonly auditLog: VaultAccessAuditLog;
  private readonly now: () => Date;

  constructor(deps: EncryptedWalletKeyStoreDeps) {
    this.rootKey = deps.rootKey;
    this.store = deps.store;
    this.auditLog = deps.auditLog;
    this.now = deps.now ?? (() => new Date());
  }

  // Seal and persist a wallet's secret key. Fails if a row already exists for the wallet —
  // rewrap/rotation is a separate value-preserving operation, not a silent overwrite.
  async seal(identity: WalletIdentity, secretKey: Uint8Array): Promise<VaultRecord> {
    const existing = await this.store.findByWalletId(identity.walletId);
    if (existing !== null) {
      throw new Error(`vault row already exists for wallet ${identity.walletId}`);
    }
    const envelope = sealWalletSecret(this.rootKey, identity, secretKey);
    const record: VaultRecord = { ...envelope, createdAt: this.now(), rotatedAt: null };
    await this.store.insert(record);
    return record;
  }

  // Audited decrypt. Records the outcome before returning; on failure the audit row is written
  // and the error re-thrown with no plaintext released.
  async open(authoritative: WalletIdentity, purpose: string): Promise<SecureBuffer> {
    const record = await this.store.findByWalletId(authoritative.walletId);
    if (record === null) {
      const notFound = new VaultRecordNotFoundError(authoritative.walletId);
      try {
        await this.recordAccess(
          authoritative.walletId,
          authoritative.keyVersion,
          purpose,
          "NOT_FOUND",
        );
      } catch (auditError: unknown) {
        notFound.cause = auditError;
      }
      throw notFound;
    }
    let secret: SecureBuffer;
    try {
      secret = openWalletSecret(this.rootKey, record, authoritative);
    } catch (error) {
      const outcome: VaultAccessOutcome =
        error instanceof VaultOpenError ? error.code : "AUTH_TAG_FAILURE";
      try {
        await this.recordAccess(
          authoritative.walletId,
          record.keyVersion,
          purpose,
          outcome,
        );
      } catch (auditError: unknown) {
        if (error instanceof Error) {
          error.cause = auditError;
        }
      }
      throw error;
    }
    try {
      await this.recordAccess(authoritative.walletId, record.keyVersion, purpose, "OPEN_OK");
      return secret;
    } catch (error) {
      // Ownership transfers to the caller only after the durable OPEN_OK row commits.
      // Any post-decrypt rejection before that boundary must destroy plaintext exactly once.
      secret.wipe();
      throw error;
    }
  }

  // Rewrap an existing envelope under a new root key (master-key rotation). Value-preserving:
  // opens under the old root, reseals under the new root at the same key version, and verifies
  // the round trip before committing. Any failure aborts without writing.
  async rotate(
    authoritative: WalletIdentity,
    newRootKey: Uint8Array,
  ): Promise<VaultRecord> {
    const record = await this.store.findByWalletId(authoritative.walletId);
    if (record === null) {
      throw new Error(`no vault row for wallet ${authoritative.walletId}`);
    }
    const secret = openWalletSecret(this.rootKey, record, authoritative);
    try {
      const resealed = sealWalletSecret(newRootKey, authoritative, secret.bytes);
      const rotated: VaultRecord = {
        ...resealed,
        createdAt: record.createdAt,
        rotatedAt: this.now(),
      };
      // Verify the round trip under the new root before committing.
      const verified = openWalletSecret(newRootKey, rotated, authoritative);
      verified.wipe();
      await this.store.update(rotated);
      return rotated;
    } finally {
      secret.wipe();
    }
  }

  // async so a synchronous adapter throw becomes a rejected promise at this seam —
  // every await / .catch call site (present and future) observes it uniformly.
  private async recordAccess(
    walletId: string,
    keyVersion: number,
    purpose: string,
    outcome: VaultAccessOutcome,
  ): Promise<void> {
    return this.auditLog.record({ walletId, keyVersion, purpose, outcome, at: this.now() });
  }
}

// In-memory VaultStore for tests and local runs.
export class InMemoryVaultStore implements VaultStore {
  private readonly rows = new Map<string, VaultRecord>();

  async insert(record: VaultRecord): Promise<void> {
    if (this.rows.has(record.walletId)) {
      throw new Error(`vault row already exists for wallet ${record.walletId}`);
    }
    this.rows.set(record.walletId, record);
  }

  async findByWalletId(walletId: string): Promise<VaultRecord | null> {
    return this.rows.get(walletId) ?? null;
  }

  async update(record: VaultRecord): Promise<void> {
    if (!this.rows.has(record.walletId)) {
      throw new Error(`no vault row for wallet ${record.walletId}`);
    }
    this.rows.set(record.walletId, record);
  }
}

// In-memory audit log for tests; a durable adapter lives outside this package.
export class InMemoryVaultAccessAuditLog implements VaultAccessAuditLog {
  readonly entries: VaultAccessAuditEntry[] = [];

  async record(entry: VaultAccessAuditEntry): Promise<void> {
    this.entries.push(entry);
  }
}
