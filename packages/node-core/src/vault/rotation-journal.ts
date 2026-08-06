// Master-key rotation journal (wallet-vault model guard 3;
// generic-node-contracts vault/lifecycle.contract.ts ROTATION_STATES).
//
// The journal is the sole durable epoch authority for master-key rotation. Phases match
// the frozen lifecycle contract:
// STABLE → ROTATING → ROTATION_COMPLETE → STABLE
//
// Crash safety (guard 3):
// - old KEK/root is retained until a committed ROTATION_COMPLETE marker exists;
// - ROTATING may observe a mixed population (some rows already under the new root);
// - any unreadable / failed-pubkey row aborts without advancing the writer epoch;
// - old ciphertext GC and old-root wipe happen only after ROTATION_COMPLETE → STABLE.
//
// This module holds NO key material (the key-custody rule). Keys live in the caller's key-ring.
// Boundary: vault is a leaf module — phases are pinned here to match the lifecycle contract
// byte-for-byte; the contracts package freezes the same vocabulary independently.

/** Frozen rotation phases (lifecycle.contract.ts ROTATION_STATES). */
export const MASTER_KEY_ROTATION_PHASES = ["STABLE", "ROTATING", "ROTATION_COMPLETE"] as const;
export type MasterKeyRotationPhase = (typeof MASTER_KEY_ROTATION_PHASES)[number];

/** Durable journal record. Never logs or stores key bytes — only epoch integers + wallet ids. */
export interface MasterKeyRotationJournalRecord {
  readonly phase: MasterKeyRotationPhase;
  /** Writer epoch currently authoritative for NEW seals (stable = active epoch). */
  readonly writerEpoch: number;
  /** Epoch of the OLD root retained during ROTATING / until finalize. Null when STABLE. */
  readonly fromEpoch: number | null;
  /** Epoch of the NEW root being rolled out. Null when STABLE. */
  readonly toEpoch: number | null;
  /**
   * Wallet ids whose vault row has already been re-sealed under `toEpoch` during an
   * in-progress (or interrupted) rotation. Empty when STABLE.
   */
  readonly rewrappedWalletIds: readonly string[];
}

export interface MasterKeyRotationJournal {
  read(): Promise<MasterKeyRotationJournalRecord>;
  /**
   * STABLE → ROTATING. Records from/to epochs and clears the rewrapped set.
   * Resume of an interrupted rotation (same epochs, already ROTATING) is a no-op begin.
   */
  begin(input: { fromEpoch: number; toEpoch: number }): Promise<MasterKeyRotationJournalRecord>;
  /** Record that one wallet row is durable under the new root. Idempotent. */
  markRewrapped(walletId: string): Promise<void>;
  /**
   * ROTATING → ROTATION_COMPLETE. The single atomic commit marker: every registered
   * store has been rewrapped + round-trip verified. Advances `writerEpoch` to `toEpoch`.
   */
  complete(): Promise<MasterKeyRotationJournalRecord>;
  /**
   * ROTATION_COMPLETE → STABLE after old ciphertext GC / old-root decommission.
   * Also used by abort paths that roll a non-committed ROTATING journal back to STABLE
   * without advancing the writer epoch.
   */
  settleStable(): Promise<MasterKeyRotationJournalRecord>;
}

const STABLE_RECORD = (writerEpoch: number): MasterKeyRotationJournalRecord => ({
  phase: "STABLE",
  writerEpoch,
  fromEpoch: null,
  toEpoch: null,
  rewrappedWalletIds: [],
});

/**
 * In-memory journal for unit tests and local dry runs. Production supplies a durable
 * adapter with the same port (single-row table or equivalent).
 */
export class InMemoryMasterKeyRotationJournal implements MasterKeyRotationJournal {
  #record: MasterKeyRotationJournalRecord;

  constructor(initialWriterEpoch = 1) {
    if (!Number.isInteger(initialWriterEpoch) || initialWriterEpoch < 1) {
      throw new Error("InMemoryMasterKeyRotationJournal: writerEpoch must be a positive integer");
    }
    this.#record = STABLE_RECORD(initialWriterEpoch);
  }

  async read(): Promise<MasterKeyRotationJournalRecord> {
    return this.#record;
  }

  async begin(input: {
    fromEpoch: number;
    toEpoch: number;
  }): Promise<MasterKeyRotationJournalRecord> {
    const { fromEpoch, toEpoch } = input;
    if (!Number.isInteger(fromEpoch) || !Number.isInteger(toEpoch)) {
      throw new Error("rotation journal begin: epochs must be integers");
    }
    if (toEpoch !== fromEpoch + 1) {
      throw new Error(
        `rotation journal begin: toEpoch must be fromEpoch+1 (from=${fromEpoch} to=${toEpoch})`,
      );
    }

    const current = this.#record;
    if (current.phase === "ROTATING") {
      if (current.fromEpoch === fromEpoch && current.toEpoch === toEpoch) {
        return current;
      }
      throw new Error(
        `rotation journal begin: already ROTATING epochs ${current.fromEpoch}->${current.toEpoch}`,
      );
    }
    if (current.phase === "ROTATION_COMPLETE") {
      throw new Error(
        "rotation journal begin: journal is ROTATION_COMPLETE — call settleStable before a new rotation",
      );
    }
    if (current.writerEpoch !== fromEpoch) {
      throw new Error(
        `rotation journal begin: fromEpoch ${fromEpoch} does not match writerEpoch ${current.writerEpoch}`,
      );
    }

    this.#record = {
      phase: "ROTATING",
      writerEpoch: current.writerEpoch, // not advanced until complete
      fromEpoch,
      toEpoch,
      rewrappedWalletIds: [],
    };
    return this.#record;
  }

  async markRewrapped(walletId: string): Promise<void> {
    if (this.#record.phase !== "ROTATING") {
      throw new Error(`rotation journal markRewrapped: phase is ${this.#record.phase}`);
    }
    if (this.#record.rewrappedWalletIds.includes(walletId)) return;
    this.#record = {
      ...this.#record,
      rewrappedWalletIds: [...this.#record.rewrappedWalletIds, walletId],
    };
  }

  async complete(): Promise<MasterKeyRotationJournalRecord> {
    const current = this.#record;
    if (current.phase === "ROTATION_COMPLETE") {
      return current;
    }
    if (current.phase !== "ROTATING" || current.toEpoch === null) {
      throw new Error(`rotation journal complete: phase is ${current.phase}`);
    }
    this.#record = {
      phase: "ROTATION_COMPLETE",
      writerEpoch: current.toEpoch,
      fromEpoch: current.fromEpoch,
      toEpoch: current.toEpoch,
      rewrappedWalletIds: current.rewrappedWalletIds,
    };
    return this.#record;
  }

  async settleStable(): Promise<MasterKeyRotationJournalRecord> {
    const current = this.#record;
    if (current.phase === "STABLE") return current;
    // Abort (ROTATING): keep prior writerEpoch. Finalize (ROTATION_COMPLETE): keep advanced.
    this.#record = STABLE_RECORD(current.writerEpoch);
    return this.#record;
  }
}
