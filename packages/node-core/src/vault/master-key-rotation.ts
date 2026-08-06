// Atomic multi-store master-key rotation coordinator.
//
// wallet-vault model guards 3–4; v1 node frozen clean-room; sealed-store rewrap census register/rewrap split.
//
// Deliverables of this module:
// 1. Iterate every SEALED_STORES entry with rewrapStatus IMPLEMENTED (WALLET_VAULT via
// rewrap under the key-ring; NODE_SIGNING_KEYS via injected rewrap port —).
// DEFERRED_NO_SEAL_RUNTIME stores are skipped with a structured log line — inventing
// a vacuous rewrap is forbidden (sealed-store rewrap census).
// 2. Exclusive rotation under a MasterKeyRotationInterlock (quiesce signing) + required
// RotationUnitOfWork that acquires the ceremony session advisory lock on begin and
// holds it through journal.complete / settleStable (D-B4 / guard 4). Vault rows
// share a nested TX (xact lock) committed before the epoch marker; the session lease
// is the exclusive fence across both durability domains.
// 3. Dry-run: prove every rewrap + round-trip, then roll back (no journal advance,
// no commit). Commit path: vault rows → unit.commit (TX) → marks → journal.complete
// → settleStable → unit.end (session lease). Writer epoch never leads durable rows.
// 4. Crash-safe resume (guard 3):
// - ROTATING + mixed census → key-ring open; marks soft only (never "marked ⇒ new");
// - ROTATION_COMPLETE @ toEpoch → idempotent settleStable finalize (D-B5);
// - complete-throw after vault durable → resume via key-ring + complete.
//
// Logging discipline: store / phase / counts / timing only — never a key,
// nonce, ciphertext, or secret byte.
//
// Boundary: vault is a leaf. The sealed-store id list is passed in by the composition
// root (which may import schema); this module never imports schema or a database driver.

import { sortWalletIdsAscending } from "./sort-wallets.js";
import {
  keyMaterialHygiene,
  openWalletSecret,
  sealWalletSecret,
} from "./envelope.js";
import {
  type SealedStoreRewrapResult,
  type WalletVaultRewrapRow,
} from "./rewrap.js";
import type {
  MasterKeyRotationJournal,
  MasterKeyRotationJournalRecord,
} from "./rotation-journal.js";
import {
  openWithKeyRing,
  writerRoot,
  type VaultKeyRing,
} from "./key-ring.js";

// ─── Ports ───────────────────────────────────────────────────────────────────

/**
 * Exclusive node signing interlock (guard 4). Rotation is the sole
 * all-envelope writer and quiesces signing for the whole ceremony. acquire must
 * refuse concurrent MOVE_INTERNAL / signUnderLease admission; release always runs.
 *
 * Named distinctly from core/recovery's `NodeSigningInterlock` so the package barrel
 * star-exports do not collide (same structural shape; either satisfies the other).
 *
 * Concrete {@link ProcessLocalMasterKeyRotationInterlock} exposes `assertSigningAdmitted`
 * for composition roots to wire into `signUnderLease` / MOVE_INTERNAL admission.
 */
export interface MasterKeyRotationInterlock {
  acquire(): Promise<void>;
  release(): Promise<void>;
}

/**
 * Exclusive ceremony unit of work (guards 3–4 / D-B4).
 *
 * Contract:
 * - begin MUST acquire the ceremony session advisory lock
 * (`ACQUIRE_ROTATION_SESSION_LOCK_SQL` / `MASTER_KEY_ROTATION_ADVISORY_LOCK_ID`) and
 * open the vault TX (acquiring the nested xact lock). The session lock is the
 * exclusive fence held for the whole ceremony — including journal.complete/settle.
 * - commit persists the vault TX and releases the nested xact lock ONLY. The session
 * lease MUST remain held so a concurrent begin still refuses through journal
 * epoch advance (D-B4).
 * - end releases the session lease (and connection). Call only after journal
 * complete+settle on the happy path, or after an abort that already committed vault.
 * - rollback aborts an open vault TX and releases the session lease.
 *
 * Required on every rotateMasterKey call (commit and dry-run). Dry-run always ends in
 * rollback after proving rewrap.
 */
export interface RotationUnitOfWork {
  begin(): Promise<void>;
  commit(): Promise<void>;
  /** Release the ceremony-wide session lease. No-op if already released. */
  end(): Promise<void>;
  rollback(): Promise<void>;
}

/** Structured logger — only non-secret fields. */
export interface RotationLogger {
  info(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}

const silentLogger: RotationLogger = {
  info() {},
  error() {},
};

/** One sealed store the coordinator may rewrap. Mirrors SEALED_STORES shape without importing schema. */
export type RegisteredStoreRewrapStatus = "IMPLEMENTED" | "DEFERRED_NO_SEAL_RUNTIME";

export interface RegisteredSealedStore {
  readonly id: string;
  readonly rewrapStatus: RegisteredStoreRewrapStatus;
}

export interface WalletVaultRotationCensus {
  /**
   * Full wallet-vault row set (N≥0). Orchestrator sorts by wallet id.
   *
   * This is a SNAPSHOT the caller reads before the ceremony fence exists, so it is not
   * self-authoritative: parity is proven against `countWalletVaultRows` inside the fence,
   * never against this array's own length (which would be a tautology).
   */
  readonly rows: readonly WalletVaultRewrapRow[];
}

/**
 * Structural NODE_SIGNING_KEYS census row. Crypto lives in signing-keys/rewrap.ts (vault
 * is a leaf — rewrap is injected via `rewrapNodeSigningKeyStore` so this module never
 * imports the signing-keys package).
 */
export interface NodeSigningKeyRotationRow {
  readonly identity: {
    readonly nodeId: string;
    readonly purpose: string;
    readonly publicKey: string;
    readonly keyVersion: number;
  };
  readonly envelope: {
    readonly vaultSecretRef: string;
    readonly keyVersion: number;
    readonly ciphertext: Uint8Array;
    readonly nonce: Uint8Array;
    readonly authTag: Uint8Array;
    readonly ciphertextSha256: string;
  };
}

export interface NodeSigningKeyRotationCensus {
  readonly rows: readonly NodeSigningKeyRotationRow[];
}

/** Structural PUSH_RECEIVER_SECRETS row; crypto is injected from push/rewrap. */
export interface PushSecretRotationRow {
  readonly identity: {
    readonly nodeId: string;
    readonly walletId: string;
    readonly materialKind: "ECDH_PRIVATE_KEY" | "AUTH_SECRET";
    /** Database tracking only; canonical push AAD does not include this value. */
    readonly keyVersion: number;
  };
  /** Opaque canonical `zp-push-seal-v1` envelope text. */
  readonly envelope: string;
}

export interface PushSecretRotationCensus {
  readonly rows: readonly PushSecretRotationRow[];
}

export interface MasterKeyRotationInput {
  /** Registry snapshot (typically `SEALED_STORES` from the schema contract). */
  readonly sealedStores: readonly RegisteredSealedStore[];
  readonly walletVault: WalletVaultRotationCensus;
  /**
   * NODE_SIGNING_KEYS census. Required when store rewrapStatus is IMPLEMENTED —
   * omit only when the store is DEFERRED; empty `{ rows: [] }` is the greenfield shape.
   * When rows are non-empty, `rewrapNodeSigningKeyStore` and `commitNodeSigningKeys` are required.
   */
  readonly nodeSigningKeys?: NodeSigningKeyRotationCensus;
  /** PUSH_RECEIVER_SECRETS census; required when that registered store is IMPLEMENTED. */
  readonly pushReceiverSecrets?: PushSecretRotationCensus;
  /**
   * Key-ring carrying BOTH the old root (retained) and the new root (writer during
   * rotation). writerEpoch must equal journal.toEpoch once begin succeeds; for a
   * fresh rotation the caller sets writerEpoch to the NEW epoch and retains the old.
   */
  readonly keyRing: VaultKeyRing;
  /** Epoch of the OLD root (journal.fromEpoch). */
  readonly fromEpoch: number;
  /** Epoch of the NEW root (journal.toEpoch = fromEpoch + 1). */
  readonly toEpoch: number;
  /** Root derived from the OLD master key. */
  readonly oldRootKey: Uint8Array;
  /** Root derived from the NEW master key. */
  readonly newRootKey: Uint8Array;
  readonly journal: MasterKeyRotationJournal;
  readonly interlock: MasterKeyRotationInterlock;
  /**
   * Persist every rewrapped wallet-vault row. Called once after all stores rewrap +
   * verify, and only on a non-dry-run path. Must NOT touch wallets.* recovery columns.
   * When a SQL unit of work is open, this write MUST land on the same connection so
   * vault rows and the subsequent unit commit share one atomic boundary.
   */
  readonly commitWalletVault: (rows: readonly WalletVaultRewrapRow[]) => Promise<void>;
  /**
   * Persist every rewrapped NODE_SIGNING_KEYS sealed row. Optional when the census is
   * empty; required (fail-closed) when rows are present.
   */
  readonly commitNodeSigningKeys?: (
    rows: readonly NodeSigningKeyRotationRow[],
  ) => Promise<void>;
  /** Persist every rewrapped push secret row in the same rotation transaction. */
  readonly commitPushSecrets?: (rows: readonly PushSecretRotationRow[]) => Promise<void>;
  /**
   * Injected NODE_SIGNING_KEYS rewrap (composition wires signing-keys/rewrap). Required
   * when census is non-empty.
   */
  readonly rewrapNodeSigningKeyStore?: (input: {
    readonly oldRootKey: Uint8Array;
    readonly newRootKey: Uint8Array;
    readonly rows: readonly NodeSigningKeyRotationRow[];
  }) => {
    readonly result: SealedStoreRewrapResult;
    readonly rewrappedRows: readonly NodeSigningKeyRotationRow[];
  };
  /** Injected key-ring-aware PUSH_RECEIVER_SECRETS rewrap primitive. */
  readonly rewrapPushSecretStore?: (input: {
    readonly keyRing: VaultKeyRing;
    readonly newRootKey: Uint8Array;
    readonly fromEpoch: number;
    readonly toEpoch: number;
    readonly rows: readonly PushSecretRotationRow[];
  }) => Promise<{
    readonly result: SealedStoreRewrapResult;
    readonly rewrappedRows: readonly PushSecretRotationRow[];
  }>;
  /**
   * Authoritative live `vault` row count, re-read INSIDE the ceremony fence (D-A2).
   *
   * `walletVault` is a snapshot the caller takes before `interlock.acquire` /
   * `unitOfWork.begin`, so a row inserted in that window is absent from the census. Such
   * a row is never rewrapped, stays sealed under the retired old root, and becomes
   * permanently unopenable at OPERATOR_SEQUENCE step 5 ("retire the OLD key LAST") — the
   * exit criterion "rotation cannot orphan a wallet" verbatim, and "any
   * unreadable row aborts the whole rotation" (a row never read cannot abort).
   *
   * MUST issue on the same connection/TX the unit of work opened, so the count observes
   * the ceremony's own snapshot. Rotation aborts with zero mutation when it disagrees with
   * the rewrapped row count. Required — absent port → ROTATION_REFUSED (fail-closed).
   */
  readonly countWalletVaultRows: () => Promise<number>;
  /**
   * Authoritative live node_signing_key_sealed_store row count inside the fence.
   * Required when NODE_SIGNING_KEYS is IMPLEMENTED (same shape as countWalletVaultRows) —
   * never default to census length (that vacuous path canned post-destroy unrecoverable rows).
   */
  readonly countNodeSigningKeyRows?: () => Promise<number>;
  /** Authoritative push secret row count inside the ceremony fence. */
  readonly countPushSecretRows?: () => Promise<number>;
  /**
   * Required exclusive unit of work. begin takes the ceremony session advisory lock
   * (+ nested vault TX); commit ends the vault TX only; end releases the session
   * lease after journal complete/settle. Absent unit → ROTATION_REFUSED (fail-closed).
   */
  readonly unitOfWork: RotationUnitOfWork;
  /** Prove then roll back — journal stays at pre-rotation state; nothing committed. */
  readonly dryRun?: boolean;
  readonly logger?: RotationLogger;
}

export interface StoreRotationReport {
  readonly storeId: string;
  readonly status: RegisteredStoreRewrapStatus | "REWRAPPED";
  readonly result: SealedStoreRewrapResult | null;
}

export interface MasterKeyRotationResult {
  readonly committed: boolean;
  readonly dryRun: boolean;
  readonly fromEpoch: number;
  readonly toEpoch: number;
  readonly stores: readonly StoreRotationReport[];
  readonly walletCount: number;
  readonly durationMs: number;
  /** Journal snapshot after the ceremony (STABLE on dry-run / abort settle; COMPLETE then settled on commit). */
  readonly journal: MasterKeyRotationJournalRecord;
}

export class MasterKeyRotationError extends Error {
  readonly code:
    | "ROTATION_REFUSED"
    | "ROTATION_ABORTED"
    | "ROTATION_STATE"
    | "REGISTRY_INCOMPLETE"
    | "SIGNING_QUIESCED";
  constructor(
    code: MasterKeyRotationError["code"],
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "MasterKeyRotationError";
    this.code = code;
  }
}

/** Sentinel: dry-run proved success; force rollback of the unit of work. */
class DryRunRollback extends Error {
  constructor(readonly outcome: Omit<MasterKeyRotationResult, "journal"> & {
    journalSnapshot: MasterKeyRotationJournalRecord;
  }) {
    super("master-key-rotation: dry-run rollback");
    this.name = "DryRunRollback";
  }
}

// ─── Concrete interlock (guard 4) ──────────────────────────────────────

/**
 * Process-local exclusive rotation interlock. Composition roots wire
 * {@link assertSigningAdmitted} into `signUnderLease` / MOVE_INTERNAL admission so
 * signing is refused for the entire hold duration. Concurrent acquire fails closed.
 */
export class ProcessLocalMasterKeyRotationInterlock implements MasterKeyRotationInterlock {
  #held = false;
  #acquireCount = 0;
  #releaseCount = 0;

  get held(): boolean {
    return this.#held;
  }

  get acquireCount(): number {
    return this.#acquireCount;
  }

  get releaseCount(): number {
    return this.#releaseCount;
  }

  async acquire(): Promise<void> {
    if (this.#held) {
      throw new MasterKeyRotationError(
        "ROTATION_REFUSED",
        "master-key rotation interlock already held — concurrent rotation refused",
      );
    }
    this.#held = true;
    this.#acquireCount += 1;
  }

  async release(): Promise<void> {
    if (this.#held) {
      this.#held = false;
      this.#releaseCount += 1;
    }
  }

  /**
   * Gate for MOVE_INTERNAL / signUnderLease. Throws SIGNING_QUIESCED while rotation holds
   * the interlock. Safe to call from any admission path; no side effects.
   */
  assertSigningAdmitted(purpose = "signUnderLease"): void {
    if (this.#held) {
      throw new MasterKeyRotationError(
        "SIGNING_QUIESCED",
        `signing refused while master-key rotation holds the exclusive interlock (${purpose})`,
      );
    }
  }
}

// ─── Concrete unit of work ───────────────────────────────────────────────────

/**
 * In-memory unit of work that serialises concurrent rotation ceremonies on the
 * advisory lock id. Production supplies {@link createSqlRotationUnitOfWork}.
 *
 * Models the session-lease span (D-B4): commit ends the vault TX but keeps the
 * process-global holder until end/rollback so a concurrent begin refuses
 * through journal.complete / settleStable.
 */
export class InMemoryRotationUnitOfWork implements RotationUnitOfWork {
  static #globalHolder: InMemoryRotationUnitOfWork | null = null;

  #begun = false;
  /** Ceremony session lease (survives vault commit until end/rollback). */
  #sessionHeld = false;
  /** Nested vault TX open (cleared on commit/rollback). */
  #txOpen = false;
  #terminal: "open" | "committed" | "rolled_back" | "ended" = "open";
  begins = 0;
  commits = 0;
  ends = 0;
  rollbacks = 0;
  /** True after begin successfully claims the ceremony lock id (until end/rollback). */
  lockAcquired = false;
  readonly lockId = MASTER_KEY_ROTATION_ADVISORY_LOCK_ID;

  /** Test/observability: session lease currently held. */
  get sessionHeld(): boolean {
    return this.#sessionHeld;
  }

  async begin(): Promise<void> {
    if (this.#sessionHeld) {
      throw new MasterKeyRotationError(
        "ROTATION_REFUSED",
        "rotation unit of work already begun",
      );
    }
    if (
      InMemoryRotationUnitOfWork.#globalHolder !== null &&
      InMemoryRotationUnitOfWork.#globalHolder !== this
    ) {
      throw new MasterKeyRotationError(
        "ROTATION_REFUSED",
        `rotation advisory lock ${MASTER_KEY_ROTATION_ADVISORY_LOCK_ID} held by another unit of work`,
      );
    }
    this.#begun = true;
    this.#terminal = "open";
    this.#sessionHeld = true;
    this.#txOpen = true;
    this.lockAcquired = true;
    this.begins += 1;
    InMemoryRotationUnitOfWork.#globalHolder = this;
  }

  async commit(): Promise<void> {
    this.#assertSession("commit");
    if (!this.#txOpen || this.#terminal !== "open") {
      throw new MasterKeyRotationError(
        "ROTATION_STATE",
        `rotation unit of work cannot commit (begun=${this.#begun} terminal=${this.#terminal} txOpen=${this.#txOpen})`,
      );
    }
    // Vault TX committed — session lease STAYS held (D-B4).
    this.#txOpen = false;
    this.#terminal = "committed";
    this.commits += 1;
  }

  async end(): Promise<void> {
    if (!this.#sessionHeld) return;
    if (this.#txOpen) {
      throw new MasterKeyRotationError(
        "ROTATION_STATE",
        "rotation unit of work end() while vault TX still open — commit or rollback first",
      );
    }
    this.#releaseSession();
    this.#terminal = "ended";
    this.ends += 1;
  }

  async rollback(): Promise<void> {
    if (!this.#sessionHeld) return;
    this.#txOpen = false;
    this.#terminal = "rolled_back";
    this.#releaseSession();
    this.rollbacks += 1;
  }

  /** Test helper — release the process-global lock holder without going through rollback. */
  static resetGlobalHolder(): void {
    InMemoryRotationUnitOfWork.#globalHolder = null;
  }

  #assertSession(op: string): void {
    if (!this.#begun || !this.#sessionHeld || !this.lockAcquired) {
      throw new MasterKeyRotationError(
        "ROTATION_STATE",
        `rotation unit of work ${op} without ceremony session lock held`,
      );
    }
  }

  #releaseSession(): void {
    this.#sessionHeld = false;
    this.lockAcquired = false;
    if (InMemoryRotationUnitOfWork.#globalHolder === this) {
      InMemoryRotationUnitOfWork.#globalHolder = null;
    }
  }
}

/**
 * Narrow SQL surface for the rotation unit of work. `pg.PoolClient` satisfies it
 * structurally; vault never imports `pg` (leaf boundary).
 */
export interface RotationSqlClient {
  query(sql: string, params?: readonly unknown[]): Promise<unknown>;
}

export interface RotationSqlTransactionFactory {
  /**
   * Open a dedicated connection and begin a vault TX. The connection MUST remain
   * checked out until the UoW calls rollback after end (post-commit connection
   * return) or rollback on abort — session advisory locks live on the connection.
   * handle.commit ends only the SQL transaction (xact lock drops); session locks
   * acquired on client survive until unlock or disconnect.
   */
  begin(): Promise<{
    readonly client: RotationSqlClient;
    commit(): Promise<void>;
    rollback(): Promise<void>;
  }>;
}

/**
 * Production unit of work (D-B4):
 * - begin: open connection/TX, take session advisory lock (ceremony fence), then
 * nested xact lock for the vault write window;
 * - commit: commit vault TX (xact lock drops) but KEEP the connection + session lock
 * until end so journal.complete/settle run under the exclusive fence;
 * - end: unlock session + release connection (via factory rollback/commit no-op path
 * when TX already closed — see `release` on the factory handle);
 * - rollback: abort open TX if any, unlock session, release connection.
 *
 * Factory.begin must return a dedicated connection that stays checked out for the
 * full ceremony. `commit` on the handle ends only the SQL transaction; the caller
 * (this UoW) retains the handle until end/rollback.
 */
export function createSqlRotationUnitOfWork(
  factory: RotationSqlTransactionFactory,
): RotationUnitOfWork & { readonly lockId: number } {
  let active: {
    readonly client: RotationSqlClient;
    commit(): Promise<void>;
    rollback(): Promise<void>;
  } | null = null;
  let sessionHeld = false;
  let txOpen = false;

  async function releaseSessionAndConnection(): Promise<void> {
    const handle = active;
    active = null;
    const held = sessionHeld;
    sessionHeld = false;
    txOpen = false;
    if (handle === null) return;
    try {
      if (held) {
        await handle.client.query(RELEASE_ROTATION_SESSION_LOCK_SQL, [
          MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
        ]);
      }
    } finally {
      // Connection return: vault TX already closed on end; factory.rollback
      // releases the checked-out client (no-op on an already-committed TX).
      try {
        await handle.rollback();
      } catch {
        // best-effort connection return
      }
    }
  }

  return {
    lockId: MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
    async begin(): Promise<void> {
      if (active !== null || sessionHeld) {
        throw new MasterKeyRotationError(
          "ROTATION_REFUSED",
          "SQL rotation unit of work already begun",
        );
      }
      const tx = await factory.begin();
      active = tx;
      try {
        // Session lease first — survives vault TX commit (D-B4 exclusive span).
        await tx.client.query(ACQUIRE_ROTATION_SESSION_LOCK_SQL, [
          MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
        ]);
        sessionHeld = true;
        await tx.client.query(ACQUIRE_ROTATION_XACT_LOCK_SQL, [
          MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
        ]);
        txOpen = true;
      } catch (err) {
        // Partial begin must not leak session lock or checked-out connection
        // (D-B7). Orchestrator only sets uowStarted after begin resolves, so
        // cleanup cannot wait for rollback/end — release here.
        try {
          await releaseSessionAndConnection();
        } catch {
          // best-effort; preserve the original begin failure
        }
        throw err;
      }
    },
    async commit(): Promise<void> {
      if (active === null || !sessionHeld || !txOpen) {
        throw new MasterKeyRotationError(
          "ROTATION_STATE",
          "SQL rotation unit of work commit without begun+locked TX",
        );
      }
      // Keep `active` + sessionHeld until commit resolves. If commit throws
      // (driver/network), rollback must still release TX + session lock (D-B2).
      await active.commit();
      txOpen = false;
      // sessionHeld stays true — journal.complete/settle still fenced (D-B4).
    },
    async end(): Promise<void> {
      if (active === null && !sessionHeld) return;
      if (txOpen) {
        throw new MasterKeyRotationError(
          "ROTATION_STATE",
          "SQL rotation unit of work end() while vault TX still open — commit or rollback first",
        );
      }
      await releaseSessionAndConnection();
    },
    async rollback(): Promise<void> {
      if (active === null && !sessionHeld) return;
      const handle = active;
      active = null;
      const hadSession = sessionHeld;
      const hadTx = txOpen;
      sessionHeld = false;
      txOpen = false;
      if (handle === null) return;
      try {
        if (hadSession) {
          try {
            await handle.client.query(RELEASE_ROTATION_SESSION_LOCK_SQL, [
              MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
            ]);
          } catch {
            // unlock best-effort
          }
        }
      } finally {
        if (hadTx) {
          await handle.rollback();
        } else {
          // TX already committed — still return the connection.
          try {
            await handle.rollback();
          } catch {
            // ignore
          }
        }
      }
    },
  };
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

/**
 * Run atomic master-key rotation across every IMPLEMENTED sealed store.
 *
 * Algorithm:
 * 0. ROTATION_COMPLETE @ toEpoch → verify census under new root → settleStable (D-B5);
 * 1. acquire signing interlock (quiesce MOVE_INTERNAL / signUnderLease);
 * 2. begin unit of work (ceremony session advisory lock — held through step 6);
 * 3. journal.begin(from,to) — or resume if already ROTATING;
 * 4. for each IMPLEMENTED store, rewrap + count-parity (wallet vault via key-ring);
 * 5. dry-run → throw DryRunRollback (unit rolls back; journal restore);
 * commit → commitWalletVault → unitOfWork.commit (vault TX only; session stays)
 * → markRewrapped → journal.complete → settleStable → unitOfWork.end;
 * 6. release interlock.
 *
 * Crash safety (guard 3 / D-B4 / D-B5):
 * - writerEpoch advances only AFTER vault TX commits durable rows;
 * - ceremony session lock spans vault commit AND journal complete/settle;
 * - crash between vault commit and complete → ROTATING resume via key-ring;
 * - crash between complete and settle → ROTATION_COMPLETE resume settles;
 * - crash before vault commit → TX rollback + journal restore; no epoch advance.
 */
export async function rotateMasterKey(
  input: MasterKeyRotationInput,
): Promise<MasterKeyRotationResult> {
  const logger = input.logger ?? silentLogger;
  const dryRun = input.dryRun === true;
  const startedAt = Date.now();

  validateEpochs(input);
  assertKeyRingMatches(input);

  if (input.unitOfWork === undefined || input.unitOfWork === null) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "unitOfWork is required — exclusive advisory-locked TX is mandatory for master-key rotation",
    );
  }

  if (typeof input.countWalletVaultRows !== "function") {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "countWalletVaultRows is required — census/store parity must be proven inside the ceremony fence",
    );
  }

  // Registry completeness: at least one IMPLEMENTED store must exist (wallet vault).
  const implemented = input.sealedStores.filter((s) => s.rewrapStatus === "IMPLEMENTED");
  if (implemented.length === 0) {
    throw new MasterKeyRotationError(
      "REGISTRY_INCOMPLETE",
      "sealed-store registry has no IMPLEMENTED store to rewrap",
    );
  }
  if (!implemented.some((s) => s.id === "WALLET_VAULT")) {
    throw new MasterKeyRotationError(
      "REGISTRY_INCOMPLETE",
      "WALLET_VAULT must be IMPLEMENTED in the sealed-store registry",
    );
  }

  // D-B5: stranded ROTATION_COMPLETE (complete succeeded, settle threw / crash).
  // Finalize under the exclusive fence without re-entering begin/rewrap.
  const journalProbe = await input.journal.read();
  if (journalProbe.phase === "ROTATION_COMPLETE") {
    return finalizeCompletedRotation(input, journalProbe, logger, startedAt);
  }

  await input.interlock.acquire();
  let uowStarted = false;
  let journalBegan = false;
  // Snapshot taken before begin so dry-run / abort can restore the pre-rotation journal
  // for in-memory journals that don't have transactional rollback of journal writes.
  const journalBefore = await input.journal.read();
  // Tracks whether durable vault rows were committed via the unit. Journal.complete runs
  // only after this is true so writerEpoch never leads durable ciphertext.
  let vaultDurable = false;
  // Session lease still held after vault commit (until end). Distinct from uowStarted
  // so abort after vaultDurable releases via end rather than rolling back committed rows.
  let sessionHeld = false;

  try {
    await input.unitOfWork.begin();
    uowStarted = true;
    sessionHeld = true;

    const journalAfterBegin = await input.journal.begin({
      fromEpoch: input.fromEpoch,
      toEpoch: input.toEpoch,
    });
    journalBegan = true;
    logger.info(
      {
        event: "rotate.phase",
        phase: journalAfterBegin.phase,
        fromEpoch: input.fromEpoch,
        toEpoch: input.toEpoch,
        resumed: journalBefore.phase === "ROTATING",
        advisoryLockId: MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
      },
      "master-key rotation: journal ROTATING",
    );

    // D-A2: authoritative row count, taken on the ceremony connection INSIDE the fence.
    // The census itself was snapshotted before acquire/begin; this is the only value
    // that can prove it still covers the store, so it is what parity compares against.
    const storeRowCount = await input.countWalletVaultRows();

    const stores: StoreRotationReport[] = [];
    let walletRewrapped: readonly WalletVaultRewrapRow[] = [];
    let nodeSigningRewrapped: readonly NodeSigningKeyRotationRow[] = [];
    let pushSecretsRewrapped: readonly PushSecretRotationRow[] = [];

    for (const store of input.sealedStores) {
      if (store.rewrapStatus === "DEFERRED_NO_SEAL_RUNTIME") {
        stores.push({ storeId: store.id, status: "DEFERRED_NO_SEAL_RUNTIME", result: null });
        logger.info(
          { event: "rotate.store_deferred", store: store.id },
          "master-key rotation: store deferred (no seal-write runtime)",
        );
        continue;
      }

      if (store.id === "WALLET_VAULT") {
        const report = rewrapWalletVaultForRotation(input, journalAfterBegin, storeRowCount);
        stores.push({ storeId: store.id, status: "REWRAPPED", result: report.result });
        walletRewrapped = report.rewrappedRows;
        // Do NOT markRewrapped here. Journal marks are independent durability from the
        // vault/UoW TX; a mark before durable vault write poisons crash-resume
        // (false "already under new root" → ROTATION_STATE). Marks land only after
        // commitWalletVault succeeds (same window as durable ciphertext).
        logger.info(
          {
            event: "rotate.store_done",
            store: store.id,
            rows: report.result.rowsAfter,
            rewrapped: report.result.rewrapped,
            skippedAlreadyNew: report.skippedAlreadyNew,
          },
          "master-key rotation: WALLET_VAULT re-wrapped",
        );
        continue;
      }

      if (store.id === "NODE_SIGNING_KEYS") {
        // IMPLEMENTED store: count port is mandatory (no census-length default
        // forbids vacuous rewrap that reports REWRAPPED while live rows stay under old root).
        if (input.countNodeSigningKeyRows === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_REFUSED",
            "NODE_SIGNING_KEYS is IMPLEMENTED but countNodeSigningKeyRows port is missing",
          );
        }
        if (input.nodeSigningKeys === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_REFUSED",
            "NODE_SIGNING_KEYS is IMPLEMENTED but nodeSigningKeys census is missing (pass { rows: [] } when empty)",
          );
        }
        const censusRows = input.nodeSigningKeys.rows;
        const signingCount = await input.countNodeSigningKeyRows();
        if (censusRows.length !== signingCount) {
          throw new MasterKeyRotationError(
            "ROTATION_ABORTED",
            `NODE_SIGNING_KEYS census/count parity failed (census=${censusRows.length} count=${signingCount})`,
          );
        }
        let result: SealedStoreRewrapResult;
        if (signingCount === 0) {
          result = { rowsBefore: 0, rowsAfter: 0, rewrapped: 0 };
          nodeSigningRewrapped = [];
        } else {
          if (input.rewrapNodeSigningKeyStore === undefined) {
            throw new MasterKeyRotationError(
              "ROTATION_REFUSED",
              "NODE_SIGNING_KEYS rows present but rewrapNodeSigningKeyStore port is missing",
            );
          }
          if (input.commitNodeSigningKeys === undefined) {
            throw new MasterKeyRotationError(
              "ROTATION_REFUSED",
              "NODE_SIGNING_KEYS rows present but commitNodeSigningKeys port is missing",
            );
          }
          const report = input.rewrapNodeSigningKeyStore({
            oldRootKey: input.oldRootKey,
            newRootKey: input.newRootKey,
            rows: censusRows,
          });
          if (
            report.result.rowsBefore !== report.result.rowsAfter ||
            report.result.rewrapped !== report.result.rowsBefore
          ) {
            throw new MasterKeyRotationError(
              "ROTATION_ABORTED",
              `NODE_SIGNING_KEYS rewrap count parity failed (before=${report.result.rowsBefore} after=${report.result.rowsAfter} rewrapped=${report.result.rewrapped})`,
            );
          }
          result = report.result;
          nodeSigningRewrapped = report.rewrappedRows;
        }
        stores.push({ storeId: store.id, status: "REWRAPPED", result });
        logger.info(
          {
            event: "rotate.store_done",
            store: store.id,
            rows: result.rowsAfter,
            rewrapped: result.rewrapped,
          },
          "master-key rotation: NODE_SIGNING_KEYS re-wrapped",
        );
        continue;
      }

      if (store.id === "PUSH_RECEIVER_SECRETS") {
        if (input.pushReceiverSecrets === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_REFUSED",
            "PUSH_RECEIVER_SECRETS is IMPLEMENTED but pushReceiverSecrets census is missing",
          );
        }
        if (input.countPushSecretRows === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_REFUSED",
            "PUSH_RECEIVER_SECRETS is IMPLEMENTED but countPushSecretRows port is missing",
          );
        }
        const censusRows = input.pushReceiverSecrets.rows;
        const storeCount = await input.countPushSecretRows();
        if (storeCount !== censusRows.length) {
          throw new MasterKeyRotationError(
            "ROTATION_ABORTED",
            `PUSH_RECEIVER_SECRETS census/count parity failed (census=${censusRows.length} count=${storeCount})`,
          );
        }
        let result: SealedStoreRewrapResult;
        if (storeCount === 0) {
          result = { rowsBefore: 0, rowsAfter: 0, rewrapped: 0 };
        } else {
          if (input.rewrapPushSecretStore === undefined || input.commitPushSecrets === undefined) {
            throw new MasterKeyRotationError(
              "ROTATION_REFUSED",
              "PUSH_RECEIVER_SECRETS rows present but rewrap/commit ports are missing",
            );
          }
          const report = await input.rewrapPushSecretStore({
            keyRing: input.keyRing,
            newRootKey: input.newRootKey,
            fromEpoch: input.fromEpoch,
            toEpoch: input.toEpoch,
            rows: censusRows,
          });
          if (
            report.result.rowsBefore !== storeCount ||
            report.result.rowsAfter !== storeCount ||
            report.result.rewrapped !== storeCount
          ) {
            throw new MasterKeyRotationError(
              "ROTATION_ABORTED",
              `PUSH_RECEIVER_SECRETS rewrap count parity failed (store=${storeCount} before=${report.result.rowsBefore} after=${report.result.rowsAfter} rewrapped=${report.result.rewrapped})`,
            );
          }
          result = report.result;
          pushSecretsRewrapped = report.rewrappedRows;
        }
        stores.push({ storeId: store.id, status: "REWRAPPED", result });
        logger.info(
          { event: "rotate.store_done", store: store.id, rows: result.rowsAfter, rewrapped: result.rewrapped },
          "master-key rotation: PUSH_RECEIVER_SECRETS re-wrapped",
        );
        continue;
      }

      // IMPLEMENTED but no rewrap branch here — fail closed rather than silently skip.
      throw new MasterKeyRotationError(
        "REGISTRY_INCOMPLETE",
        `store ${store.id} is IMPLEMENTED but has no rewrap branch`,
      );
    }

    const durationMs = Date.now() - startedAt;
    const baseOutcome = {
      committed: false as boolean,
      dryRun,
      fromEpoch: input.fromEpoch,
      toEpoch: input.toEpoch,
      stores,
      walletCount: walletRewrapped.length,
      durationMs,
    };

    if (dryRun) {
      // Prove-only: force unit rollback; restore journal to pre-rotation snapshot.
      throw new DryRunRollback({
        ...baseOutcome,
        journalSnapshot: journalBefore,
      });
    }

    // Commit path (guard 3 / D2 / D-B1 / D-B4):
    // 1. persist vault rows (same TX as unit when SQL-wired);
    // 2. unitOfWork.commit — durable vault TX; ceremony session lock STAYS held;
    // 3. journal.markRewrapped only AFTER unit commit (marks must not precede durable ciphertext);
    // 4. journal.complete advances writerEpoch WHILE session lock held;
    // 5. settleStable WHILE session lock held;
    // 6. unitOfWork.end releases the ceremony session lock.
    // If step 2 throws, journal is restored and writerEpoch stays at fromEpoch.
    // If step 4 throws after step 2, rows are under the new root; resume via key-ring.
    // If step 5 throws after step 4, journal is ROTATION_COMPLETE; resume finalizes (D-B5).
    await input.commitWalletVault(walletRewrapped);
    if (nodeSigningRewrapped.length > 0) {
      if (input.commitNodeSigningKeys === undefined) {
        throw new MasterKeyRotationError(
          "ROTATION_REFUSED",
          "NODE_SIGNING_KEYS rewrapped but commitNodeSigningKeys port is missing",
        );
      }
      await input.commitNodeSigningKeys(nodeSigningRewrapped);
    }
    if (pushSecretsRewrapped.length > 0) {
      if (input.commitPushSecrets === undefined) {
        throw new MasterKeyRotationError(
          "ROTATION_REFUSED",
          "PUSH_RECEIVER_SECRETS rewrapped but commitPushSecrets port is missing",
        );
      }
      await input.commitPushSecrets(pushSecretsRewrapped);
    }
    await input.unitOfWork.commit();
    // Vault TX closed; session lease still held (uowStarted stays true until end).
    vaultDurable = true;

    for (const row of walletRewrapped) {
      await input.journal.markRewrapped(row.identity.walletId);
    }

    const completed = await input.journal.complete();
    // Auto-settle to STABLE so a clean run leaves the journal ready for the next rotation.
    // If settle throws, journal remains ROTATION_COMPLETE — resume via finalizeCompletedRotation.
    const settled = await input.journal.settleStable();

    await input.unitOfWork.end();
    uowStarted = false;
    sessionHeld = false;

    logger.info(
      {
        event: "rotate.complete",
        dryRun: false,
        durationMs,
        walletCount: walletRewrapped.length,
        writerEpoch: settled.writerEpoch,
        completedPhase: completed.phase,
        vaultDurable,
      },
      "master-key rotation complete — every IMPLEMENTED store re-wrapped under the new key",
    );

    return {
      ...baseOutcome,
      committed: true,
      durationMs: Date.now() - startedAt,
      journal: settled,
    };
  } catch (err) {
    if (err instanceof DryRunRollback) {
      if (uowStarted || sessionHeld) {
        await input.unitOfWork.rollback();
        uowStarted = false;
        sessionHeld = false;
      }
      await restoreJournal(input.journal, err.outcome.journalSnapshot);
      logger.info(
        {
          event: "rotate.dry_run_ok",
          walletCount: err.outcome.walletCount,
          durationMs: err.outcome.durationMs,
          stores: err.outcome.stores.map((s) => ({
            store: s.storeId,
            status: s.status,
            rows: s.result?.rowsAfter ?? 0,
          })),
        },
        "master-key rotation DRY-RUN OK — would succeed; nothing committed",
      );
      return {
        committed: false,
        dryRun: true,
        fromEpoch: err.outcome.fromEpoch,
        toEpoch: err.outcome.toEpoch,
        stores: err.outcome.stores,
        walletCount: err.outcome.walletCount,
        durationMs: err.outcome.durationMs,
        journal: await input.journal.read(),
      };
    }

    // Abort: release unit. If vault is not durable, rollback TX + restore journal.
    // If vaultDurable, vault TX already committed — end releases session lease only;
    // leave journal ROTATING or ROTATION_COMPLETE for resume (do NOT restore epoch).
    if (uowStarted || sessionHeld) {
      try {
        if (vaultDurable) {
          await input.unitOfWork.end();
        } else {
          await input.unitOfWork.rollback();
        }
      } catch {
        // swallow — original error is authoritative; best-effort lease release
        try {
          await input.unitOfWork.rollback();
        } catch {
          // ignore
        }
      }
      uowStarted = false;
      sessionHeld = false;
    }
    if (journalBegan && !vaultDurable) {
      try {
        await restoreJournal(input.journal, journalBefore);
      } catch {
        // best-effort
      }
    }
    // D-B5 / operator surface: never claim "nothing committed" when vault rows are durable.
    const failMsg = vaultDurable
      ? "master-key rotation FAILED after durable vault commit — journal left for resume"
      : "master-key rotation FAILED — nothing committed";
    logger.error(
      {
        event: "rotate.failed",
        err: err instanceof Error ? err.message : String(err),
        vaultDurable,
      },
      failMsg,
    );
    if (err instanceof MasterKeyRotationError) throw err;
    throw new MasterKeyRotationError(
      "ROTATION_ABORTED",
      err instanceof Error ? err.message : String(err),
      err,
    );
  } finally {
    await input.interlock.release();
  }
}

/**
 * D-B5 resume: journal already at ROTATION_COMPLETE with writerEpoch advanced.
 * Verify every census row opens under the new root, settle to STABLE, return success.
 * Refuses when writerEpoch !== toEpoch or any row fails under newRoot.
 */
async function finalizeCompletedRotation(
  input: MasterKeyRotationInput,
  journalProbe: MasterKeyRotationJournalRecord,
  logger: RotationLogger,
  startedAt: number,
): Promise<MasterKeyRotationResult> {
  if (journalProbe.writerEpoch !== input.toEpoch) {
    throw new MasterKeyRotationError(
      "ROTATION_STATE",
      `journal is ROTATION_COMPLETE at writerEpoch ${journalProbe.writerEpoch} but toEpoch is ${input.toEpoch}`,
    );
  }
  await input.interlock.acquire();
  let sessionHeld = false;
  try {
    await input.unitOfWork.begin();
    sessionHeld = true;

    // The census is a pre-fence snapshot. Re-read authoritative counts and verify every
    // IMPLEMENTED store under the new root before any success or settlement result.
    const stores = await verifyCompletedStoreCensus(input);

    const current = await input.journal.read();
    // Lost race with another finalizer — already done. Still prove every row opens under
    // the new root: the winner's success is otherwise asserted rather than verified.
    const alreadySettled = current.phase === "STABLE" && current.writerEpoch === input.toEpoch;
    if (!alreadySettled && (current.phase !== "ROTATION_COMPLETE" || current.writerEpoch !== input.toEpoch)) {
      throw new MasterKeyRotationError(
        "ROTATION_STATE",
        `finalize expected ROTATION_COMPLETE@${input.toEpoch}, saw ${current.phase}@${current.writerEpoch}`,
      );
    }

    // Ahead of the lost-race branch on purpose (M2): a caller that asked for
    // dryRun must never be told `{ committed: true, dryRun: false }` just because a
    // concurrent finalizer settled first. A dry run reports what it did — nothing.
    if (input.dryRun === true) {
      await input.unitOfWork.rollback();
      sessionHeld = false;
      return {
        committed: false,
        dryRun: true,
        fromEpoch: input.fromEpoch,
        toEpoch: input.toEpoch,
        stores,
        walletCount: input.walletVault.rows.length,
        durationMs: Date.now() - startedAt,
        journal: current,
      };
    }

    if (alreadySettled) {
      await input.unitOfWork.rollback();
      sessionHeld = false;
      return {
        committed: true,
        dryRun: false,
        fromEpoch: input.fromEpoch,
        toEpoch: input.toEpoch,
        stores,
        walletCount: input.walletVault.rows.length,
        durationMs: Date.now() - startedAt,
        journal: current,
      };
    }

    // No vault TX work — commit is a no-op close of the nested TX so end can run.
    await input.unitOfWork.commit();
    const settled = await input.journal.settleStable();
    await input.unitOfWork.end();
    sessionHeld = false;

    logger.info(
      {
        event: "rotate.complete",
        dryRun: false,
        durationMs: Date.now() - startedAt,
        walletCount: input.walletVault.rows.length,
        writerEpoch: settled.writerEpoch,
        completedPhase: "ROTATION_COMPLETE",
        vaultDurable: true,
        resumedFinalize: true,
      },
      "master-key rotation finalize — ROTATION_COMPLETE settled to STABLE",
    );

    return {
      committed: true,
      dryRun: false,
      fromEpoch: input.fromEpoch,
      toEpoch: input.toEpoch,
      stores,
      walletCount: input.walletVault.rows.length,
      durationMs: Date.now() - startedAt,
      journal: settled,
    };
  } catch (err) {
    if (sessionHeld) {
      try {
        await input.unitOfWork.rollback();
      } catch {
        // ignore
      }
    }
    logger.error(
      {
        event: "rotate.failed",
        err: err instanceof Error ? err.message : String(err),
        vaultDurable: true,
        resumedFinalize: true,
      },
      "master-key rotation FAILED during ROTATION_COMPLETE finalize — journal left for resume",
    );
    if (err instanceof MasterKeyRotationError) throw err;
    throw new MasterKeyRotationError(
      "ROTATION_ABORTED",
      err instanceof Error ? err.message : String(err),
      err,
    );
  } finally {
    await input.interlock.release();
  }
}

/** Authoritative count/parity/open proof for every registry store. */
async function verifyCompletedStoreCensus(
  input: MasterKeyRotationInput,
): Promise<StoreRotationReport[]> {
  const stores: StoreRotationReport[] = [];
  for (const store of input.sealedStores) {
    if (store.rewrapStatus === "DEFERRED_NO_SEAL_RUNTIME") {
      stores.push({ storeId: store.id, status: "DEFERRED_NO_SEAL_RUNTIME", result: null });
      continue;
    }

    if (store.id === "WALLET_VAULT") {
      const count = await input.countWalletVaultRows();
      assertCompletedCountParity(store.id, input.walletVault.rows.length, count);
      for (const row of input.walletVault.rows) {
        try {
          const opened = openWalletSecret(input.newRootKey, row.envelope, row.identity);
          opened.wipe();
        } catch (err) {
          throw new MasterKeyRotationError(
            "ROTATION_STATE",
            `WALLET_VAULT row ${row.identity.walletId} does not open under new root during ROTATION_COMPLETE finalize`,
            err,
          );
        }
      }
      stores.push(completedStoreReport(store.id, count));
      continue;
    }

    if (store.id === "NODE_SIGNING_KEYS") {
      if (input.nodeSigningKeys === undefined || input.countNodeSigningKeyRows === undefined) {
        throw new MasterKeyRotationError(
          "ROTATION_STATE",
          "NODE_SIGNING_KEYS finalize requires census and authoritative count ports",
        );
      }
      const count = await input.countNodeSigningKeyRows();
      assertCompletedCountParity(store.id, input.nodeSigningKeys.rows.length, count);
      if (count > 0) {
        if (input.rewrapNodeSigningKeyStore === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_STATE",
            "NODE_SIGNING_KEYS finalize requires a new-root open verifier",
          );
        }
        try {
          const proof = input.rewrapNodeSigningKeyStore({
            oldRootKey: input.newRootKey,
            newRootKey: input.newRootKey,
            rows: input.nodeSigningKeys.rows,
          });
          assertCompletedRewrapParity(store.id, count, proof.result);
        } catch (err) {
          if (err instanceof MasterKeyRotationError) throw err;
          throw new MasterKeyRotationError(
            "ROTATION_STATE",
            "NODE_SIGNING_KEYS census does not open under new root during ROTATION_COMPLETE finalize",
            err,
          );
        }
      }
      stores.push(completedStoreReport(store.id, count));
      continue;
    }

    if (store.id === "PUSH_RECEIVER_SECRETS") {
      if (input.pushReceiverSecrets === undefined || input.countPushSecretRows === undefined) {
        throw new MasterKeyRotationError(
          "ROTATION_STATE",
          "PUSH_RECEIVER_SECRETS finalize requires census and authoritative count ports",
        );
      }
      const count = await input.countPushSecretRows();
      assertCompletedCountParity(store.id, input.pushReceiverSecrets.rows.length, count);
      if (count > 0) {
        if (input.rewrapPushSecretStore === undefined) {
          throw new MasterKeyRotationError(
            "ROTATION_STATE",
            "PUSH_RECEIVER_SECRETS finalize requires a new-root open verifier",
          );
        }
        try {
          const proof = await input.rewrapPushSecretStore({
            keyRing: {
              writerEpoch: input.toEpoch,
              entries: [{ epoch: input.toEpoch, root: input.newRootKey }],
            },
            newRootKey: input.newRootKey,
            fromEpoch: input.fromEpoch,
            toEpoch: input.toEpoch,
            rows: input.pushReceiverSecrets.rows,
          });
          assertCompletedRewrapParity(store.id, count, proof.result);
        } catch (err) {
          if (err instanceof MasterKeyRotationError) throw err;
          throw new MasterKeyRotationError(
            "ROTATION_STATE",
            "PUSH_RECEIVER_SECRETS census does not open under new root during ROTATION_COMPLETE finalize",
            err,
          );
        }
      }
      stores.push(completedStoreReport(store.id, count));
      continue;
    }

    throw new MasterKeyRotationError(
      "REGISTRY_INCOMPLETE",
      `store ${store.id} is IMPLEMENTED but has no ROTATION_COMPLETE verifier`,
    );
  }
  return stores;
}

function assertCompletedCountParity(storeId: string, census: number, count: number): void {
  if (census !== count) {
    throw new MasterKeyRotationError(
      "ROTATION_STATE",
      `${storeId} finalize census/count parity failed (census=${census} count=${count})`,
    );
  }
}

function assertCompletedRewrapParity(
  storeId: string,
  count: number,
  result: SealedStoreRewrapResult,
): void {
  if (result.rowsBefore !== count || result.rowsAfter !== count || result.rewrapped !== count) {
    throw new MasterKeyRotationError(
      "ROTATION_STATE",
      `${storeId} finalize verification parity failed (count=${count} before=${result.rowsBefore} after=${result.rowsAfter} verified=${result.rewrapped})`,
    );
  }
}

function completedStoreReport(storeId: string, count: number): StoreRotationReport {
  return {
    storeId,
    status: "REWRAPPED",
    result: { rowsBefore: count, rowsAfter: count, rewrapped: count },
  };
}

// ─── Internals ───────────────────────────────────────────────────────────────

function validateEpochs(input: MasterKeyRotationInput): void {
  if (input.toEpoch !== input.fromEpoch + 1) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      `toEpoch must be fromEpoch+1 (from=${input.fromEpoch} to=${input.toEpoch})`,
    );
  }
  if (input.oldRootKey.length === 0 || input.newRootKey.length === 0) {
    throw new MasterKeyRotationError("ROTATION_REFUSED", "root keys must be non-empty");
  }
  if (buffersEqual(input.oldRootKey, input.newRootKey)) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "new root equals old root — nothing to rotate",
    );
  }
}

function assertKeyRingMatches(input: MasterKeyRotationInput): void {
  // During rotation the writer root is the NEW root (seals go out under toEpoch).
  if (input.keyRing.writerEpoch !== input.toEpoch) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      `key-ring writerEpoch ${input.keyRing.writerEpoch} must equal toEpoch ${input.toEpoch}`,
    );
  }
  const wr = writerRoot(input.keyRing);
  if (!buffersEqual(wr, input.newRootKey)) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "key-ring writer root does not match newRootKey",
    );
  }
  const oldEntry = input.keyRing.entries.find((e) => e.epoch === input.fromEpoch);
  if (oldEntry === undefined) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      `key-ring must retain old epoch ${input.fromEpoch} until ROTATION_COMPLETE`,
    );
  }
  if (!buffersEqual(oldEntry.root, input.oldRootKey)) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "key-ring retained old root does not match oldRootKey",
    );
  }
}

/**
 * Rewrap the wallet-vault census under the key-ring (guard 3 resume).
 *
 * - Every row opens via key-ring (writer first, then retained old). Journal marks are
 * a soft hint only — never assume "marked ⇒ new root" (false marks from a prior
 * crash window would strand the vault under ROTATION_STATE).
 * - If already under toEpoch, carry through without reseal; if under fromEpoch, reseal
 * under newRoot with a fresh nonce and round-trip verify.
 * Canonical wallet-id ordering (guard 4).
 * - Parity is proven against `storeRowCount` (read inside the fence), not against the
 * census length — comparing the census to a set derived from it can never fail (D-A2).
 */
function rewrapWalletVaultForRotation(
  input: MasterKeyRotationInput,
  journal: MasterKeyRotationJournalRecord,
  storeRowCount: number,
): {
  result: SealedStoreRewrapResult;
  rewrappedRows: readonly WalletVaultRewrapRow[];
  skippedAlreadyNew: number;
} {
  const sortedIds = sortWalletIdsAscending(
    input.walletVault.rows.map((r) => r.identity.walletId),
  );
  const byId = new Map(input.walletVault.rows.map((r) => [r.identity.walletId, r]));
  // A duplicated wallet id would silently collapse to one rewrap while every count still
  // agreed, committing N rows for one distinct wallet. Fail closed on a malformed census.
  if (byId.size !== input.walletVault.rows.length) {
    throw new MasterKeyRotationError(
      "ROTATION_ABORTED",
      `wallet census has duplicate wallet ids (${input.walletVault.rows.length} rows, ${byId.size} distinct)`,
    );
  }
  // journal.rewrappedWalletIds is intentionally not consulted for open path — marks are
  // not co-durable with vault envelopes (D-B1). Key-ring open is the source of truth.
  void journal.rewrappedWalletIds;

  const out: WalletVaultRewrapRow[] = [];
  let rewrappedFresh = 0;
  let skippedAlreadyNew = 0;

  for (const id of sortedIds) {
    const row = byId.get(id);
    if (row === undefined) {
      throw new MasterKeyRotationError(
        "ROTATION_ABORTED",
        `wallet census missing row for ${id}`,
      );
    }

    // Always open via key-ring. Marks are not a durability signal for the envelope
    // epoch — a mark without durable new ciphertext must still reseal under newRoot.
    let openedEpoch: number;
    let secretBytes: Uint8Array;
    try {
      const opened = openWithKeyRing(input.keyRing, row.envelope, row.identity);
      openedEpoch = opened.epoch;
      // brand the coordinator-owned plaintext copy so zeroize cannot be
      // discharged by a decoy Buffer under the same role string.
      secretBytes = keyMaterialHygiene.adopt(Buffer.from(opened.secret.bytes));
      opened.secret.wipe();
    } catch (err) {
      throw new MasterKeyRotationError(
        "ROTATION_ABORTED",
        err instanceof Error ? err.message : String(err),
        err,
      );
    }

    // D-A1 / D-B8: `secretBytes` is module-owned plaintext Ed25519 secret key material.
    // EVERY exit from here — the already-new `continue` (the crash-resume branch), the
    // unexpected-epoch `throw`, and the reseal path — must pass through the wipe. wallet-vault model
    // guard 5 and its carried-forward never persist or log key material invariant ("plaintext in memory only, zeroed
    // after use"); same discipline envelope.ts documents for this class. Routed through
    // keyMaterialHygiene.zeroize so the wipe is the spyable seam, not a bare fill(0).
    // Role `seal_plaintext`: same class as envelope seal's module-owned secret copy
    // (rotation holds it only to reseal under the new root).
    try {
      if (openedEpoch === input.toEpoch) {
        // Already under new root (prior durable commit, with or without a journal mark).
        out.push(row);
        skippedAlreadyNew += 1;
        continue;
      }

      if (openedEpoch !== input.fromEpoch) {
        throw new MasterKeyRotationError(
          "ROTATION_ABORTED",
          `wallet ${id} opened under unexpected epoch ${openedEpoch} (from=${input.fromEpoch} to=${input.toEpoch})`,
        );
      }

      // Opened under old root — reseal under new.
      try {
        const resealed = sealWalletSecret(input.newRootKey, row.identity, secretBytes);
        if (resealed.walletId !== row.identity.walletId || resealed.keyVersion !== row.identity.keyVersion) {
          throw new Error(`reseal mutated identity for ${id}`);
        }
        if (buffersEqual(resealed.nonce, row.envelope.nonce)) {
          throw new Error(`reseal reused nonce for ${id}`);
        }
        const roundTrip = openWalletSecret(input.newRootKey, resealed, row.identity);
        try {
          if (!buffersEqual(roundTrip.bytes, secretBytes)) {
            throw new Error(`round-trip secret mismatch for ${id}`);
          }
        } finally {
          roundTrip.wipe();
        }
        out.push({ identity: row.identity, envelope: resealed });
        rewrappedFresh += 1;
      } catch (err) {
        if (err instanceof MasterKeyRotationError) throw err;
        throw new MasterKeyRotationError(
          "ROTATION_ABORTED",
          err instanceof Error ? err.message : String(err),
          err,
        );
      }
    } finally {
      keyMaterialHygiene.zeroize(secretBytes, "seal_plaintext");
    }
  }

  // D-A2: parity against the STORE, read inside the fence — not against the census length,
  // which is derived from the same array every branch above pushes exactly once from and so
  // can never disagree. A store row absent from the census would otherwise be skipped
  // silently, stay under the old root, and be lost when the operator destroys that root.
  const result: SealedStoreRewrapResult = {
    rowsBefore: storeRowCount,
    rowsAfter: out.length,
    // Count every row that ends under the new root (fresh reseal + already-new).
    rewrapped: out.length,
  };
  if (result.rowsBefore !== result.rowsAfter) {
    throw new MasterKeyRotationError(
      "ROTATION_ABORTED",
      `wallet vault count parity failed — census does not cover the store (store=${result.rowsBefore} rewrapped=${result.rowsAfter} fresh=${rewrappedFresh} skipped=${skippedAlreadyNew})`,
    );
  }

  return { result, rewrappedRows: out, skippedAlreadyNew };
}


/**
 * Restore journal to a prior snapshot. InMemory journal has no transactional undo, so
 * we settle to STABLE then re-begin and re-mark if the snapshot was mid-rotation.
 * For a STABLE snapshot, settleStable alone is enough (writer epoch preserved on abort
 * because complete was never called).
 */
async function restoreJournal(
  journal: MasterKeyRotationJournal,
  snapshot: MasterKeyRotationJournalRecord,
): Promise<void> {
  // Always settle first — clears ROTATING / COMPLETE back to whatever writerEpoch the
  // journal currently holds. On abort before complete, writerEpoch is still the old one.
  await journal.settleStable();
  const current = await journal.read();
  if (snapshot.phase === "STABLE") {
    if (current.writerEpoch !== snapshot.writerEpoch) {
      throw new MasterKeyRotationError(
        "ROTATION_STATE",
        `journal restore: writerEpoch drifted ${current.writerEpoch} vs snapshot ${snapshot.writerEpoch}`,
      );
    }
    return;
  }
  // Snapshot was ROTATING — re-enter ROTATING and re-apply marks so a higher-level resume still works.
  if (snapshot.phase === "ROTATING" && snapshot.fromEpoch !== null && snapshot.toEpoch !== null) {
    await journal.begin({ fromEpoch: snapshot.fromEpoch, toEpoch: snapshot.toEpoch });
    for (const id of snapshot.rewrappedWalletIds) {
      await journal.markRewrapped(id);
    }
  }
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Ceremony advisory lock id for master-key rotation ("GNmk" ASCII). Distinct from
 * signer leadership (SLL) and migration (GNmg). Used as BOTH:
 * - session lock (`pg_advisory_lock`) held begin → end (D-B4 exclusive span through
 * journal.complete / settleStable);
 * - nested xact lock (`pg_advisory_xact_lock`) for the vault write TX only.
 */
export const MASTER_KEY_ROTATION_ADVISORY_LOCK_ID = 0x474e6d6b; // "GNmk"

/**
 * Session-scoped ceremony fence. Survives vault TX commit; released by
 * {@link RELEASE_ROTATION_SESSION_LOCK_SQL} in unit end/rollback.
 * `$1` is {@link MASTER_KEY_ROTATION_ADVISORY_LOCK_ID}.
 */
export const ACQUIRE_ROTATION_SESSION_LOCK_SQL =
  "SELECT pg_advisory_lock($1) AS locked";

/** Symmetric unlock for {@link ACQUIRE_ROTATION_SESSION_LOCK_SQL}. */
export const RELEASE_ROTATION_SESSION_LOCK_SQL =
  "SELECT pg_advisory_unlock($1) AS released";

/**
 * Nested vault-TX lock acquired after the session lock on begin.
 * Self-releases on vault TX commit/rollback. `$1` is the same lock id.
 */
export const ACQUIRE_ROTATION_XACT_LOCK_SQL =
  "SELECT pg_advisory_xact_lock($1) AS locked";
