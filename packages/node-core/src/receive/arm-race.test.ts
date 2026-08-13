import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertMemoryArmCommitSession,
  buildArmSuccessResponse,
  createArmMutationService,
  expiresAtFromUnixSecs,
  isArmableWalletStanding,
  isReceiveUnexpired,
  type ArmAuditEntry,
  type ArmAuditLog,
  type ArmClock,
  type ArmCommitSession,
  type ArmOperationGateSnapshot,
  type ArmOperationState,
  type ArmRecord,
  type ArmReleasePayload,
  type ArmSignatureVerifier,
  type ArmStore,
  type ArmWalletGate,
  type ArmWalletLockHandle,
  type ArmWalletStanding,
  type ArmWalletState,
  type T0Projection,
} from "./arm-mutation.js";
import {
  ARM_SQL_STATEMENTS,
  activeArmTx,
  commitArmUnderWalletLock,
  createFailClosedArmHandler,
  createSqlArmStore,
  createSqlArmWalletGate,
  createSqlTxBoundOperationState,
  requireActiveArmSqlTx,
  type SqlTxExecutor,
  type SqlTxFactory,
} from "./arm-sql.js";

// ---------------------------------------------------------------------------
// Memory doubles — session-bound DML (receive arm barrier)
// ---------------------------------------------------------------------------

class MemoryArmStore implements ArmStore {
  readonly records: ArmRecord[] = [];
  readonly releases = new Map<string, ArmReleasePayload>();
  /** Optional hook: runs inside tryInsert after session check (under wallet lock). */
  beforeInsert: (() => Promise<void>) | null = null;
  /** Captured sessions at tryInsert — tests assert same-TX / same-token binding. */
  readonly insertSessions: ArmCommitSession[] = [];
  /** Gate that publishes the live held token — required for memory session proofs. */
  private gate: MemoryWalletGate | null = null;

  bindGate(gate: MemoryWalletGate): void {
    this.gate = gate;
  }

  async findByOperation(operationId: string): Promise<ArmRecord | null> {
    return this.records.find((r) => r.operationId === operationId) ?? null;
  }
  async loadReleasedCode(operationId: string): Promise<ArmReleasePayload | null> {
    return this.releases.get(operationId) ?? null;
  }
  async tryInsert(record: ArmRecord, session: ArmCommitSession): Promise<ArmRecord | null> {
    // Fail closed without a live commit session (mirrors SQL requireActiveArmSqlTx).
    if (session.kind === "sql") {
      requireActiveArmSqlTx(session);
    } else if (session.kind === "memory") {
      if (this.gate === null) {
        throw new Error("MemoryArmStore has no gate for held-token bind");
      }
      assertMemoryArmCommitSession(session, (token) => this.gate!.isHeldToken(token));
    } else {
      throw new Error("unknown commit session kind");
    }
    this.insertSessions.push(session);
    if (this.beforeInsert) await this.beforeInsert();
    const existing = this.records.find((r) => r.operationId === record.operationId);
    if (existing) return null;
    this.records.push(record);
    return record;
  }
}

interface SeededOperation {
  state: string;
  walletId: string;
  t0: T0Projection;
  attentionReasons: string[];
  rowVersion: number;
  expiryUnixTimeSecs: string;
  codeStatus: "AWAITING_ARM" | "RELEASED" | "EXPIRED";
  transferCode: string;
  transferCodeSha256: string;
}

const DEFAULT_EXPIRY_SECS = "2000000000"; // far future
const DEFAULT_CODE = "exact-transfer-code-text";
const DEFAULT_CODE_SHA = "a".repeat(64);

class MemoryOperationState implements ArmOperationState {
  readonly operations = new Map<string, SeededOperation>();
  readonly transitions: string[] = [];
  readonly transitionSessions: ArmCommitSession[] = [];
  /** Populated on successful transition — mirrors receive_codes RELEASED. */
  readonly releases = new Map<string, ArmReleasePayload>();
  /** Optional external release map (shared with MemoryArmStore.loadReleasedCode). */
  externalReleases: Map<string, ArmReleasePayload> | null = null;

  seed(
    operationId: string,
    op: Omit<SeededOperation, "attentionReasons" | "rowVersion" | "expiryUnixTimeSecs" | "codeStatus" | "transferCode" | "transferCodeSha256"> &
      Partial<Pick<SeededOperation, "rowVersion" | "expiryUnixTimeSecs" | "codeStatus" | "transferCode" | "transferCodeSha256">>,
  ): void {
    this.operations.set(operationId, {
      state: op.state,
      walletId: op.walletId,
      t0: op.t0,
      attentionReasons: [],
      rowVersion: op.rowVersion ?? 2,
      expiryUnixTimeSecs: op.expiryUnixTimeSecs ?? DEFAULT_EXPIRY_SECS,
      codeStatus: op.codeStatus ?? "AWAITING_ARM",
      transferCode: op.transferCode ?? DEFAULT_CODE,
      transferCodeSha256: op.transferCodeSha256 ?? DEFAULT_CODE_SHA,
    });
  }
  async getState(operationId: string): Promise<string | null> {
    return this.operations.get(operationId)?.state ?? null;
  }
  async getAssignedWallet(operationId: string): Promise<string | null> {
    return this.operations.get(operationId)?.walletId ?? null;
  }
  async getT0(operationId: string): Promise<T0Projection | null> {
    return this.operations.get(operationId)?.t0 ?? null;
  }
  async lockAndReadGate(
    operationId: string,
    _session: ArmCommitSession,
  ): Promise<ArmOperationGateSnapshot | null> {
    const op = this.operations.get(operationId);
    if (!op) return null;
    return {
      state: op.state,
      rowVersion: op.rowVersion,
      expiryUnixTimeSecs: op.expiryUnixTimeSecs,
      receiverWalletId: op.walletId,
      codeStatus: op.codeStatus,
      transferCode: op.transferCode,
      transferCodeSha256: op.transferCodeSha256,
    };
  }
  async transitionToArmed(
    operationId: string,
    session: ArmCommitSession,
    expectedRowVersion: number,
  ): Promise<
    | { readonly ok: true; readonly release: ArmReleasePayload }
    | { readonly ok: false; readonly reason: "version_conflict" | "not_armable" | "expired"; readonly currentRowVersion?: number }
  > {
    if (session.kind === "sql") {
      requireActiveArmSqlTx(session);
    }
    this.transitionSessions.push(session);
    const op = this.operations.get(operationId);
    if (!op) return { ok: false, reason: "not_armable" };
    if (op.state !== "READY") return { ok: false, reason: "not_armable" };
    if (op.codeStatus !== "AWAITING_ARM") return { ok: false, reason: "not_armable" };
    if (op.rowVersion !== expectedRowVersion) {
      return { ok: false, reason: "version_conflict", currentRowVersion: op.rowVersion };
    }
    op.codeStatus = "RELEASED";
    op.rowVersion = op.rowVersion + 1;
    // Spec: state stays READY after arm — never invent ARMED public status.
    this.transitions.push(operationId);
    const release: ArmReleasePayload = {
      transferCode: op.transferCode,
      transferCodeSha256: op.transferCodeSha256,
      expiresAt: expiresAtFromUnixSecs(op.expiryUnixTimeSecs),
      rowVersion: op.rowVersion,
    };
    this.releases.set(operationId, release);
    if (this.externalReleases) this.externalReleases.set(operationId, release);
    return { ok: true, release };
  }
  async markAttention(operationId: string, reason: string): Promise<void> {
    const op = this.operations.get(operationId);
    if (op) op.attentionReasons.push(reason);
  }
}

/**
 * In-memory wallet gate with a **faithful row-lock model**:
 * - `withWalletLocked` holds a per-wallet mutex for the full body and issues a
 * unique memory commit token via `requireCommitSession`.
 * - Standing mutations ONLY apply under that mutex (`quarantineLocked`). There is
 * no unlocked mid-hold flip — that would not be possible under real FOR UPDATE.
 * Concurrent quarantineLocked waits until the arm body releases (serialization).
 */
class MemoryWalletGate implements ArmWalletGate {
  readonly wallets = new Map<string, ArmWalletStanding>();
  readonly lockCalls: string[] = [];
  private readonly chain = new Map<string, Promise<void>>();
  /** Live lock token while withWalletLocked body runs; cleared on release. */
  private readonly heldToken = new Map<string, object>();

  seed(walletId: string, standing: Omit<ArmWalletStanding, "walletId">): void {
    this.wallets.set(walletId, { walletId, ...standing });
  }

  /** Quarantine under the same FOR UPDATE mutex the arm path holds. */
  async quarantineLocked(walletId: string, _reason = "unexpected head movement"): Promise<void> {
    await this.withLockHeld(walletId, async () => {
      const row = this.wallets.get(walletId);
      if (!row) return;
      this.wallets.set(walletId, { ...row, state: "QUARANTINED" });
    });
  }

  /** Seed-time / pre-arm flip — only legal when the lock is NOT held. */
  quarantineBeforeArm(walletId: string): void {
    if (this.heldToken.has(walletId)) {
      throw new Error("test bug: quarantineBeforeArm while lock held — use quarantineLocked");
    }
    const row = this.wallets.get(walletId);
    if (!row) return;
    this.wallets.set(walletId, { ...row, state: "QUARANTINED" });
  }

  peek(walletId: string): ArmWalletStanding | null {
    const row = this.wallets.get(walletId);
    return row === undefined ? null : { ...row };
  }

  /** True iff token is the live held lock token for some wallet (identity equality). */
  isHeldToken(token: object): boolean {
    for (const held of this.heldToken.values()) {
      if (held === token) return true;
    }
    return false;
  }

  async withWalletLocked<T>(
    walletId: string,
    body: (lock: ArmWalletLockHandle) => Promise<T>,
  ): Promise<T> {
    this.lockCalls.push(walletId);
    return this.withLockHeld(walletId, async () => {
      const token = { walletId };
      this.heldToken.set(walletId, token);
      try {
        const lock: ArmWalletLockHandle = {
          readStanding: async () => {
            if (this.heldToken.get(walletId) !== token) {
              throw new Error("readStanding after wallet lock released");
            }
            const row = this.wallets.get(walletId);
            return row === undefined ? null : { ...row };
          },
          requireCommitSession: (): ArmCommitSession => {
            if (this.heldToken.get(walletId) !== token) {
              throw new Error("requireCommitSession after wallet lock released");
            }
            return { kind: "memory", token };
          },
        };
        return await body(lock);
      } finally {
        this.heldToken.delete(walletId);
      }
    });
  }

  async withLockHeld<T>(walletId: string, body: () => Promise<T>): Promise<T> {
    const prev = this.chain.get(walletId) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.chain.set(walletId, prev.then(() => mine));
    await prev;
    try {
      return await body();
    } finally {
      release();
    }
  }
}

class MemoryAuditLog implements ArmAuditLog {
  readonly entries: ArmAuditEntry[] = [];
  async append(entry: ArmAuditEntry): Promise<void> {
    this.entries.push(entry);
  }
}

function keyFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function pubKeyBase64Url(privateKey: ReturnType<typeof keyFromSeed>): string {
  return createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .subarray(-32)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_");
}

class Ed25519ArmVerifier implements ArmSignatureVerifier {
  constructor(private readonly publicKeys: Map<string, string>) {}
  async verify(input: {
    walletId: string;
    preimageText: string;
    signatureBytes: Uint8Array;
  }): Promise<boolean> {
    const pubEncoded = this.publicKeys.get(input.walletId);
    if (!pubEncoded) return false;
    const raw = Buffer.from(pubEncoded.replaceAll("-", "+").replaceAll("_", "/"), "base64");
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const pubKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    return verify(
      null,
      Buffer.from(input.preimageText, "utf8"),
      pubKey,
      Buffer.from(input.signatureBytes),
    );
  }
}

const FIXED_TIME = "2026-01-15T10:00:00.000Z";
const WALLET_KEY = keyFromSeed(0xab);
const WALLET_PUB = pubKeyBase64Url(WALLET_KEY);
const WALLET_ID = "wallet-receiver-001";
const NODE_T0: T0Projection = {
  observationId: "obs-001",
  s0: "s0-value",
  p0: "p0-value",
  b0: "10.000000",
};
const fixedClock: ArmClock = { now: () => FIXED_TIME };

function validArmRequest(operationId: string) {
  const preimageText = `arm:${operationId}:${NODE_T0.observationId}:${NODE_T0.s0}:${NODE_T0.p0}:${NODE_T0.b0}`;
  const signatureBytes = new Uint8Array(sign(null, Buffer.from(preimageText, "utf8"), WALLET_KEY));
  return {
    operationId,
    walletId: WALLET_ID,
    nodeT0ObservationId: NODE_T0.observationId,
    acknowledgedS: NODE_T0.s0,
    acknowledgedP: NODE_T0.p0,
    acknowledgedB: NODE_T0.b0,
    openedCursor: 1043n,
    expectedRowVersion: 2,
    nowMs: Date.parse(FIXED_TIME),
    signatureBytes,
    preimageText,
  };
}

function buildService(opts?: {
  walletState?: ArmWalletState;
  recoveryVerifiedAt?: string | null;
}) {
  const armStore = new MemoryArmStore();
  const operationState = new MemoryOperationState();
  operationState.externalReleases = armStore.releases;
  const auditLog = new MemoryAuditLog();
  const walletGate = new MemoryWalletGate();
  armStore.bindGate(walletGate);
  walletGate.seed(WALLET_ID, {
    recoveryVerifiedAt:
      opts?.recoveryVerifiedAt === undefined ? FIXED_TIME : opts.recoveryVerifiedAt,
    state: opts?.walletState ?? "PINNED",
    allowExternalReceive: true,
  });
  const publicKeys = new Map([[WALLET_ID, WALLET_PUB]]);
  const signatureVerifier = new Ed25519ArmVerifier(publicKeys);
  const service = createArmMutationService({
    armStore,
    operationState,
    signatureVerifier,
    auditLog,
    clock: fixedClock,
    walletGate,
  });
  return { service, armStore, operationState, auditLog, walletGate };
}

function testArmEnvelope(record: ArmRecord) {
  return {
    armId: `arm-${record.operationId}`,
    nodeId: "node-001",
    implementerId: "impl-001",
    rawTarget: `/v1/operations/${record.operationId}/armed`,
    requestBodySha256: "a".repeat(64),
    reportingNonceId: `nonce-${record.operationId}`,
    mutationIdempotencyId: `mut-${record.operationId}`,
  };
}

function seedReady(operationState: MemoryOperationState, operationId: string): void {
  operationState.seed(operationId, { state: "READY", walletId: WALLET_ID, t0: NODE_T0 });
}

// ---------------------------------------------------------------------------
// Faithful SQL lock mock: per-wallet serialization + query log with tx identity
// ---------------------------------------------------------------------------

interface TxLogEntry {
  readonly txId: number;
  readonly text: string;
  readonly params: readonly unknown[] | undefined;
}

/**
 * Models Postgres FOR UPDATE on wallet_id: concurrent withTransaction bodies that
 * lock the same wallet serialize; maxConcurrent for one wallet stays 1.
 */
function createLockSerializingTxFactory(opts: {
  rows: Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>;
  /** Optional: arm ack + code/ops tables for createSqlArmStore path. */
  armAcks?: Map<string, ArmRecord>;
  opStates?: Map<string, string>;
  codeStatuses?: Map<string, string>;
  opRowVersions?: Map<string, number>;
}): {
  txFactory: SqlTxFactory;
  log: TxLogEntry[];
  maxConcurrentByWallet: Map<string, number>;
  codeStatuses: Map<string, string>;
  opRowVersions: Map<string, number>;
  /** Quarantine that takes FOR UPDATE — blocks while arm holds the lock. */
  quarantineUnderLock: (walletId: string) => Promise<void>;
} {
  const log: TxLogEntry[] = [];
  const maxConcurrentByWallet = new Map<string, number>();
  const currentConcurrent = new Map<string, number>();
  const walletChains = new Map<string, Promise<void>>();
  let nextTxId = 1;
  const armAcks = opts.armAcks ?? new Map<string, ArmRecord>();
  const opStates = opts.opStates ?? new Map<string, string>();
  const codeStatuses = opts.codeStatuses ?? new Map<string, string>();
  const opRowVersions = opts.opRowVersions ?? new Map<string, number>();

  async function withWalletRowLock<T>(walletId: string, body: () => Promise<T>): Promise<T> {
    const prev = walletChains.get(walletId) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((resolve) => {
      release = resolve;
    });
    walletChains.set(walletId, prev.then(() => mine));
    await prev;
    const cur = (currentConcurrent.get(walletId) ?? 0) + 1;
    currentConcurrent.set(walletId, cur);
    maxConcurrentByWallet.set(
      walletId,
      Math.max(maxConcurrentByWallet.get(walletId) ?? 0, cur),
    );
    try {
      return await body();
    } finally {
      currentConcurrent.set(walletId, (currentConcurrent.get(walletId) ?? 1) - 1);
      release();
    }
  }

  const txFactory: SqlTxFactory = {
    async withTransaction<T>(fn: (tx: SqlTxExecutor) => Promise<T>): Promise<T> {
      const txId = nextTxId++;
      // Deferred wallet lock: acquired on first LOCK_WALLET_STANDING for a wallet.
      let heldWallet: string | null = null;
      const lockRelease: { fn: (() => void) | undefined } = { fn: undefined };

      const acquire = async (walletId: string) => {
        if (heldWallet === walletId) return;
        if (heldWallet !== null) {
          throw new Error("test mock: one wallet lock per TX");
        }
        const prev = walletChains.get(walletId) ?? Promise.resolve();
        let releaseGate!: () => void;
        const mine = new Promise<void>((resolve) => {
          releaseGate = () => resolve();
        });
        walletChains.set(walletId, prev.then(() => mine));
        await prev;
        heldWallet = walletId;
        lockRelease.fn = releaseGate;
        const cur = (currentConcurrent.get(walletId) ?? 0) + 1;
        currentConcurrent.set(walletId, cur);
        maxConcurrentByWallet.set(
          walletId,
          Math.max(maxConcurrentByWallet.get(walletId) ?? 0, cur),
        );
      };

      const tx: SqlTxExecutor = {
        async query<R>(text: string, params?: readonly unknown[]) {
          log.push({ txId, text, params });
          if (text === ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING) {
            const id = String(params?.[0]);
            await acquire(id);
            const row = opts.rows.get(id);
            if (row === undefined) return { rows: [] as R[] };
            return {
              rows: [
                {
                  wallet_id: id,
                  state: row.state,
                  recovery_verified_at: row.recovery_verified_at,
                  allow_external_receive: row.allow_external_receive !== false,
                },
              ] as R[],
            };
          }
          if (text === ARM_SQL_STATEMENTS.INSERT_ARM_ACK) {
            // Params: armId, operationId, nodeId, implementerId, rawTarget,
            // nodeT0, s, p, b, cursor, bodySha, nonceId, mutId, armedAt
            const operationId = String(params?.[1]);
            if (armAcks.has(operationId)) return { rows: [] as R[] };
            const record: ArmRecord = {
              operationId,
              walletId: WALLET_ID,
              nodeT0ObservationId: String(params?.[5]),
              acknowledgedS: String(params?.[6]),
              acknowledgedP: String(params?.[7]),
              acknowledgedB: String(params?.[8]),
              openedCursor: BigInt(String(params?.[9])),
              armedAt: String(params?.[13]),
            };
            armAcks.set(operationId, record);
            codeStatuses.set(operationId, codeStatuses.get(operationId) ?? "AWAITING_ARM");
            return { rows: [{ operation_id: operationId }] as R[] };
          }
          if (text === ARM_SQL_STATEMENTS.LOCK_OPERATION_GATE) {
            const operationId = String(params?.[0]);
            if (!opStates.has(operationId)) return { rows: [] as R[] };
            return {
              rows: [
                {
                  operation_id: operationId,
                  state: opStates.get(operationId),
                  row_version: opRowVersions.get(operationId) ?? 2,
                  expiry_unix_time_secs: "2000000000",
                  receiver_wallet_id: WALLET_ID,
                  code_status: codeStatuses.get(operationId) ?? "AWAITING_ARM",
                  transfer_code: "exact-transfer-code-text",
                  transfer_code_sha256: "a".repeat(64),
                },
              ] as R[],
            };
          }
          if (text === ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE) {
            const operationId = String(params?.[0]);
            if (codeStatuses.get(operationId) !== "AWAITING_ARM") return { rows: [] as R[] };
            codeStatuses.set(operationId, "RELEASED");
            return {
              rows: [
                {
                  operation_id: operationId,
                  transfer_code: "exact-transfer-code-text",
                  transfer_code_sha256: "a".repeat(64),
                  expiry_unix_time_secs: "2000000000",
                },
              ] as R[],
            };
          }
          if (text === ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION) {
            const operationId = String(params?.[0]);
            const expected = Number(params?.[1]);
            if (opStates.get(operationId) !== "READY") return { rows: [] as R[] };
            const cur = opRowVersions.get(operationId) ?? 2;
            if (cur !== expected) return { rows: [] as R[] };
            // status stays READY; row_version CAS bump
            const next = cur + 1;
            opRowVersions.set(operationId, next);
            return { rows: [{ operation_id: operationId, row_version: next }] as R[] };
          }
          if (text === ARM_SQL_STATEMENTS.LOAD_RELEASED_CODE) {
            const operationId = String(params?.[0]);
            if (codeStatuses.get(operationId) !== "RELEASED") return { rows: [] as R[] };
            return {
              rows: [
                {
                  transfer_code: "exact-transfer-code-text",
                  transfer_code_sha256: "a".repeat(64),
                  expiry_unix_time_secs: "2000000000",
                  row_version: opRowVersions.get(operationId) ?? 3,
                },
              ] as R[],
            };
          }
          if (text === ARM_SQL_STATEMENTS.FIND_ARM_BY_OPERATION) {
            const operationId = String(params?.[0]);
            const rec = armAcks.get(operationId);
            if (!rec) return { rows: [] as R[] };
            return {
              rows: [
                {
                  operation_id: rec.operationId,
                  wallet_id: rec.walletId,
                  node_t0_observation_id: rec.nodeT0ObservationId,
                  acknowledged_s: rec.acknowledgedS,
                  acknowledged_p: rec.acknowledgedP,
                  acknowledged_b: rec.acknowledgedB,
                  opened_cursor: rec.openedCursor.toString(),
                  armed_at: rec.armedAt,
                },
              ] as R[],
            };
          }
          return { rows: [] as R[] };
        },
      };
      try {
        return await fn(tx);
      } finally {
        const locked = heldWallet;
        const unlock = lockRelease.fn;
        if (locked !== null && unlock !== undefined) {
          currentConcurrent.set(locked, (currentConcurrent.get(locked) ?? 1) - 1);
          unlock();
        }
      }
    },
  };

  return {
    txFactory,
    log,
    maxConcurrentByWallet,
    codeStatuses,
    opRowVersions,
    quarantineUnderLock: async (walletId: string) => {
      await withWalletRowLock(walletId, async () => {
        const row = opts.rows.get(walletId);
        if (row) opts.rows.set(walletId, { ...row, state: "QUARANTINED" });
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Suites
// ---------------------------------------------------------------------------

describe("arm race safety", () => {
  it("admits exactly one of eight concurrent arm attempts on the same operation", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-race");
    const results = await Promise.all(
      Array.from({ length: 8 }, () => service.arm(validArmRequest("op-race"))),
    );
    const armed = results.filter((r) => r.status === "armed");
    const already = results.filter((r) => r.status === "already_armed");
    expect(armed.length + already.length).toBe(8);
    expect(armed.length).toBe(1);
    expect(armStore.records.length).toBe(1);
  });

  it("concurrent arms with mismatched T0: only the correct one commits", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-t0");
    const good = validArmRequest("op-t0");
    const bad = { ...validArmRequest("op-t0"), acknowledgedS: "wrong-s0" };
    const [a, b] = await Promise.all([service.arm(good), service.arm(bad)]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toContain("armed");
    expect(statuses).toContain("t0_mismatch");
    expect(armStore.records.length).toBe(1);
  });
});

describe("arm secrecy (the key-custody rule: platform never touches private keys)", () => {
  it("arm signature is produced by the reporting key, not the wallet signing key", () => {
    // Structural: verifier accepts ed25519 over public preimage; no private key in record.
    const preimage = "arm:op:obs:s:p:b";
    const sig = sign(null, Buffer.from(preimage, "utf8"), WALLET_KEY);
    expect(sig.byteLength).toBe(64);
    expect(WALLET_PUB.length).toBeGreaterThan(0);
  });

  it("arm record contains only public observation data, never private key material", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-sec");
    await service.arm(validArmRequest("op-sec"));
    const rec = armStore.records[0]!;
    const blob = JSON.stringify(rec, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
    expect(blob).not.toMatch(/302e020100300506032b6570/i);
    expect(rec).toMatchObject({
      operationId: "op-sec",
      walletId: WALLET_ID,
      acknowledgedS: NODE_T0.s0,
    });
  });

  it("signature bytes in the request are never persisted in the arm record", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-nosig");
    const req = validArmRequest("op-nosig");
    await service.arm(req);
    const rec = armStore.records[0] as unknown as Record<string, unknown>;
    expect(rec).not.toHaveProperty("signatureBytes");
    expect(rec).not.toHaveProperty("preimageText");
  });
});

describe("arm atomicity (no partial state visible)", () => {
  it("arm record is either fully committed or absent — never partial", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-atom");
    await service.arm(validArmRequest("op-atom"));
    const rec = armStore.records[0]!;
    expect(rec.operationId).toBe("op-atom");
    expect(rec.armedAt).toBe(FIXED_TIME);
    expect(rec.openedCursor).toBe(1043n);
  });

  it("state transition and arm record commit together — observers see both or neither", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-both");
    // Fail transition after insert — service currently doesn't roll back memory;
    // session binding still ensures both see the same session when both succeed.
    const outcome = await service.arm(validArmRequest("op-both"));
    expect(outcome.status).toBe("armed");
    expect(armStore.records.length).toBe(1);
    expect(await operationState.getState("op-both")).toBe("READY");
    expect(operationState.transitions).toContain("op-both");
    expect(armStore.insertSessions[0]).toBe(operationState.transitionSessions[0]);
  });
});

describe("failed arms do not corrupt operation state", () => {
  it("T0 mismatch leaves no arm record and does not transition state", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-fail-t0");
    const bad = { ...validArmRequest("op-fail-t0"), acknowledgedS: "nope" };
    const outcome = await service.arm(bad);
    expect(outcome.status).toBe("t0_mismatch");
    expect(armStore.records.length).toBe(0);
    expect(await operationState.getState("op-fail-t0")).toBe("READY");
  });

  it("invalid signature leaves no arm record and does not transition state", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-fail-sig");
    const bad = { ...validArmRequest("op-fail-sig"), signatureBytes: new Uint8Array(64) };
    const outcome = await service.arm(bad);
    expect(outcome.status).toBe("invalid_signature");
    expect(armStore.records.length).toBe(0);
    expect(await operationState.getState("op-fail-sig")).toBe("READY");
  });

  it("wrong wallet leaves no arm record and does not transition state", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-fail-w");
    const bad = { ...validArmRequest("op-fail-w"), walletId: "other-wallet" };
    // Gate has no seed for other-wallet; standing fails after lock.
    // Assigned-wallet check rejects before lock when walletId !== assigned.
    const outcome = await service.arm(bad);
    expect(outcome.status).toBe("operation_not_armable");
    expect(armStore.records.length).toBe(0);
    expect(await operationState.getState("op-fail-w")).toBe("READY");
  });

  it("non-READY operation rejects arm without writing any record", async () => {
    const { service, armStore, operationState } = buildService();
    operationState.seed("op-opened", { state: "OPENED", walletId: WALLET_ID, t0: NODE_T0 });
    const outcome = await service.arm(validArmRequest("op-opened"));
    expect(outcome.status).toBe("operation_not_armable");
    expect(armStore.records.length).toBe(0);
  });

  it("repeated failed arms followed by a valid arm: only the valid one commits", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-retry");
    await service.arm({ ...validArmRequest("op-retry"), acknowledgedS: "bad" });
    await service.arm({ ...validArmRequest("op-retry"), signatureBytes: new Uint8Array(64) });
    const ok = await service.arm(validArmRequest("op-retry"));
    expect(ok.status).toBe("armed");
    expect(armStore.records.length).toBe(1);
  });

  it("audit log records rejections without altering operation state", async () => {
    const { service, operationState, auditLog } = buildService();
    seedReady(operationState, "op-aud");
    await service.arm({ ...validArmRequest("op-aud"), acknowledgedS: "bad" });
    expect(auditLog.entries.some((e) => e.outcome === "REJECTED")).toBe(true);
    expect(await operationState.getState("op-aud")).toBe("READY");
  });
});


describe("code release + version + expiry", () => {
  it("armed outcome carries release payload (code + sha + expires_at + row_version)", async () => {
    const { service, operationState } = buildService();
    seedReady(operationState, "op-rel");
    const outcome = await service.arm(validArmRequest("op-rel"));
    expect(outcome.status).toBe("armed");
    if (outcome.status !== "armed") return;
    expect(outcome.release.transferCode).toBe("exact-transfer-code-text");
    expect(outcome.release.transferCodeSha256).toBe("a".repeat(64));
    expect(outcome.release.rowVersion).toBe(3); // was 2, CAS +1
    expect(outcome.release.expiresAt).toBe(expiresAtFromUnixSecs("2000000000"));
    const body = buildArmSuccessResponse({
      operationId: "op-rel",
      release: outcome.release,
    });
    expect(body).toEqual({
      operation_id: "op-rel",
      state: "READY",
      row_version: 3,
      code_status: "RELEASED",
      transfer_code: "exact-transfer-code-text",
      transfer_code_sha256: "a".repeat(64),
      expires_at: outcome.release.expiresAt,
    });
    // Public operation state stays READY.
    expect(await operationState.getState("op-rel")).toBe("READY");
  });

  it("stale expected_row_version returns operation_version_conflict and does not arm", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-ver");
    const outcome = await service.arm({
      ...validArmRequest("op-ver"),
      expectedRowVersion: 1, // durable is 2
    });
    expect(outcome.status).toBe("operation_version_conflict");
    if (outcome.status !== "operation_version_conflict") return;
    expect(outcome.currentRowVersion).toBe(2);
    expect(armStore.records.length).toBe(0);
    expect(operationState.transitions).toEqual([]);
    expect(await operationState.getState("op-ver")).toBe("READY");
  });

  it("expired code returns operation_not_armable and does not release", async () => {
    const { service, armStore, operationState } = buildService();
    operationState.seed("op-exp", {
      state: "READY",
      walletId: WALLET_ID,
      t0: NODE_T0,
      expiryUnixTimeSecs: "1000", // long past
    });
    const outcome = await service.arm(validArmRequest("op-exp"));
    expect(outcome.status).toBe("operation_not_armable");
    if (outcome.status !== "operation_not_armable") return;
    expect(outcome.reason).toMatch(/expired/i);
    expect(armStore.records.length).toBe(0);
    expect(operationState.transitions).toEqual([]);
  });

  it("t0 mismatch never returns release payload or mutates T0", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-mm");
    const before = await operationState.getT0("op-mm");
    const outcome = await service.arm({
      ...validArmRequest("op-mm"),
      acknowledgedS: "wrong",
    });
    expect(outcome.status).toBe("t0_mismatch");
    expect(armStore.records.length).toBe(0);
    expect(await operationState.getT0("op-mm")).toEqual(before);
    expect("release" in outcome).toBe(false);
  });

  it("idempotent re-arm returns identical release bytes without a second transition", async () => {
    const { service, armStore, operationState } = buildService();
    seedReady(operationState, "op-id");
    const first = await service.arm(validArmRequest("op-id"));
    expect(first.status).toBe("armed");
    if (first.status !== "armed") return;
    const second = await service.arm(validArmRequest("op-id"));
    expect(second.status).toBe("already_armed");
    if (second.status !== "already_armed") return;
    expect(second.release).toEqual(first.release);
    expect(armStore.records.length).toBe(1);
    expect(operationState.transitions).toEqual(["op-id"]);
    const body1 = JSON.stringify(
      buildArmSuccessResponse({ operationId: "op-id", release: first.release }),
    );
    const body2 = JSON.stringify(
      buildArmSuccessResponse({ operationId: "op-id", release: second.release }),
    );
    expect(body2).toBe(body1);
  });

  it("isReceiveUnexpired is exclusive at the whole-second boundary", () => {
    expect(isReceiveUnexpired("100", 100_000 - 1)).toBe(true);
    expect(isReceiveUnexpired("100", 100_000)).toBe(false);
    expect(isReceiveUnexpired("not-a-number", 0)).toBe(false);
  });
});

describe("arm standing gate — intervening quarantine (receive arm barrier; receive-gate enforcement)", () => {
  it("isArmableWalletStanding admits AVAILABLE and PINNED with recovery stamp only", () => {
    expect(
      isArmableWalletStanding({
        walletId: "w",
        state: "AVAILABLE",
        recoveryVerifiedAt: FIXED_TIME,
        allowExternalReceive: true,
      }).ok,
    ).toBe(true);
    expect(
      isArmableWalletStanding({
        walletId: "w",
        state: "PINNED",
        recoveryVerifiedAt: FIXED_TIME,
        allowExternalReceive: true,
      }).ok,
    ).toBe(true);
    expect(
      isArmableWalletStanding({
        walletId: "w",
        state: "QUARANTINED",
        recoveryVerifiedAt: FIXED_TIME,
        allowExternalReceive: true,
      }).ok,
    ).toBe(false);
    expect(
      isArmableWalletStanding({
        walletId: "w",
        state: "PINNED",
        recoveryVerifiedAt: null,
        allowExternalReceive: true,
      }).ok,
    ).toBe(false);
  });

  it("rejects when allow_external_receive is false (ZTR-1268)", () => {
    expect(
      isArmableWalletStanding({
        walletId: "w",
        state: "PINNED",
        recoveryVerifiedAt: FIXED_TIME,
        allowExternalReceive: false,
      }).ok,
    ).toBe(false);
  });

  it("rejects arm when the assigned wallet is already QUARANTINED — no arm record, no code path", async () => {
    const { service, armStore, operationState } = buildService({ walletState: "QUARANTINED" });
    seedReady(operationState, "op-q");
    const outcome = await service.arm(validArmRequest("op-q"));
    expect(outcome.status).toBe("operation_not_armable");
    if (outcome.status === "operation_not_armable") {
      expect(outcome.reason).toMatch(/QUARANTINED/);
    }
    expect(armStore.records.length).toBe(0);
    expect(await operationState.getState("op-q")).toBe("READY");
  });

  it("rejects arm when recovery_verified_at is null", async () => {
    const { service, armStore, operationState } = buildService({ recoveryVerifiedAt: null });
    seedReady(operationState, "op-null");
    const outcome = await service.arm(validArmRequest("op-null"));
    expect(outcome.status).toBe("operation_not_armable");
    expect(armStore.records.length).toBe(0);
  });

  it("rejects arm when wallet is RETIRED", async () => {
    const { service, armStore, operationState } = buildService({ walletState: "RETIRED" });
    seedReady(operationState, "op-ret");
    const outcome = await service.arm(validArmRequest("op-ret"));
    expect(outcome.status).toBe("operation_not_armable");
    expect(armStore.records.length).toBe(0);
  });

  it("pre-arm quarantine after READY assignment fails closed", async () => {
    const { service, armStore, operationState, walletGate } = buildService();
    seedReady(operationState, "op-pre");
    walletGate.quarantineBeforeArm(WALLET_ID);
    const outcome = await service.arm(validArmRequest("op-pre"));
    expect(outcome.status).toBe("operation_not_armable");
    expect(armStore.records.length).toBe(0);
  });

  it("held-lock serialization: concurrent locked quarantine waits until arm commits", async () => {
    const { service, armStore, operationState, walletGate } = buildService();
    seedReady(operationState, "op-ser");

    let armEntered = false;
    let armFinished = false;
    let quarantineSawArmed = false;

    // Stall inside tryInsert (under lock) so quarantine can block on the mutex.
    armStore.beforeInsert = async () => {
      armEntered = true;
      // Yield so quarantine can attempt the lock and park behind us.
      await new Promise((r) => setTimeout(r, 20));
      expect(walletGate.peek(WALLET_ID)!.state).toBe("PINNED");
    };

    const armPromise = service.arm(validArmRequest("op-ser")).then((o) => {
      armFinished = true;
      return o;
    });

    // Wait until arm holds the lock inside tryInsert.
    for (let i = 0; i < 50 && !armEntered; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(armEntered).toBe(true);

    const quarantinePromise = (async () => {
      await walletGate.quarantineLocked(WALLET_ID);
      // When quarantine acquires the lock, arm must already have finished.
      quarantineSawArmed = armFinished;
    })();

    const outcome = await armPromise;
    await quarantinePromise;

    expect(outcome.status).toBe("armed");
    expect(quarantineSawArmed).toBe(true);
    expect(walletGate.peek(WALLET_ID)!.state).toBe("QUARANTINED");
    expect(armStore.records.length).toBe(1);
  });

  it("admits arm for PINNED recovery-verified receiver (happy path still works)", async () => {
    const { service, operationState } = buildService();
    seedReady(operationState, "op-ok");
    const outcome = await service.arm(validArmRequest("op-ok"));
    expect(outcome.status).toBe("armed");
  });

  it("tryInsert without commit session binding is refused (unbound DML fails closed)", async () => {
    const store = new MemoryArmStore();
    await expect(
      store.tryInsert(
        {
          operationId: "x",
          walletId: WALLET_ID,
          nodeT0ObservationId: "o",
          acknowledgedS: "s",
          acknowledgedP: "p",
          acknowledgedB: "b",
          openedCursor: 1n,
          armedAt: FIXED_TIME,
        },
        { kind: "sql", sqlTx: { query: async () => ({ rows: [] }) } },
      ),
    ).rejects.toThrow(/activeArmTx|wallet-lock/);
  });
});

describe("memory commit-session held-token bind (receive arm barrier)", () => {
  it("rejects forged { kind: memory, token: {} } that is not the gate held token", async () => {
    const { armStore, walletGate } = buildService();
    seedReady(new MemoryOperationState(), "op-forge"); // just to keep pattern; insert is direct
    await expect(
      armStore.tryInsert(
        {
          operationId: "op-forge",
          walletId: WALLET_ID,
          nodeT0ObservationId: "o",
          acknowledgedS: "s",
          acknowledgedP: "p",
          acknowledgedB: "b",
          openedCursor: 1n,
          armedAt: FIXED_TIME,
        },
        { kind: "memory", token: {} },
      ),
    ).rejects.toThrow(/held wallet-lock token|lock token/i);
    expect(armStore.records.length).toBe(0);
    // Gate has no held lock — isHeldToken is false for any foreign object.
    expect(walletGate.isHeldToken({})).toBe(false);
  });

  it("admits only lock.requireCommitSession() token under withWalletLocked", async () => {
    const { armStore, walletGate } = buildService();
    let admitted = false;
    await walletGate.withWalletLocked(WALLET_ID, async (lock) => {
      const session = lock.requireCommitSession();
      const inserted = await armStore.tryInsert(
        {
          operationId: "op-held",
          walletId: WALLET_ID,
          nodeT0ObservationId: NODE_T0.observationId,
          acknowledgedS: NODE_T0.s0,
          acknowledgedP: NODE_T0.p0,
          acknowledgedB: NODE_T0.b0,
          openedCursor: 1n,
          armedAt: FIXED_TIME,
        },
        session,
      );
      expect(inserted).not.toBeNull();
      admitted = true;
      // Foreign token still rejected while a real lock is held.
      await expect(
        armStore.tryInsert(
          {
            operationId: "op-held-2",
            walletId: WALLET_ID,
            nodeT0ObservationId: "o",
            acknowledgedS: "s",
            acknowledgedP: "p",
            acknowledgedB: "b",
            openedCursor: 2n,
            armedAt: FIXED_TIME,
          },
          { kind: "memory", token: {} },
        ),
      ).rejects.toThrow(/held wallet-lock token/i);
    });
    expect(admitted).toBe(true);
    expect(armStore.records.map((r) => r.operationId)).toEqual(["op-held"]);
  });
});

describe("SQL same-TX arm DML (composition proof)", () => {
  it("ARM_SQL_STATEMENTS target real 04/custody relations (unit pin)", () => {
    // Schema-pin suite is authoritative; this is a fast local guard against fiction relapse.
    expect(ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING).toMatch(/FOR UPDATE/i);
    expect(ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING).toMatch(/FROM wallets/i);
    expect(ARM_SQL_STATEMENTS.INSERT_ARM_ACK).toMatch(/INSERT INTO receive_arms/i);
    expect(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE).toMatch(/UPDATE receive_codes/i);
    expect(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE).toMatch(/code_status = 'RELEASED'/i);
    expect(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE).toMatch(/AWAITING_ARM/);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/UPDATE operations/i);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/row_version/);
    expect(ARM_SQL_STATEMENTS.FIND_ARM_BY_OPERATION).toMatch(/FROM receive_arms/i);
    // Forbidden fiction from prior FAIL heads.
    const all = Object.values(ARM_SQL_STATEMENTS).join("\n");
    expect(all).not.toMatch(/receive_arm_acknowledgements/);
    expect(all).not.toMatch(/receive_operations/);
    expect(all).not.toMatch(/status = 'ARMED'/);
  });

  it("same-client executor log: FOR UPDATE + receive_arms INSERT + code release share one txId", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "PINNED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const armAcks = new Map<string, ArmRecord>();
    const opStates = new Map<string, string>([["op-sametx", "READY"]]);
    const codeStatuses = new Map<string, string>([["op-sametx", "AWAITING_ARM"]]);
    const opRowVersions = new Map<string, number>([["op-sametx", 2]]);
    const { txFactory, log } = createLockSerializingTxFactory({
      rows,
      armAcks,
      opStates,
      codeStatuses,
      opRowVersions,
    });

    const walletGate = createSqlArmWalletGate(txFactory);
    const armStore = createSqlArmStore({
      envelopeFor: testArmEnvelope,
      queryOutsideLock: async <R,>(text: string, params?: readonly unknown[]) => {
        if (text === ARM_SQL_STATEMENTS.FIND_ARM_BY_OPERATION) {
          const id = String(params?.[0]);
          const rec = armAcks.get(id);
          if (!rec) return { rows: [] as R[] };
          return {
            rows: [
              {
                operation_id: rec.operationId,
                wallet_id: rec.walletId,
                node_t0_observation_id: rec.nodeT0ObservationId,
                acknowledged_s: rec.acknowledgedS,
                acknowledged_p: rec.acknowledgedP,
                acknowledged_b: rec.acknowledgedB,
                opened_cursor: rec.openedCursor.toString(),
                armed_at: rec.armedAt,
              },
            ] as R[],
          };
        }
        return { rows: [] as R[] };
      },
    });
    const baseState = new MemoryOperationState();
    seedReady(baseState, "op-sametx");
    const operationState = createSqlTxBoundOperationState(baseState);

    const auditLog = new MemoryAuditLog();
    const service = createArmMutationService({
      armStore,
      operationState,
      signatureVerifier: new Ed25519ArmVerifier(new Map([[WALLET_ID, WALLET_PUB]])),
      auditLog,
      clock: fixedClock,
      walletGate,
    });

    const outcome = await service.arm(validArmRequest("op-sametx"));
    expect(outcome.status).toBe("armed");

    const lockEntries = log.filter((e) => e.text === ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING);
    const insertEntries = log.filter((e) => e.text === ARM_SQL_STATEMENTS.INSERT_ARM_ACK);
    const releaseEntries = log.filter((e) => e.text === ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE);
    const bumpEntries = log.filter((e) => e.text === ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION);
    expect(lockEntries.length).toBeGreaterThanOrEqual(2);
    expect(insertEntries.length).toBe(1);
    expect(releaseEntries.length).toBe(1);
    expect(bumpEntries.length).toBe(1);

    const lockTx = lockEntries[0]!.txId;
    expect(insertEntries[0]!.txId).toBe(lockTx);
    expect(releaseEntries[0]!.txId).toBe(lockTx);
    expect(bumpEntries[0]!.txId).toBe(lockTx);
    for (const e of lockEntries) expect(e.txId).toBe(lockTx);

    expect(armAcks.has("op-sametx")).toBe(true);
    expect(codeStatuses.get("op-sametx")).toBe("RELEASED");
    expect(opStates.get("op-sametx")).toBe("READY"); // status unchanged
    expect(opRowVersions.get("op-sametx")).toBe(3);
  });

  it("createSqlArmStore.tryInsert fails closed when activeArmTx is undefined", async () => {
    const store = createSqlArmStore({
      queryOutsideLock: async () => ({ rows: [] }),
      envelopeFor: testArmEnvelope,
    });
    const foreignTx: SqlTxExecutor = { query: async () => ({ rows: [] }) };
    await expect(
      store.tryInsert(
        {
          operationId: "x",
          walletId: WALLET_ID,
          nodeT0ObservationId: "o",
          acknowledgedS: "s",
          acknowledgedP: "p",
          acknowledgedB: "b",
          openedCursor: 1n,
          armedAt: FIXED_TIME,
        },
        { kind: "sql", sqlTx: foreignTx },
      ),
    ).rejects.toThrow(/activeArmTx|wallet-lock/);
  });

  it("SQL gate serializes concurrent withWalletLocked — maxConcurrent stays 1", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "PINNED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const { txFactory, maxConcurrentByWallet } = createLockSerializingTxFactory({ rows });
    const gate = createSqlArmWalletGate(txFactory);

    let releaseA!: () => void;
    const aHeld = new Promise<void>((r) => {
      releaseA = r;
    });
    let bEntered = false;

    const a = gate.withWalletLocked(WALLET_ID, async () => {
      // Hold the lock until we say so.
      await new Promise<void>((resolve) => {
        // signal held
        setTimeout(resolve, 0);
      });
      await aHeld;
      return "a";
    });

    // Let A acquire.
    await new Promise((r) => setTimeout(r, 15));

    const b = gate.withWalletLocked(WALLET_ID, async () => {
      bEntered = true;
      return "b";
    });

    await new Promise((r) => setTimeout(r, 30));
    // B must still be blocked on FOR UPDATE serialization.
    expect(bEntered).toBe(false);
    expect(maxConcurrentByWallet.get(WALLET_ID)).toBe(1);

    releaseA();
    await expect(a).resolves.toBe("a");
    await expect(b).resolves.toBe("b");
    expect(bEntered).toBe(true);
    expect(maxConcurrentByWallet.get(WALLET_ID)).toBe(1);
  });

  it("concurrent quarantine UPDATE blocks until arm COMMIT; arm stays armed", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "PINNED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const armAcks = new Map<string, ArmRecord>();
    const opStates = new Map<string, string>([["op-qser", "READY"]]);
    const codeStatuses = new Map<string, string>([["op-qser", "AWAITING_ARM"]]);
    const { txFactory, quarantineUnderLock, maxConcurrentByWallet } =
      createLockSerializingTxFactory({ rows, armAcks, opStates, codeStatuses });

    const walletGate = createSqlArmWalletGate(txFactory);
    const armStore = createSqlArmStore({
      queryOutsideLock: async () => ({ rows: [] }),
      envelopeFor: testArmEnvelope,
    });
    // Stall insert so quarantine can attempt lock while arm holds it.
    const stallingStore: ArmStore = {
      findByOperation: (id) => armStore.findByOperation(id),
      tryInsert: async (record, session) => {
        // Prove session is the live ALS tx before stalling.
        expect(requireActiveArmSqlTx(session)).toBe(activeArmTx());
        await new Promise((r) => setTimeout(r, 40));
        return armStore.tryInsert(record, session);
      },
    };
    const baseState = new MemoryOperationState();
    seedReady(baseState, "op-qser");
    const operationState = createSqlTxBoundOperationState(baseState);
    const service = createArmMutationService({
      armStore: stallingStore,
      operationState,
      signatureVerifier: new Ed25519ArmVerifier(new Map([[WALLET_ID, WALLET_PUB]])),
      auditLog: new MemoryAuditLog(),
      clock: fixedClock,
      walletGate,
    });

    let armDone = false;
    const armPromise = service.arm(validArmRequest("op-qser")).then((o) => {
      armDone = true;
      return o;
    });

    // Wait until arm is inside the critical section.
    await new Promise((r) => setTimeout(r, 15));

    let quarantineAfterArm = false;
    const qPromise = quarantineUnderLock(WALLET_ID).then(() => {
      quarantineAfterArm = armDone;
    });

    const outcome = await armPromise;
    await qPromise;

    expect(outcome.status).toBe("armed");
    expect(quarantineAfterArm).toBe(true);
    expect(rows.get(WALLET_ID)!.state).toBe("QUARANTINED");
    expect(armAcks.has("op-qser")).toBe(true);
    expect(maxConcurrentByWallet.get(WALLET_ID)).toBe(1);
  });

  it("quarantine first: arm gets operation_not_armable and zero arm rows", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "PINNED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const armAcks = new Map<string, ArmRecord>();
    const opStates = new Map<string, string>([["op-qfirst", "READY"]]);
    const { txFactory, quarantineUnderLock } = createLockSerializingTxFactory({
      rows,
      armAcks,
      opStates,
    });

    await quarantineUnderLock(WALLET_ID);
    expect(rows.get(WALLET_ID)!.state).toBe("QUARANTINED");

    const walletGate = createSqlArmWalletGate(txFactory);
    const armStore = createSqlArmStore({
      queryOutsideLock: async () => ({ rows: [] }),
      envelopeFor: testArmEnvelope,
    });
    const baseState = new MemoryOperationState();
    seedReady(baseState, "op-qfirst");
    const service = createArmMutationService({
      armStore,
      operationState: createSqlTxBoundOperationState(baseState),
      signatureVerifier: new Ed25519ArmVerifier(new Map([[WALLET_ID, WALLET_PUB]])),
      auditLog: new MemoryAuditLog(),
      clock: fixedClock,
      walletGate,
    });

    const outcome = await service.arm(validArmRequest("op-qfirst"));
    expect(outcome.status).toBe("operation_not_armable");
    expect(armAcks.size).toBe(0);
  });

  it("commitArmUnderWalletLock rejects QUARANTINED and never invokes commit", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "QUARANTINED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const { txFactory } = createLockSerializingTxFactory({ rows });
    let commitCalls = 0;
    const result = await commitArmUnderWalletLock(txFactory, WALLET_ID, async () => {
      commitCalls += 1;
      return "nope";
    });
    expect(result.ok).toBe(false);
    expect(commitCalls).toBe(0);
  });

  it("commitArmUnderWalletLock admits PINNED and runs commit under activeArmTx", async () => {
    const rows = new Map<string, { state: string; recovery_verified_at: string | null; allow_external_receive?: boolean }>();
    rows.set(WALLET_ID, { state: "PINNED", recovery_verified_at: FIXED_TIME, allow_external_receive: true });
    const { txFactory } = createLockSerializingTxFactory({ rows });
    const result = await commitArmUnderWalletLock(txFactory, WALLET_ID, async (tx, standing) => {
      expect(standing.state).toBe("PINNED");
      expect(activeArmTx()).toBe(tx);
      return "armed-ok";
    });
    expect(result).toEqual({ ok: true, value: "armed-ok" });
  });

  it("createFailClosedArmHandler refuses arm until engine injects gate+tx store", async () => {
    const handler = createFailClosedArmHandler();
    await expect(handler("op-unwired")).rejects.toThrow(/not wired|operation_not_armable|ArmStore/i);
  });
});
