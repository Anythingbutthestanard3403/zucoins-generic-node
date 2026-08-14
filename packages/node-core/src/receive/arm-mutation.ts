// Receive arm barrier.
//
// The arm commit window locks the receiver wallet row FOR UPDATE, rechecks recovery
// standing under that lock (live re-read immediately before insert), locks the operation
// row, requires READY + unexpired + expected_row_version, inserts the arm acknowledgement,
// releases the withheld code (AWAITING_ARM→RELEASED), and bumps operations.row_version in
// **one DB-TX**. Code bytes leave the node only after that commit
// Ports receive an ArmCommitSession issued by the held lock;
// tryInsert / transitionToArmed MUST bind DML to that session (SQL: same SqlTxExecutor
// as activeArmTx). A free-standing insert outside the lock TX is a TOCTOU defect.

export interface T0Projection {
  readonly observationId: string;
  readonly s0: string;
  readonly p0: string;
  readonly b0: string;
}

/** Success fields carried after a committed arm (state stays READY). */
export interface ArmReleasePayload {
  readonly transferCode: string;
  readonly transferCodeSha256: string;
  readonly expiresAt: string;
  readonly rowVersion: number;
}

export interface ArmRecord {
  readonly operationId: string;
  readonly walletId: string;
  readonly nodeT0ObservationId: string;
  readonly acknowledgedS: string;
  readonly acknowledgedP: string;
  readonly acknowledgedB: string;
  readonly openedCursor: bigint;
  readonly armedAt: string;
}

export type ArmOutcome =
  | {
      readonly status: "armed";
      readonly record: ArmRecord;
      readonly release: ArmReleasePayload;
    }
  | {
      readonly status: "already_armed";
      readonly record: ArmRecord;
      readonly release: ArmReleasePayload;
    }
  | { readonly status: "t0_mismatch"; readonly operationId: string; readonly field: string }
  | { readonly status: "invalid_signature"; readonly operationId: string }
  | {
      readonly status: "operation_version_conflict";
      readonly operationId: string;
      readonly currentRowVersion: number;
    }
  | {
      readonly status: "operation_not_armable";
      readonly operationId: string;
      readonly reason: string;
    }
  /**
   * armed called on a NODE_VERIFIED op (ZTR-1302). Code was auto-released at ready-commit;
   * consumer arm is not admitted. Idempotent: no state change, no attention row.
   */
  | {
      readonly status: "verification_mode_mismatch";
      readonly operationId: string;
    };

export interface ArmRequest {
  readonly operationId: string;
  readonly walletId: string;
  readonly nodeT0ObservationId: string;
  readonly acknowledgedS: string;
  readonly acknowledgedP: string;
  readonly acknowledgedB: string;
  readonly openedCursor: bigint;
  /** CAS — expected_row_version. */
  readonly expectedRowVersion: number;
  /**
   * Protocol-clock instant for the unexpired guard (unix ms). Compared to
   * durable expiry_unix_time_secs (whole seconds).
   */
  readonly nowMs: number;
  /**
   * Optional wallet-key signature over a local preimage. The live reporting path
   * authenticates via zp-report-request-v1 only and omits this; unit
   * fixtures that exercise the assigned-signer gate still supply it.
   */
  readonly signatureBytes?: Uint8Array;
  readonly preimageText?: string;
}

/**
 * Proof that arm DML is executing under the held wallet-row lock (receive arm barrier).
 * Issued only by `ArmWalletLockHandle.requireCommitSession` while the lock is held.
 * SQL sessions carry the same `SqlTxExecutor` that ran `SELECT … FOR UPDATE`.
 */
export type ArmCommitSession =
  | {
      readonly kind: "sql";
      /** Wallet-lock TX — MUST be identical to `activeArmTx` at DML time. */
      readonly sqlTx: ArmSqlTxRef;
    }
  | {
      readonly kind: "memory";
      /** Opaque token unique to the held lock epoch; stores refuse foreign tokens. */
      readonly token: object;
    };

/** Minimal TX surface so arm-mutation does not import arm-sql (cycle-free). */
export interface ArmSqlTxRef {
  query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export interface ArmStore {
  findByOperation(operationId: string): Promise<ArmRecord | null>;
  /**
   * Insert under the wallet-lock session. Implementations MUST refuse a session that
   * is not the held lock (SQL: `session.sqlTx === activeArmTx`).
   */
  tryInsert(record: ArmRecord, session: ArmCommitSession): Promise<ArmRecord | null>;
  /**
   * Load the already-released code for an idempotent re-arm.
   * Required once an arm row exists so retries return identical bytes.
   */
  loadReleasedCode?(operationId: string): Promise<ArmReleasePayload | null>;
}

/** Snapshot under the operation-row lock. */
export interface ArmOperationGateSnapshot {
  readonly state: string;
  readonly rowVersion: number;
  /** Whole-second decimal string from receive_codes / operations.expiry_unix_time_secs. */
  readonly expiryUnixTimeSecs: string;
  readonly receiverWalletId: string;
  readonly codeStatus: string;
  readonly transferCode: string;
  readonly transferCodeSha256: string;
}

export interface ArmOperationState {
  getState(operationId: string): Promise<string | null>;
  getAssignedWallet(operationId: string): Promise<string | null>;
  getT0(operationId: string): Promise<T0Projection | null>;
  /**
   * Frozen admission-time verification_mode. Optional for legacy unit fixtures —
   * absent/`undefined` is treated as INDEPENDENT (arm admitted). Live SQL ports MUST
   * return the durable column so NODE_VERIFIED arms 409 without mutation (ZTR-1302).
   */
  getVerificationMode?(operationId: string): Promise<"INDEPENDENT" | "NODE_VERIFIED" | null>;
  /**
   * Under the commit session: lock the operation (+ code) row and return the arm gate
   * snapshot. null when the operation is absent.
   */
  lockAndReadGate(
    operationId: string,
    session: ArmCommitSession,
  ): Promise<ArmOperationGateSnapshot | null>;
  /**
   * READY stays READY. Releases code AWAITING_ARM→RELEASED and CAS-bumps row_version
   * under the same wallet-lock session as tryInsert (one-TX).
   */
  transitionToArmed(
    operationId: string,
    session: ArmCommitSession,
    expectedRowVersion: number,
  ): Promise<
    | { readonly ok: true; readonly release: ArmReleasePayload }
    | { readonly ok: false; readonly reason: "version_conflict" | "not_armable" | "expired"; readonly currentRowVersion?: number }
  >;
  /**
   * failed arm-standing recheck: set attention and leave the wallet PINNED.
   * Optional so pure unit fixtures without attention storage still exercise the reject path.
   */
  markAttention?(operationId: string, reason: string): Promise<void>;
}

export interface ArmSignatureVerifier {
  verify(input: {
    readonly walletId: string;
    readonly preimageText: string;
    readonly signatureBytes: Uint8Array;
  }): Promise<boolean>;
}

export interface ArmAuditLog {
  append(entry: ArmAuditEntry): Promise<void>;
}

export interface ArmAuditEntry {
  readonly operationId: string;
  readonly walletId: string;
  readonly outcome: "ARMED" | "REJECTED";
  readonly rejectionReason?: string;
  readonly timestamp: string;
}

export interface ArmClock {
  now(): string;
}

/**
 * Wallet-row standing observed under `SELECT... FOR UPDATE` (receive arm barrier; receive-gate enforcement).
 * Arm recheck allowlist is {AVAILABLE, PINNED} — PINNED is the normal arm-time state.
 */
export type ArmWalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";

export interface ArmWalletStanding {
  readonly walletId: string;
  readonly recoveryVerifiedAt: string | null;
  readonly state: ArmWalletState;
  /** Money capability (ZTR-1268) — arm requires allow_external_receive. */
  readonly allowExternalReceive: boolean;
}

/**
 * Handle for the held wallet-row lock. `readStanding` re-reads the locked row so the
 * service never trusts a copy taken before an intervening await (TOCTOU close).
 * `requireCommitSession` is the only way to obtain a session accepted by arm DML ports.
 */
export interface ArmWalletLockHandle {
  readStanding(): Promise<ArmWalletStanding | null>;
  /**
   * Issue the commit session for this held lock. Throws if the lock is no longer held.
   * SQL gates bind the session to the FOR UPDATE transaction.
   */
  requireCommitSession(): ArmCommitSession;
}

/**
 * Holds the assigned receiver wallet row lock for the entire `body` callback.
 *
 * Production SQL implementations MUST open one DB-TX, `SELECT ... FOR UPDATE` the wallet
 * row, invoke `body`, and only COMMIT/ROLLBACK after `body` returns — so tryInsert +
 * READY→armed run on that same TX. A point-in-time lock that
 * releases before insert is a TOCTOU defect.
 */
export interface ArmWalletGate {
  withWalletLocked<T>(
    walletId: string,
    body: (lock: ArmWalletLockHandle) => Promise<T>,
  ): Promise<T>;
}

export interface ArmMutationService {
  arm(request: ArmRequest): Promise<ArmOutcome>;
}

const ARMABLE_STATE = "READY";

/** arm-time allowlist — positive, never a blocklist complement. */
const ARMABLE_WALLET_STATES: ReadonlySet<ArmWalletState> = new Set(["AVAILABLE", "PINNED"]);

export function isArmableWalletStanding(
  standing: ArmWalletStanding,
): { ok: true } | { ok: false; reason: string } {
  if (standing.recoveryVerifiedAt === null) {
    return { ok: false, reason: "receiver recovery_verified_at is null" };
  }
  if (!ARMABLE_WALLET_STATES.has(standing.state)) {
    return { ok: false, reason: `receiver wallet state ${standing.state} is not armable` };
  }
  if (standing.allowExternalReceive !== true) {
    return { ok: false, reason: "receiver allow_external_receive is false" };
  }
  return { ok: true };
}

/**
 * Fail-closed check used by SQL-bound ports: session must be the live wallet-lock TX.
 * `activeTx` is injected (typically `activeArmTx`) so arm-mutation stays free of arm-sql.
 */
export function assertSqlArmCommitSession(
  session: ArmCommitSession,
  activeTx: ArmSqlTxRef | undefined,
): ArmSqlTxRef {
  if (session.kind !== "sql") {
    throw new Error("SQL arm DML rejected a non-sql commit session");
  }
  if (activeTx === undefined) {
    throw new Error("arm DML outside withWalletLocked (no activeArmTx)");
  }
  if (session.sqlTx !== activeTx) {
    throw new Error("arm DML TX is not the held wallet-lock transaction");
  }
  return session.sqlTx;
}

/**
 * Fail-closed check for memory-bound ports: session token MUST be the live held
 * lock token published by MemoryWalletGate (identity equality). A forgeable
 * `{ kind: "memory", token: {} }` is not a receive arm barrier session proof.
 */
export function assertMemoryArmCommitSession(
  session: ArmCommitSession,
  isHeldToken: (token: object) => boolean,
): object {
  if (session.kind !== "memory") {
    throw new Error("memory arm DML rejected a non-memory commit session");
  }
  if (session.token === undefined || typeof session.token !== "object" || session.token === null) {
    throw new Error("memory arm DML missing lock token");
  }
  if (!isHeldToken(session.token)) {
    throw new Error("memory arm DML token is not the held wallet-lock token");
  }
  return session.token;
}

/** True when nowMs is strictly before the exclusive end of the whole-second expiry. */
export function isReceiveUnexpired(expiryUnixTimeSecs: string, nowMs: number): boolean {
  if (!/^[0-9]+$/.test(expiryUnixTimeSecs)) return false;
  const expiryMs = Number(expiryUnixTimeSecs) * 1000;
  if (!Number.isFinite(expiryMs)) return false;
  return nowMs < expiryMs;
}

/** RFC3339-ms projection of a whole-second expiry decimal string (same as READY 201 body). */
export function expiresAtFromUnixSecs(expiryUnixTimeSecs: string): string {
  return new Date(Number(expiryUnixTimeSecs) * 1000).toISOString();
}

/** Byte-stable success body (Byte-exact — key insertion ordering fixed). */
export function buildArmSuccessResponse(input: {
  readonly operationId: string;
  readonly release: ArmReleasePayload;
}): {
  readonly operation_id: string;
  readonly state: "READY";
  readonly row_version: number;
  readonly code_status: "RELEASED";
  readonly transfer_code: string;
  readonly transfer_code_sha256: string;
  readonly expires_at: string;
} {
  return {
    operation_id: input.operationId,
    state: "READY",
    row_version: input.release.rowVersion,
    code_status: "RELEASED",
    transfer_code: input.release.transferCode,
    transfer_code_sha256: input.release.transferCodeSha256,
    expires_at: input.release.expiresAt,
  };
}

export function createArmMutationService(deps: {
  readonly armStore: ArmStore;
  readonly operationState: ArmOperationState;
  readonly auditLog: ArmAuditLog;
  readonly clock: ArmClock;
  /** Required: fail-closed standing gate (wallet lock + recovery recheck). */
  readonly walletGate: ArmWalletGate;
  /** Optional: only consulted when the request carries signatureBytes + preimageText. */
  readonly signatureVerifier?: ArmSignatureVerifier;
}): ArmMutationService {
  const { armStore, operationState, signatureVerifier, auditLog, clock, walletGate } = deps;
  return {
    async arm(request: ArmRequest): Promise<ArmOutcome> {
      const { operationId, walletId } = request;

      // NODE_VERIFIED refuses arm before any mutation (ZTR-1302 AC3). Idempotent: no
      // arm row, no code status flip, no attention. Checked before already_armed so a
      // NODE_VERIFIED op never serves code via the arm surface even if a stale arm row
      // somehow exists (should not — ready-commit auto-releases without arming).
      if (operationState.getVerificationMode !== undefined) {
        const mode = await operationState.getVerificationMode(operationId);
        if (mode === "NODE_VERIFIED") {
          return { status: "verification_mode_mismatch", operationId };
        }
      }

      // Idempotent pre-check (outside lock). Under lock we re-tryInsert and re-load.
      const existing = await armStore.findByOperation(operationId);
      if (existing !== null) {
        const release = await loadReleaseForExisting(armStore, operationState, existing, request);
        if (release === null) {
          return {
            status: "operation_not_armable",
            operationId,
            reason: "arm row exists but released code is unavailable",
          };
        }
        return { status: "already_armed", record: existing, release };
      }

      const state = await operationState.getState(operationId);
      if (state === null) {
        return { status: "operation_not_armable", operationId, reason: "operation not found" };
      }
      if (state !== ARMABLE_STATE) {
        return {
          status: "operation_not_armable",
          operationId,
          reason: `operation is in state ${state}, expected ${ARMABLE_STATE}`,
        };
      }

      const assignedWallet = await operationState.getAssignedWallet(operationId);
      if (assignedWallet === null) {
        return {
          status: "operation_not_armable",
          operationId,
          reason: "operation has no assigned wallet",
        };
      }
      if (assignedWallet !== walletId) {
        await auditLog.append({
          operationId,
          walletId,
          outcome: "REJECTED",
          rejectionReason: `wallet ${walletId} is not the assigned wallet`,
          timestamp: clock.now(),
        });
        return {
          status: "operation_not_armable",
          operationId,
          reason: "wallet is not assigned to this operation",
        };
      }

      if (request.signatureBytes !== undefined || request.preimageText !== undefined) {
        if (
          signatureVerifier === undefined ||
          request.signatureBytes === undefined ||
          request.preimageText === undefined
        ) {
          return { status: "invalid_signature", operationId };
        }
        const signatureValid = await signatureVerifier.verify({
          walletId,
          preimageText: request.preimageText,
          signatureBytes: request.signatureBytes,
        });
        if (!signatureValid) {
          await auditLog.append({
            operationId,
            walletId,
            outcome: "REJECTED",
            rejectionReason: "signature verification failed",
            timestamp: clock.now(),
          });
          return { status: "invalid_signature", operationId };
        }
      }

      const nodeT0 = await operationState.getT0(operationId);
      if (nodeT0 === null) {
        return {
          status: "operation_not_armable",
          operationId,
          reason: "operation has no T0 record",
        };
      }

      const mismatchField = compareT0(nodeT0, request);
      if (mismatchField !== null) {
        await auditLog.append({
          operationId,
          walletId,
          outcome: "REJECTED",
          rejectionReason: `t0_mismatch on ${mismatchField}`,
          timestamp: clock.now(),
        });
        return { status: "t0_mismatch", operationId, field: mismatchField };
      }

      // lock spans standing recheck + op lock + arm insert + code release.
      return walletGate.withWalletLocked(walletId, async (lock) => {
        const rejectIfUnarmable = async (
          standing: ArmWalletStanding | null,
        ): Promise<ArmOutcome | null> => {
          if (standing === null) {
            const reason = "assigned wallet not found";
            await rejectStanding(operationState, auditLog, clock, operationId, walletId, reason);
            return { status: "operation_not_armable", operationId, reason };
          }
          const standingCheck = isArmableWalletStanding(standing);
          if (!standingCheck.ok) {
            await rejectStanding(
              operationState,
              auditLog,
              clock,
              operationId,
              walletId,
              standingCheck.reason,
            );
            return {
              status: "operation_not_armable",
              operationId,
              reason: standingCheck.reason,
            };
          }
          return null;
        };

        const early = await rejectIfUnarmable(await lock.readStanding());
        if (early !== null) return early;

        const now = clock.now();
        const record: ArmRecord = {
          operationId,
          walletId,
          nodeT0ObservationId: request.nodeT0ObservationId,
          acknowledgedS: request.acknowledgedS,
          acknowledgedP: request.acknowledgedP,
          acknowledgedB: request.acknowledgedB,
          openedCursor: request.openedCursor,
          armedAt: now,
        };

        // Live re-read under the still-held lock immediately before code-releasing DML.
        const preInsert = await rejectIfUnarmable(await lock.readStanding());
        if (preInsert !== null) return preInsert;

        const session = lock.requireCommitSession();

        const gate = await operationState.lockAndReadGate(operationId, session);
        if (gate === null) {
          return {
            status: "operation_not_armable",
            operationId,
            reason: "operation not found under lock",
          };
        }
        if (gate.state !== ARMABLE_STATE) {
          return {
            status: "operation_not_armable",
            operationId,
            reason: `operation is in state ${gate.state}, expected ${ARMABLE_STATE}`,
          };
        }
        if (gate.receiverWalletId !== walletId) {
          return {
            status: "operation_not_armable",
            operationId,
            reason: "wallet is not assigned to this operation",
          };
        }
        if (gate.codeStatus === "RELEASED") {
          // Lost race with a concurrent arm that committed between pre-check and lock.
          const release: ArmReleasePayload = {
            transferCode: gate.transferCode,
            transferCodeSha256: gate.transferCodeSha256,
            expiresAt: expiresAtFromUnixSecs(gate.expiryUnixTimeSecs),
            rowVersion: gate.rowVersion,
          };
          const winner = (await armStore.findByOperation(operationId)) ?? record;
          return { status: "already_armed", record: winner, release };
        }
        if (gate.codeStatus !== "AWAITING_ARM") {
          return {
            status: "operation_not_armable",
            operationId,
            reason: `code_status ${gate.codeStatus} is not armable`,
          };
        }
        if (!isReceiveUnexpired(gate.expiryUnixTimeSecs, request.nowMs)) {
          return {
            status: "operation_not_armable",
            operationId,
            reason: "receive code expired",
          };
        }
        if (gate.rowVersion !== request.expectedRowVersion) {
          return {
            status: "operation_version_conflict",
            operationId,
            currentRowVersion: gate.rowVersion,
          };
        }

        const persisted = await armStore.tryInsert(record, session);
        if (persisted === null) {
          const winner = await armStore.findByOperation(operationId);
          if (winner === null) {
            return {
              status: "operation_not_armable",
              operationId,
              reason: "arm insert lost race and no arm row is visible",
            };
          }
          const release = await loadReleaseForExisting(armStore, operationState, winner, request);
          if (release === null) {
            // Concurrent winner may still be mid-commit; surface as not armable rather than
            // leaking a partial code.
            return {
              status: "operation_not_armable",
              operationId,
              reason: "concurrent arm in progress",
            };
          }
          return { status: "already_armed", record: winner, release };
        }

        const transitioned = await operationState.transitionToArmed(
          operationId,
          session,
          request.expectedRowVersion,
        );
        if (!transitioned.ok) {
          if (transitioned.reason === "version_conflict") {
            return {
              status: "operation_version_conflict",
              operationId,
              currentRowVersion: transitioned.currentRowVersion ?? gate.rowVersion,
            };
          }
          return {
            status: "operation_not_armable",
            operationId,
            reason:
              transitioned.reason === "expired"
                ? "receive code expired"
                : "operation not armable at commit",
          };
        }

        await auditLog.append({ operationId, walletId, outcome: "ARMED", timestamp: now });
        return { status: "armed", record: persisted, release: transitioned.release };
      });
    },
  };
}

async function loadReleaseForExisting(
  armStore: ArmStore,
  operationState: ArmOperationState,
  record: ArmRecord,
  request: ArmRequest,
): Promise<ArmReleasePayload | null> {
  if (armStore.loadReleasedCode !== undefined) {
    const loaded = await armStore.loadReleasedCode(record.operationId);
    if (loaded !== null) return loaded;
  }
  // Fall back: re-lock path is unavailable outside the wallet gate; callers that need
  // already_armed without loadReleasedCode must implement the port.
  void operationState;
  void request;
  return null;
}

async function rejectStanding(
  operationState: ArmOperationState,
  auditLog: ArmAuditLog,
  clock: ArmClock,
  operationId: string,
  walletId: string,
  reason: string,
): Promise<void> {
  await auditLog.append({
    operationId,
    walletId,
    outcome: "REJECTED",
    rejectionReason: reason,
    timestamp: clock.now(),
  });
  if (operationState.markAttention !== undefined) {
    await operationState.markAttention(operationId, reason);
  }
}

function compareT0(nodeT0: T0Projection, request: ArmRequest): string | null {
  if (request.nodeT0ObservationId !== nodeT0.observationId) return "observationId";
  if (request.acknowledgedS !== nodeT0.s0) return "S0";
  if (request.acknowledgedP !== nodeT0.p0) return "P0";
  if (request.acknowledgedB !== nodeT0.b0) return "B0";
  return null;
}
