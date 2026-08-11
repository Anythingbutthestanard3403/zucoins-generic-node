import { createHash } from "node:crypto";
import type { LeaseRole } from "@zucoins/generic-node-contracts/wallet-state";

// Money-path purpose closed set (exact-literal membership). No recovery-lane
// purpose may enter this set. Comparison is byte-identical — no trim, case-fold, or
// Unicode normalization, and no multi-purpose fallback verifier.
export const SIGNING_PURPOSES = ["SPLITCHAIN_STEP_1", "SPLITCHAIN_STEP_2"] as const;

export type SigningPurpose = (typeof SIGNING_PURPOSES)[number];

// The capability shape, parameterised by purpose so a non-money lane (the recovery
// probe) can route through this exact boundary instead of forking a parallel signer, WITHOUT
// widening the money-path union below.
export type SigningCapabilityOf<P extends string> = {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly purpose: P;
  readonly preimageText: string;
  readonly expectedPreimageSha256: string;
};

// The money-path capability. Its purpose union is UNCHANGED and stays exactly the two
// SplitChain steps — no recovery-lane purpose may ever enter it (generic-node-contracts
// RECOVERY_PROBE_IS_NOT_MONEY_PATH.in_wallet_signing_capability_union).
export type WalletSigningCapability = SigningCapabilityOf<SigningPurpose>;

/**
 * The money-path signer rule: exact-literal purpose comparison, performed before
 * leadership, lease, or vault. Throws on any value that is not byte-identical to one of the two
 * admissible SplitChain purposes. The presented value is carried on the error but never
 * interpolated into a message (so attacker-controlled purpose bytes never land in logs).
 */
export class UnknownSigningPurposeError extends Error {
  constructor(readonly presented: string) {
    super("unknown signing purpose");
    this.name = "UnknownSigningPurposeError";
  }
}

export function assertExactSigningPurpose(presented: string): SigningPurpose {
  for (const purpose of SIGNING_PURPOSES) {
    if (presented === purpose) return purpose;
  }
  throw new UnknownSigningPurposeError(presented);
}

export type ActiveLeaseRecord = {
  readonly walletId: string;
  readonly operationId: string;
  readonly epoch: bigint;
  readonly role: LeaseRole;
  readonly lifecycle: "ACTIVE" | "RELEASED";
};

export type SigningResult = {
  readonly signature: string;
  readonly preimageSha256: string;
};

export type SignerAuditEntryOf<P extends string> = {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly purpose: P;
  readonly preimageSha256: string;
  readonly outcome: "SIGNED" | "REJECTED";
  readonly rejectionReason?: string;
  readonly timestamp: string;
};

export type SignerAuditEntry = SignerAuditEntryOf<SigningPurpose>;

export interface LeaseReader {
  readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null>;
}

/**
 * Ports bound to one pinned-client transaction for the lease-lock critical section.
 * Production money-path wiring supplies these via {@link SignerBoundaryDepsOf.withSignTransaction}
 * so `FOR UPDATE` on `wallet_active_leases` stays held across vault sign and the SIGNED audit
 * append (ZTR-1160).
 */
export type SignUnderLeaseTxPortsOf<P extends string> = {
  readonly leaseReader: LeaseReader;
  readonly auditLog: SignerAuditLogOf<P>;
  /**
   * Optional wallet-state re-read under the same transaction that holds the lease
   * FOR UPDATE (ZTR-1171). When present, runLockedSignSection refuses QUARANTINED /
   * RETIRED / signing-halted wallets after the lease check and before vault open.
   * Production money-path wiring supplies this; recovery harnesses may omit it.
   */
  readonly assertWalletMaySign?: (walletId: string) => void | Promise<void>;
};

export type SignUnderLeaseTxPorts = SignUnderLeaseTxPortsOf<SigningPurpose>;

/**
 * Runs `body` inside one DB transaction on a pinned client. The body must not throw to
 * report a lease/digest rejection — return a value and throw after commit so REJECTED audit
 * rows are not rolled back with the lock transaction.
 */
export type SignUnderLeaseTransactionFnOf<P extends string> = <T>(
  body: (tx: SignUnderLeaseTxPortsOf<P>) => Promise<T>,
) => Promise<T>;

export type SignUnderLeaseTransactionFn = SignUnderLeaseTransactionFnOf<SigningPurpose>;

export interface VaultSigner {
  sign(walletId: string, preimageBytes: Uint8Array): Promise<string>;
}

// Process-wide signer leadership, as a port: `core` may not depend on `workers`, and this
// boundary needs only the non-secret boolean the acquisition module already exposes, so the
// `workers` SignerLeadership latch satisfies this structurally. No key material (the key-custody rule).
export interface SignerLeadershipLatch {
  readonly held: boolean;
  readonly reason?: string;
  /**
   * Optional flush bridge (custody claim boundary). When present, {@link signUnderLease}
   * always registers the in-flight body so leadership release cannot race a
   * mid-sign. Plain `{ held: true }` test doubles omit it; the real
   * {@link SignerLeadership} latch installs the bridge via the shutdown registry.
   */
  trackSigningInflight?(work: Promise<unknown>): void;
}

/** Thrown by a signing seam asked to sign while this process is not the leader. */
export class NotSignerLeaderError extends Error {
  constructor(reason?: string) {
    super(`node does not hold signer leadership${reason === undefined ? "" : `: ${reason}`}`);
    this.name = "NotSignerLeaderError";
  }
}

/** Refuse before the seam reads a lease, writes an audit row, or reaches the vault. */
export function assertSignerLeadership(latch: SignerLeadershipLatch): void {
  if (!latch.held) throw new NotSignerLeaderError(latch.reason);
}

export interface SignerAuditLogOf<P extends string> {
  append(entry: SignerAuditEntryOf<P>): Promise<void>;
}

export type SignerAuditLog = SignerAuditLogOf<SigningPurpose>;

export class SignerBoundaryError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "NO_LEASE"
      | "LEASE_RELEASED"
      | "WALLET_MISMATCH"
      | "OPERATION_MISMATCH"
      | "EPOCH_MISMATCH"
      | "ROLE_NOT_PERMITTED"
      | "PREIMAGE_DIGEST_MISMATCH",
  ) {
    super(message);
    this.name = "SignerBoundaryError";
  }
}

// Every wallet signing action — receive co-sign, internal move step 1, internal move
// step 2, external send step 1, recovery completion — uses the single wallet_active_leases
// table. Each of those actions is a role on ONE side of the SplitChain pair, so the permitted
// set is per SplitChain step, not a flat list: a lease held to originate value may not sign the
// receiving step, and vice versa. RECONCILIATION appears in both because recovery completion
// re-signs whichever step the crashed attempt left unsigned.
//
// MOVE_DESTINATION enters here with — it is the lease acquire-leases.ts
// puts on the destination wallet, and step 7 signs step 2 under exactly that
// capability. It is the structural twin of RECEIVE_WINDOW's step-2 co-sign, and was absent only
// because MOVE step-2 signing did not exist yet. It stays refused for step 1.
const ROLES_BY_SIGNING_PURPOSE: Readonly<Record<SigningPurpose, ReadonlySet<LeaseRole>>> = {
  SPLITCHAIN_STEP_1: new Set(["SEND_SOURCE", "MOVE_SOURCE", "RECONCILIATION"]),
  SPLITCHAIN_STEP_2: new Set(["RECEIVE_WINDOW", "MOVE_DESTINATION", "RECONCILIATION"]),
};

/**
 * The recovery probe routes a non-money purpose through this same boundary. It is not a
 * SplitChain step, so it has no step-scoped set; it falls back to the union — every role that
 * may sign anything — and is still gated on wallet / operation / epoch like every other call.
 */
const ANY_SIGNING_ROLE: ReadonlySet<LeaseRole> = new Set([
  ...ROLES_BY_SIGNING_PURPOSE.SPLITCHAIN_STEP_1,
  ...ROLES_BY_SIGNING_PURPOSE.SPLITCHAIN_STEP_2,
]);

function permittedRolesFor(purpose: string): ReadonlySet<LeaseRole> {
  return (SIGNING_PURPOSES as readonly string[]).includes(purpose)
    ? ROLES_BY_SIGNING_PURPOSE[purpose as SigningPurpose]
    : ANY_SIGNING_ROLE;
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export type MoneyPathSignerGates = {
  readonly assertMoneyAdmitted: () => void;
  readonly assertCanOperate: () => void;
  readonly assertWalletMaySign: (walletId: string) => void | Promise<void>;
};

export interface SignerBoundaryDepsOf<P extends string> {
  readonly leadership: SignerLeadershipLatch;
  readonly leaseReader: LeaseReader;
  readonly vaultSigner: VaultSigner;
  readonly auditLog: SignerAuditLogOf<P>;
  readonly now?: () => string;
  readonly assertMoneyAdmitted: () => void;
  readonly assertCanOperate: () => void;
  readonly assertWalletMaySign: (walletId: string) => void | Promise<void>;
  /**
   * Optional transaction scope for the lease-lock critical section (ZTR-1160).
   * When present, lease `FOR UPDATE`, vault sign, and audit append run on one pinned
   * client; COMMIT releases the row lock. Production money-path wirings MUST supply this.
   * Recovery / in-memory harnesses omit it and use {@link leaseReader} + {@link auditLog} directly.
   */
  readonly withSignTransaction?: SignUnderLeaseTransactionFnOf<P>;
}

/** Wallet is signing-halted or quarantined — refuse before lease read / vault. */
export class WalletSigningHaltedError extends Error {
  constructor(readonly walletId: string) {
    super(`wallet signing halted: ${walletId}`);
    this.name = "WalletSigningHaltedError";
  }
}

/** Money-path sign attempted without required admission / operate / quarantine ports. */
export class MoneyPathGatesMissingError extends Error {
  constructor(readonly gate: keyof MoneyPathSignerGates) {
    super(`money-path signUnderLease missing required gate: ${gate}`);
    this.name = "MoneyPathGatesMissingError";
  }
}

function requireMoneyPathGates<P extends string>(
  deps: SignerBoundaryDepsOf<P>,
): MoneyPathSignerGates {
  if (typeof deps.assertMoneyAdmitted !== "function") {
    throw new MoneyPathGatesMissingError("assertMoneyAdmitted");
  }
  if (typeof deps.assertCanOperate !== "function") {
    throw new MoneyPathGatesMissingError("assertCanOperate");
  }
  if (typeof deps.assertWalletMaySign !== "function") {
    throw new MoneyPathGatesMissingError("assertWalletMaySign");
  }
  return {
    assertMoneyAdmitted: deps.assertMoneyAdmitted,
    assertCanOperate: deps.assertCanOperate,
    assertWalletMaySign: deps.assertWalletMaySign,
  };
}

export type SignerBoundaryDeps = SignerBoundaryDepsOf<SigningPurpose>;

async function validateLease<P extends string>(
  leaseReader: LeaseReader,
  capability: SigningCapabilityOf<P>,
): Promise<string | null> {
  const lease = await leaseReader.readActiveLease(capability.walletId);

  if (lease === null) {
    return "no active lease for wallet";
  }
  if (lease.lifecycle !== "ACTIVE") {
    return "lease is released";
  }
  if (lease.walletId !== capability.walletId) {
    return "wallet mismatch";
  }
  if (lease.operationId !== capability.operationId) {
    return "operation mismatch";
  }
  if (lease.epoch !== capability.leaseEpoch) {
    return "lease epoch mismatch";
  }
  if (!permittedRolesFor(capability.purpose).has(lease.role)) {
    return "lease role not permitted for signing";
  }
  return null;
}

/** Outcome of the locked critical section — thrown rejections surface only AFTER commit. */
type LockedSignOutcome =
  | { readonly kind: "signed"; readonly result: SigningResult }
  | { readonly kind: "rejected"; readonly reason: string };

async function runLockedSignSection<P extends string>(
  ports: SignUnderLeaseTxPortsOf<P>,
  vaultSigner: VaultSigner,
  capability: SigningCapabilityOf<P>,
  now: () => string,
): Promise<LockedSignOutcome> {
  const rejection = await validateLease(ports.leaseReader, capability);
  if (rejection !== null) {
    await ports.auditLog.append({
      walletId: capability.walletId,
      operationId: capability.operationId,
      leaseEpoch: capability.leaseEpoch,
      purpose: capability.purpose,
      preimageSha256: capability.expectedPreimageSha256,
      outcome: "REJECTED",
      rejectionReason: rejection,
      timestamp: now(),
    });
    return { kind: "rejected", reason: rejection };
  }

  // ZTR-1171: re-check wallet state inside the lease-lock transaction so a wallet
  // quarantined after lease acquisition cannot still be signed from. Prefer the
  // transaction-scoped port when present; outer assertWalletMaySign runs earlier
  // for money-path leadership/admission ordering and for harnesses without a TX.
  if (ports.assertWalletMaySign !== undefined) {
    try {
      await ports.assertWalletMaySign(capability.walletId);
    } catch (err) {
      const reason =
        err instanceof WalletSigningHaltedError
          ? `wallet signing halted: ${err.walletId}`
          : err instanceof Error
            ? err.message
            : "wallet may not sign";
      await ports.auditLog.append({
        walletId: capability.walletId,
        operationId: capability.operationId,
        leaseEpoch: capability.leaseEpoch,
        purpose: capability.purpose,
        preimageSha256: capability.expectedPreimageSha256,
        outcome: "REJECTED",
        rejectionReason: reason,
        timestamp: now(),
      });
      return { kind: "rejected", reason };
    }
  }

  const computedDigest = sha256Hex(capability.preimageText);
  if (computedDigest !== capability.expectedPreimageSha256) {
    const reason = "preimage digest mismatch";
    await ports.auditLog.append({
      walletId: capability.walletId,
      operationId: capability.operationId,
      leaseEpoch: capability.leaseEpoch,
      purpose: capability.purpose,
      preimageSha256: capability.expectedPreimageSha256,
      outcome: "REJECTED",
      rejectionReason: reason,
      timestamp: now(),
    });
    return { kind: "rejected", reason };
  }

  const preimageBytes = new TextEncoder().encode(capability.preimageText);
  const signature = await vaultSigner.sign(capability.walletId, preimageBytes);

  await ports.auditLog.append({
    walletId: capability.walletId,
    operationId: capability.operationId,
    leaseEpoch: capability.leaseEpoch,
    purpose: capability.purpose,
    preimageSha256: computedDigest,
    outcome: "SIGNED",
    timestamp: now(),
  });

  return {
    kind: "signed",
    result: Object.freeze({ signature, preimageSha256: computedDigest }),
  };
}

// The single signing enforcement path: re-read the current lease row, require an exact
// wallet / operation / epoch / permitted-role match, recompute the preimage digest, sign, audit.
// Purpose is opaque here so the recovery probe runs THIS code rather than a parallel
// restore-only signer. It returns only the signature and digest; it never returns or logs a key.
export function signUnderLease<P extends string>(
  deps: SignerBoundaryDepsOf<P>,
  capability: SigningCapabilityOf<P>,
): Promise<SigningResult> {
  // Process exclusivity before anything else. A session advisory lock is connection-scoped, so
  // once this node loses it the lock is already free server-side and another instance may be
  // signing this instant — a node that is not the leader must not even read a lease.
  // Throws synchronously (same as money-gate miss) so expect( => signUnderLease).toThrow works.
  assertSignerLeadership(deps.leadership);

  // Money admission / storage operate: refuse NEW money work before lease read or vault.
  // Money paths ALWAYS require the three gates (fail-closed); missing gate throws immediately.
  // Recovery probe and internal callers supply gates with appropriate behaviour.
  const moneyGates = requireMoneyPathGates(deps);
  moneyGates.assertMoneyAdmitted();
  moneyGates.assertCanOperate();

  // Body is a distinct promise so the flush bridge observes the full mid-sign
  // window (lease read → vault → audit), not only a post-await tail. custody claim boundary:
  // inflight_signing_completes_before_leadership_release — non-opt-in.
  const body = signUnderLeaseBody(deps, capability, moneyGates);
  deps.leadership.trackSigningInflight?.(body);
  return body;
}

async function signUnderLeaseBody<P extends string>(
  deps: SignerBoundaryDepsOf<P>,
  capability: SigningCapabilityOf<P>,
  moneyGates: MoneyPathSignerGates,
): Promise<SigningResult> {
  const now = deps.now ?? (() => new Date().toISOString());

  // Per-wallet quarantine (anomaly action). Runs inside the body so the
  // flush bridge still covers the full mid-sign window when the gate awaits I/O.
  // Ordering (unchanged): leadership → money gates → quarantine → lease → digest → vault → audit.
  await moneyGates.assertWalletMaySign(capability.walletId);

  // Transaction-scoped path (production): lease FOR UPDATE + sign + audit on one pinned client.
  // Outcome is returned (not thrown) so REJECTED audit rows commit with the lock release —
  // throwing inside withSignTransaction would ROLLBACK the audit append.
  const withTx = deps.withSignTransaction;
  const outcome: LockedSignOutcome =
    withTx !== undefined
      ? await withTx((tx) => runLockedSignSection(tx, deps.vaultSigner, capability, now))
      : await runLockedSignSection(
          { leaseReader: deps.leaseReader, auditLog: deps.auditLog },
          deps.vaultSigner,
          capability,
          now,
        );

  if (outcome.kind === "rejected") {
    throw new SignerBoundaryError(outcome.reason, rejectionCode(outcome.reason));
  }
  return outcome.result;
}

export class LeaseSignerBoundary {
  private readonly deps: SignerBoundaryDeps;
  // Per-wallet in-process queue: concurrent money-path signs against one wallet serialize
  // rather than race into a double-sign. Failure of one call never blocks the next.
  private readonly walletQueues = new Map<string, Promise<unknown>>();

  constructor(deps: SignerBoundaryDeps) {
    this.deps = deps;
  }

  async sign(capability: WalletSigningCapability): Promise<SigningResult> {
    // Purpose first: reject unknown literals before leadership / lease / vault.
    assertExactSigningPurpose(capability.purpose);

    const walletId = capability.walletId;
    const prior = this.walletQueues.get(walletId) ?? Promise.resolve();
    const next = prior
      .catch(() => undefined)
      .then(() => signUnderLease(this.deps, capability));
    this.walletQueues.set(
      walletId,
      next.then(
        () => undefined,
        () => undefined,
      ),
    );
    return next;
  }
}

function rejectionCode(reason: string): SignerBoundaryError["code"] {
  if (reason.includes("no active lease")) return "NO_LEASE";
  if (reason.includes("released")) return "LEASE_RELEASED";
  if (reason.includes("wallet mismatch")) return "WALLET_MISMATCH";
  if (reason.includes("operation mismatch")) return "OPERATION_MISMATCH";
  if (reason.includes("epoch")) return "EPOCH_MISMATCH";
  if (reason.includes("preimage digest")) return "PREIMAGE_DIGEST_MISMATCH";
  return "ROLE_NOT_PERMITTED";
}
