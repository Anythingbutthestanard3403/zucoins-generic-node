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
  await moneyGates.assertWalletMaySign(capability.walletId);

  const rejection = await validateLease(deps.leaseReader, capability);
  if (rejection !== null) {
    await deps.auditLog.append({
      walletId: capability.walletId,
      operationId: capability.operationId,
      leaseEpoch: capability.leaseEpoch,
      purpose: capability.purpose,
      preimageSha256: capability.expectedPreimageSha256,
      outcome: "REJECTED",
      rejectionReason: rejection,
      timestamp: now(),
    });
    throw new SignerBoundaryError(rejection, rejectionCode(rejection));
  }

  const computedDigest = sha256Hex(capability.preimageText);
  if (computedDigest !== capability.expectedPreimageSha256) {
    const reason = "preimage digest mismatch";
    await deps.auditLog.append({
      walletId: capability.walletId,
      operationId: capability.operationId,
      leaseEpoch: capability.leaseEpoch,
      purpose: capability.purpose,
      preimageSha256: capability.expectedPreimageSha256,
      outcome: "REJECTED",
      rejectionReason: reason,
      timestamp: now(),
    });
    throw new SignerBoundaryError(reason, "PREIMAGE_DIGEST_MISMATCH");
  }

  const preimageBytes = new TextEncoder().encode(capability.preimageText);
  const signature = await deps.vaultSigner.sign(capability.walletId, preimageBytes);

  await deps.auditLog.append({
    walletId: capability.walletId,
    operationId: capability.operationId,
    leaseEpoch: capability.leaseEpoch,
    purpose: capability.purpose,
    preimageSha256: computedDigest,
    outcome: "SIGNED",
    timestamp: now(),
  });

  return Object.freeze({ signature, preimageSha256: computedDigest });
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
  return "ROLE_NOT_PERMITTED";
}
