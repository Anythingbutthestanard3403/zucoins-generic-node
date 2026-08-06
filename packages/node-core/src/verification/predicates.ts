// pure decision layer for the verification-complete barrier.
//
//
// The one-in-flight-per-wallet rule lives here: a wallet leaves its lease only when the whole lease group is
// covered by positive proof. Every function in this module is total and side-effect free, so
// the release decision is assertable without a database and cannot depend on wall-clock,
// heartbeat expiry, process liveness, or deployment state — none of which release a lease.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

/** The `evidence_role` CHECK — the closed set the evidence table accepts. No fourth token. */
export const ACK_EVIDENCE_ROLES = ["SOURCE", "RECEIVER", "DESTINATION"] as const;
export type AckEvidenceRole = (typeof ACK_EVIDENCE_ROLES)[number];

/** `verdict verification_verdict NOT NULL CHECK (verdict <> 'PENDING')`. */
export const ACK_VERDICTS = ["VERIFIED", "REJECTED", "INDETERMINATE"] as const;
export type AckVerdict = (typeof ACK_VERDICTS)[number];

/** `lease_release_status`. Derived per request; never a stored column. */
export const LEASE_RELEASE_STATUSES = [
  "RELEASED",
  "PINNED_GROUP_PENDING",
  "PINNED_FOR_ATTENTION",
] as const;
export type LeaseReleaseStatus = (typeof LEASE_RELEASE_STATUSES)[number];

/**
 * Receive requires receiver evidence, move requires source and destination evidence,
 * and send requires source plus destination/counterparty evidence as defined by the flow.
 * An external send's counterparty is its destination address, which occupies the DESTINATION
 * role — the CHECK admits no separate counterparty token.
 */
export const REQUIRED_EVIDENCE_ROLES: Readonly<
  Record<OperationKind, readonly AckEvidenceRole[]>
> = {
  RECEIVE_EXTERNAL: ["RECEIVER"],
  MOVE_INTERNAL: ["SOURCE", "DESTINATION"],
  SEND_EXTERNAL: ["SOURCE", "DESTINATION"],
};

export function isAckEvidenceRole(value: string): value is AckEvidenceRole {
  return (ACK_EVIDENCE_ROLES as readonly string[]).includes(value);
}

export function isAckVerdict(value: string): value is AckVerdict {
  return (ACK_VERDICTS as readonly string[]).includes(value);
}

/**
 * One durable wallet assignment for a role on the operation. Built from `operations` columns
 * (and the destination→wallet join for internal moves). `walletId` is null only for an
 * external counterparty (SEND DESTINATION = `destination_address`); the public key is always
 * the chain identity that evidence must name.
 */
export interface OperationWalletAssignment {
  readonly role: AckEvidenceRole;
  readonly walletId: string | null;
  readonly walletPublicKey: string;
}

/** One supplied wallet-evidence entry, reduced to the bound fields. */
export interface EvidenceEntry {
  readonly role: string;
  readonly walletId: string | null;
  readonly walletPublicKey: string;
}

export type EvidenceSetFailure =
  | { readonly kind: "UNKNOWN_ROLE"; readonly role: string }
  | { readonly kind: "DUPLICATE_ROLE"; readonly role: AckEvidenceRole }
  | { readonly kind: "MISSING_ROLE"; readonly role: AckEvidenceRole }
  | { readonly kind: "UNEXPECTED_ROLE"; readonly role: AckEvidenceRole }
  | { readonly kind: "DUPLICATE_WALLET_PUBLIC_KEY"; readonly walletPublicKey: string }
  | { readonly kind: "WALLET_ID_MISMATCH"; readonly role: AckEvidenceRole; readonly expected: string | null; readonly actual: string | null }
  | { readonly kind: "WALLET_PUBLIC_KEY_MISMATCH"; readonly role: AckEvidenceRole; readonly expected: string; readonly actual: string }
  | { readonly kind: "MISSING_OPERATION_WALLET"; readonly role: AckEvidenceRole };

/**
 * The evidence set must exactly match the operation's wallet-evidence rows.
 * Exact means exact on both the role set and the wallet identity each role is bound to. A
 * subset, a superset, a repeated role, a repeated public key, a wrong `wallet_id`, or a wrong
 * `wallet_public_key` are all refusals — never a silent truncate, never a release directive
 * for a wallet the consumer did not evidence (the one-in-flight-per-wallet rule).
 *
 * When `expected` is omitted the call is role-only (used by pure role-set unit cases). The
 * service always supplies the operation's durable assignments.
 */
export function validateEvidenceSet(
  kind: OperationKind,
  entries: readonly EvidenceEntry[],
  expected?: readonly OperationWalletAssignment[],
): EvidenceSetFailure | null {
  const seenKeys = new Set<string>();
  for (const entry of entries) {
    if (!isAckEvidenceRole(entry.role)) {
      return { kind: "UNKNOWN_ROLE", role: entry.role };
    }
    if (seenKeys.has(entry.walletPublicKey)) {
      return { kind: "DUPLICATE_WALLET_PUBLIC_KEY", walletPublicKey: entry.walletPublicKey };
    }
    seenKeys.add(entry.walletPublicKey);
  }
  const roleFailure = validateRoleSet(
    kind,
    entries.map((entry) => entry.role as AckEvidenceRole),
  );
  if (roleFailure !== null) return roleFailure;
  if (expected === undefined) return null;
  return validateEvidenceIdentity(entries, expected);
}

/**
 * Bind each supplied evidence entry to the operation's durable wallet assignment for that
 * role. Fail-closed when the operation is missing a required assignment (incomplete formation).
 */
export function validateEvidenceIdentity(
  entries: readonly EvidenceEntry[],
  expected: readonly OperationWalletAssignment[],
): EvidenceSetFailure | null {
  const byRole = new Map<AckEvidenceRole, OperationWalletAssignment>();
  for (const assignment of expected) {
    byRole.set(assignment.role, assignment);
  }
  for (const entry of entries) {
    // Role exactness already ran; every entry.role is a closed-set AckEvidenceRole here.
    const role = entry.role as AckEvidenceRole;
    const assignment = byRole.get(role);
    if (assignment === undefined) {
      return { kind: "MISSING_OPERATION_WALLET", role };
    }
    const expectedId = assignment.walletId;
    const actualId = entry.walletId;
    if (expectedId !== actualId) {
      return {
        kind: "WALLET_ID_MISMATCH",
        role,
        expected: expectedId,
        actual: actualId,
      };
    }
    if (assignment.walletPublicKey !== entry.walletPublicKey) {
      return {
        kind: "WALLET_PUBLIC_KEY_MISMATCH",
        role,
        expected: assignment.walletPublicKey,
        actual: entry.walletPublicKey,
      };
    }
  }
  // Every required role must have a durable assignment — not only every supplied entry.
  for (const assignment of expected) {
    if (assignment.walletPublicKey === "") {
      return { kind: "MISSING_OPERATION_WALLET", role: assignment.role };
    }
  }
  const requiredRoles = expected.map((a) => a.role);
  for (const role of requiredRoles) {
    if (!entries.some((e) => e.role === role)) {
      // Role-set validation should have caught this; keep fail-closed if called alone.
      return { kind: "MISSING_ROLE", role };
    }
  }
  return null;
}

/**
 * The role half of `validateEvidenceSet`, over roles already known to be in the closed set.
 * Shared with callers that only have role tokens (e.g. historical fixtures). New group-release
 * facts carry full identity and use `validateEvidenceSet` with expected assignments.
 */
export function validateRoleSet(
  kind: OperationKind,
  roles: readonly AckEvidenceRole[],
): EvidenceSetFailure | null {
  const required = REQUIRED_EVIDENCE_ROLES[kind];
  const seen = new Set<AckEvidenceRole>();
  for (const role of roles) {
    if (seen.has(role)) {
      return { kind: "DUPLICATE_ROLE", role };
    }
    if (!required.includes(role)) {
      return { kind: "UNEXPECTED_ROLE", role };
    }
    seen.add(role);
  }
  for (const role of required) {
    if (!seen.has(role)) {
      return { kind: "MISSING_ROLE", role };
    }
  }
  return null;
}

/** One durable evidence row as written on a leg's acknowledgement. */
export interface DurableEvidenceFact {
  readonly role: AckEvidenceRole;
  readonly walletId: string | null;
  readonly walletPublicKey: string;
}

/** One lease-group leg as durably recorded, read after this request's acknowledgement wrote. */
export interface GroupOperationFact {
  readonly operationId: string;
  readonly kind: OperationKind;
  /** null until that leg's acknowledgement row commits. */
  readonly verdict: AckVerdict | null;
  /**
   * Evidence roles durably present for that leg. Empty when it has no acknowledgement.
   * Retained for role-only callers; identity-complete checks use `evidence` + `expectedWallets`.
   */
  readonly evidenceRoles: readonly AckEvidenceRole[];
  /** Full durable evidence rows (role + wallet identity). Empty when unacknowledged. */
  readonly evidence: readonly DurableEvidenceFact[];
  /** Operation-column wallet assignments this leg must evidence. */
  readonly expectedWallets: readonly OperationWalletAssignment[];
  /** `lease_group_operations.completed_at` — the leg's terminal stamp. */
  readonly completed: boolean;
}

export interface GroupReleaseFacts {
  /** `lease_groups.child_disposition` — PENDING means a declared child has not joined yet. */
  readonly childDisposition: "NONE" | "PENDING" | "JOINED";
  readonly operations: readonly GroupOperationFact[];
}

export type GroupReleaseReason =
  | "ALL_LEGS_PROVEN"
  | "GROUP_HAS_NO_OPERATIONS"
  | "LEG_VERDICT_NOT_VERIFIED"
  | "LEG_EVIDENCE_SET_INCOMPLETE"
  | "CHILD_OPERATION_NOT_JOINED"
  | "LEG_NOT_ACKNOWLEDGED"
  | "LEG_NOT_TERMINAL";

export interface GroupReleaseDecision {
  readonly status: LeaseReleaseStatus;
  readonly reason: GroupReleaseReason;
  /** The legs that caused a non-RELEASED status. Empty when RELEASED. */
  readonly blockingOperationIds: readonly string[];
}

/**
 * The group-release predicate. `VERIFIED` may release a lease group only when every
 * operation and every wallet-evidence row in the group satisfies the release predicate.
 * `REJECTED` or `INDETERMINATE` leaves the relevant wallet pinned for operator resolution
 * unless recovery provides positive non-landing proof.
 *
 * Consequences encoded below, each of which is a way a wallet could otherwise be released
 * while a second transaction could still be in flight against it (the one-in-flight-per-wallet rule):
 *
 * - A group with no legs cannot be proven; that is a defect for an operator, not a wait.
 * - Any leg carrying REJECTED or INDETERMINATE pins the group for attention, even when
 * another leg is still pending — the stronger signal wins, and the recovery path in 09 is
 * the only route out. This module never consults it.
 * - A leg whose evidence set is not exactly its kind's required role+wallet identity set has
 * not proven its wallets moved, so it pins for attention rather than waiting for nothing.
 * - `child_disposition = PENDING` means an automatic child move is expected but has not
 * joined, so the pre-formation window is still open: pending, not
 * released.
 * - A leg with no acknowledgement, or acknowledged but not yet stamped terminal, is pending.
 *
 * RELEASED is returned only when every leg is terminal, VERIFIED, and evidence-complete, and
 * no child is awaited. The caller still performs the proof-backed release itself; this
 * function only decides, and never releases as a side effect.
 */
export function evaluateGroupRelease(facts: GroupReleaseFacts): GroupReleaseDecision {
  const { operations } = facts;
  if (operations.length === 0) {
    return {
      status: "PINNED_FOR_ATTENTION",
      reason: "GROUP_HAS_NO_OPERATIONS",
      blockingOperationIds: [],
    };
  }

  const notVerified = operations.filter(
    (op) => op.verdict !== null && op.verdict !== "VERIFIED",
  );
  if (notVerified.length > 0) {
    return {
      status: "PINNED_FOR_ATTENTION",
      reason: "LEG_VERDICT_NOT_VERIFIED",
      blockingOperationIds: notVerified.map((op) => op.operationId),
    };
  }

  const evidenceIncomplete = operations.filter((op) => {
    if (op.verdict === null) return false;
    // Prefer full identity when the fact carries it; fall back to role-only for fixtures
    // that only populated evidenceRoles (should not happen on the SQL store path).
    if (op.expectedWallets.length > 0 || op.evidence.length > 0) {
      return (
        validateEvidenceSet(
          op.kind,
          op.evidence.map((e) => ({
            role: e.role,
            walletId: e.walletId,
            walletPublicKey: e.walletPublicKey,
          })),
          op.expectedWallets,
        ) !== null
      );
    }
    return validateRoleSet(op.kind, op.evidenceRoles) !== null;
  });
  if (evidenceIncomplete.length > 0) {
    return {
      status: "PINNED_FOR_ATTENTION",
      reason: "LEG_EVIDENCE_SET_INCOMPLETE",
      blockingOperationIds: evidenceIncomplete.map((op) => op.operationId),
    };
  }

  if (facts.childDisposition === "PENDING") {
    return {
      status: "PINNED_GROUP_PENDING",
      reason: "CHILD_OPERATION_NOT_JOINED",
      blockingOperationIds: [],
    };
  }

  const unacknowledged = operations.filter((op) => op.verdict === null);
  if (unacknowledged.length > 0) {
    return {
      status: "PINNED_GROUP_PENDING",
      reason: "LEG_NOT_ACKNOWLEDGED",
      blockingOperationIds: unacknowledged.map((op) => op.operationId),
    };
  }

  const nonTerminal = operations.filter((op) => !op.completed);
  if (nonTerminal.length > 0) {
    return {
      status: "PINNED_GROUP_PENDING",
      reason: "LEG_NOT_TERMINAL",
      blockingOperationIds: nonTerminal.map((op) => op.operationId),
    };
  }

  return { status: "RELEASED", reason: "ALL_LEGS_PROVEN", blockingOperationIds: [] };
}

/**
 * Acknowledging `REJECTED` or `INDETERMINATE` never silently releases a wallet.
 * Applied to the group decision as a last clamp so a defective group read can never widen
 * this request's own non-VERIFIED verdict into a release. A group already waiting stays
 * waiting; anything else becomes an attention pin.
 */
export function clampReleaseToVerdict(
  verdict: AckVerdict,
  groupStatus: LeaseReleaseStatus,
): LeaseReleaseStatus {
  if (verdict === "VERIFIED") return groupStatus;
  return groupStatus === "PINNED_GROUP_PENDING" ? "PINNED_GROUP_PENDING" : "PINNED_FOR_ATTENTION";
}

/**
 * Build the durable role→wallet assignments from operation columns. Fail-closed callers
 * refuse acknowledgement when a required role has no public key (incomplete formation).
 */
export function expectedWalletsForOperation(
  kind: OperationKind,
  columns: {
    readonly sourceWalletId: string | null;
    readonly sourcePublicKey: string | null;
    readonly receiverWalletId: string | null;
    readonly receiverPublicKey: string | null;
    readonly destinationWalletId: string | null;
    readonly destinationPublicKey: string | null;
    /** SEND_EXTERNAL counterparty — public key with no node wallet id. */
    readonly destinationAddress: string | null;
  },
): OperationWalletAssignment[] {
  switch (kind) {
    case "RECEIVE_EXTERNAL":
      return columns.receiverPublicKey === null
        ? []
        : [
            {
              role: "RECEIVER",
              walletId: columns.receiverWalletId,
              walletPublicKey: columns.receiverPublicKey,
            },
          ];
    case "MOVE_INTERNAL": {
      const out: OperationWalletAssignment[] = [];
      if (columns.sourcePublicKey !== null) {
        out.push({
          role: "SOURCE",
          walletId: columns.sourceWalletId,
          walletPublicKey: columns.sourcePublicKey,
        });
      }
      if (columns.destinationPublicKey !== null) {
        out.push({
          role: "DESTINATION",
          walletId: columns.destinationWalletId,
          walletPublicKey: columns.destinationPublicKey,
        });
      }
      return out;
    }
    case "SEND_EXTERNAL": {
      const out: OperationWalletAssignment[] = [];
      if (columns.sourcePublicKey !== null) {
        out.push({
          role: "SOURCE",
          walletId: columns.sourceWalletId,
          walletPublicKey: columns.sourcePublicKey,
        });
      }
      if (columns.destinationAddress !== null) {
        out.push({
          role: "DESTINATION",
          walletId: null,
          walletPublicKey: columns.destinationAddress,
        });
      }
      return out;
    }
  }
}
