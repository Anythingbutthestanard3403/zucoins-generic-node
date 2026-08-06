// SEND_EXTERNAL formation worker claim-and-observe phase.
// Exact partial only.
//
// 1. Claim the APPROVED row (status=APPROVED, formation_state=APPROVED_UNSIGNED).
// 2. Acquire the source wallet's SEND_SOURCE lease BEFORE any gateway read. On
// contention leave APPROVED and retry with bounded database backoff — never mint a
// second operation or consume a second approval.
// 3. OBSERVE(source_pubkey, SEND_SOURCE_T0) under the held lease.
// 4. OBSERVE(destination_address, SEND_DESTINATION_FORMATION) — external public-key
// stream; no node wallet_id, no lease.
// 5. Require both observations verified, source balance sufficient, keys different.
//
// This module stops at step 5. It does not construct an inner, does not persist a sign
// intent, and does not sign. Its sole output is a held source lease plus two
// durable observation_ids ready for formation.
//
// Structural invariants:
// - OBSERVE(source) is unreachable without a successful source-lease acquire in this
// module (the lease port is the only path into the observer for source).
// - Destination observation carries no wallet_id / lease reference on the call surface.
// - INDETERMINATE is never coerced to genesis (B0="0").
// - No submit import, credential, worker, or attempt surface exists here (parent AC).

import type { WalletLease } from "@zucoins/generic-node-contracts/wallet-state";
import type { WalletStateProjection } from "../protocol/wallet-role.js";
import {
  captureSendBaselines,
  type SendBaselineCapture,
  type SendBaselineRejectionReason,
} from "../protocol/send-baseline.js";

// ─── Observation roles (steps 3–4) ──────────────────────────

export const SEND_T0_OBSERVATION_ROLES = [
  "SEND_SOURCE_T0",
  "SEND_DESTINATION_FORMATION",
] as const;
export type SendT0ObservationRole = (typeof SEND_T0_OBSERVATION_ROLES)[number];

/**
 * INDETERMINATE is its own outcome, not a projection with null
 * fields — the type makes "treat it as zero" unrepresentable rather than discouraged.
 * Shared shape with move-baseline-binding's ObservationOutcome; duplicated here so this
 * module does not import the move path (send and move must not couple).
 */
export type ObservationOutcome =
  | {
      readonly kind: "VERIFIED";
      readonly observationId: string;
      readonly projection: WalletStateProjection;
    }
  | { readonly kind: "INDETERMINATE"; readonly detail: string }
  | { readonly kind: "UNVERIFIED"; readonly detail: string };

/**
 * Observation port. Source and destination are deliberately separate methods so a
 * destination call cannot accidentally carry a wallet_id / lease — the type system
 * refuses a wallet_id argument on observeDestination.
 */
export interface SendFormationObserver {
  /**
   * OBSERVE(source_pubkey, SEND_SOURCE_T0). Caller must already hold the source lease;
   * the orchestration below enforces that ordering structurally.
   */
  observeSource(sourcePublicKey: string): Promise<ObservationOutcome>;
  /**
   * OBSERVE(destination_address, SEND_DESTINATION_FORMATION). External public-key
   * stream only — no node wallet_id, no lease.
   */
  observeDestination(destinationAddress: string): Promise<ObservationOutcome>;
}

// ─── Claim port (step 1) ──────────────────────────────────────────────

/** Frozen formation states this slice may observe on an APPROVED row. */
export const CLAIMABLE_FORMATION_STATE = "APPROVED_UNSIGNED" as const;
export const CLAIMABLE_STATUS = "APPROVED" as const;

export interface ApprovedSendClaim {
  readonly operationId: string;
  readonly status: typeof CLAIMABLE_STATUS;
  readonly formationState: typeof CLAIMABLE_FORMATION_STATE;
  readonly rowVersion: number;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
}

export type ClaimApprovedResult =
  | { readonly outcome: "CLAIMED"; readonly claim: ApprovedSendClaim }
  | { readonly outcome: "NOT_CLAIMABLE"; readonly detail: string };

/**
 * Loads and locks the APPROVED/APPROVED_UNSIGNED row. Composition root supplies a
 * SELECT … FOR UPDATE (or equivalent CAS) against send_operations / operations.
 * A miss leaves the operation untouched — never forces NEEDS_ATTENTION.
 */
export interface ApprovedSendClaimPort {
  claimApproved(operationId: string): Promise<ClaimApprovedResult>;
}

// ─── Lease port (step 2) ──────────────────────────────────────

export interface HeldSourceLease {
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly operationId: string;
  /** Capability shape presented to pure baseline predicates. */
  readonly lease: WalletLease;
}

export type TryAcquireSourceLeaseResult =
  | { readonly outcome: "ACQUIRED"; readonly held: HeldSourceLease }
  /** Already held by this operation (crash recovery after lease, before sign intent). */
  | { readonly outcome: "ALREADY_HELD"; readonly held: HeldSourceLease }
  /** Another operation/owner holds the wallet — step 2 contention path. */
  | { readonly outcome: "BUSY"; readonly detail: string }
  | { readonly outcome: "REJECTED"; readonly reason: string; readonly detail: string };

export interface SourceLeasePort {
  /**
   * One non-blocking attempt to take the source SEND_SOURCE lease for this operation.
   * MUST create the lease group if needed. MUST NOT observe the gateway.
   */
  tryAcquireSourceLease(input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly ownerInstanceId: string;
  }): Promise<TryAcquireSourceLeaseResult>;
}

// ─── Backoff (step 2 bounded database backoff) ────────────────────────

export interface LeaseAcquireBackoffOptions {
  /** Max acquire attempts including the first. Default 8. */
  readonly maxAttempts?: number;
  readonly baseDelayMs?: number;
  readonly maxDelayMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
  readonly onWaiting?: (info: { attempt: number; delayMs: number }) => void;
  readonly signal?: { readonly aborted: boolean };
}

const DEFAULT_MAX_ATTEMPTS = 8;
const DEFAULT_BASE_DELAY_MS = 250;
const DEFAULT_MAX_DELAY_MS = 2_000;

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// ─── Result surface ──────────────────────────────────────────────────────────

export type ClaimAndObserveRejectionReason =
  | "not_claimable"
  | "lease_contention_exhausted"
  | "lease_rejected"
  | "aborted"
  | "source_observation_indeterminate"
  | "destination_observation_indeterminate"
  | "source_observation_unverified"
  | "destination_observation_unverified"
  | "shared_t0_observation"
  | SendBaselineRejectionReason;

export type ClaimAndObserveResult =
  | {
      readonly ok: true;
      readonly claim: ApprovedSendClaim;
      readonly held: HeldSourceLease;
      readonly sourceT0ObservationId: string;
      readonly destinationFormationObservationId: string;
      readonly capture: SendBaselineCapture;
    }
  | {
      readonly ok: false;
      readonly reason: ClaimAndObserveRejectionReason;
      readonly detail: string;
      /** Present when the source lease was acquired before the rejection. */
      readonly held?: HeldSourceLease;
      /** Claim snapshot when the APPROVED row was successfully claimed. */
      readonly claim?: ApprovedSendClaim;
    };

export interface ClaimAndObserveInput {
  readonly operationId: string;
  readonly ownerInstanceId: string;
  readonly capturedAt: number;
  readonly claimPort: ApprovedSendClaimPort;
  readonly leasePort: SourceLeasePort;
  readonly observer: SendFormationObserver;
  readonly backoff?: LeaseAcquireBackoffOptions;
}

function reject(
  reason: ClaimAndObserveRejectionReason,
  detail: string,
  extras: { held?: HeldSourceLease; claim?: ApprovedSendClaim } = {},
): ClaimAndObserveResult {
  return {
    ok: false,
    reason,
    detail,
    ...(extras.held !== undefined ? { held: extras.held } : {}),
    ...(extras.claim !== undefined ? { claim: extras.claim } : {}),
  };
}

/**
 * Acquire the source SEND_SOURCE lease with bounded backoff on BUSY.
 * Leaves the operation APPROVED on exhaustion — never mints another operation.
 */
export async function acquireSourceLeaseWithBackoff(
  leasePort: SourceLeasePort,
  input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly ownerInstanceId: string;
  },
  backoff: LeaseAcquireBackoffOptions = {},
): Promise<
  | { readonly ok: true; readonly held: HeldSourceLease }
  | {
      readonly ok: false;
      readonly reason: "lease_contention_exhausted" | "lease_rejected" | "aborted";
      readonly detail: string;
    }
> {
  const maxAttempts = backoff.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const base = backoff.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const max = backoff.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  const sleep = backoff.sleep ?? defaultSleep;
  const random = backoff.random ?? Math.random;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (backoff.signal?.aborted) {
      return { ok: false, reason: "aborted", detail: "lease acquire aborted before success" };
    }

    const result = await leasePort.tryAcquireSourceLease(input);
    if (result.outcome === "ACQUIRED" || result.outcome === "ALREADY_HELD") {
      return { ok: true, held: result.held };
    }
    if (result.outcome === "REJECTED") {
      return {
        ok: false,
        reason: "lease_rejected",
        detail: `${result.reason}: ${result.detail}`,
      };
    }

    // BUSY — leave APPROVED; retry with bounded backoff. Do not observe yet.
    if (attempt === maxAttempts) {
      return {
        ok: false,
        reason: "lease_contention_exhausted",
        detail: `source lease busy after ${maxAttempts} attempts: ${result.detail}`,
      };
    }
    if (backoff.signal?.aborted) {
      return { ok: false, reason: "aborted", detail: "lease acquire aborted during backoff" };
    }
    const ceil = Math.min(max, base * 2 ** Math.min(attempt, 8));
    const delayMs = Math.floor(random() * ceil);
    backoff.onWaiting?.({ attempt, delayMs });
    await sleep(delayMs);
  }

  return {
    ok: false,
    reason: "lease_contention_exhausted",
    detail: `source lease busy after ${maxAttempts} attempts`,
  };
}

/**
 * Steps 1–5. Ordering is load-bearing:
 * claim → lease (with backoff) → OBSERVE source → OBSERVE destination → validate.
 * No gateway read occurs before the lease is held. No sign intent is written.
 */
export async function claimAndObserveSendBaselines(
  input: ClaimAndObserveInput,
): Promise<ClaimAndObserveResult> {
  // Step 1 — claim the APPROVED row.
  const claimed = await input.claimPort.claimApproved(input.operationId);
  if (claimed.outcome !== "CLAIMED") {
    return reject("not_claimable", claimed.detail);
  }
  const claim = claimed.claim;

  // Step 2 — source lease BEFORE any gateway read.
  const leased = await acquireSourceLeaseWithBackoff(
    input.leasePort,
    {
      operationId: claim.operationId,
      sourceWalletId: claim.sourceWalletId,
      ownerInstanceId: input.ownerInstanceId,
    },
    input.backoff,
  );
  if (!leased.ok) {
    return reject(leased.reason, leased.detail, { claim });
  }
  const held = leased.held;

  // Step 3 — OBSERVE source under the held lease. Unreachable without step 2 success.
  const sourceObservation = await input.observer.observeSource(claim.sourcePubkey);

  // Step 4 — OBSERVE destination (external pubkey stream; no wallet_id / lease).
  const destinationObservation = await input.observer.observeDestination(
    claim.destinationAddress,
  );

  // Step 5 — both verified; never coerce INDETERMINATE into genesis.
  if (sourceObservation.kind === "INDETERMINATE") {
    return reject("source_observation_indeterminate", sourceObservation.detail, {
      claim,
      held,
    });
  }
  if (sourceObservation.kind === "UNVERIFIED") {
    return reject("source_observation_unverified", sourceObservation.detail, { claim, held });
  }
  if (destinationObservation.kind === "INDETERMINATE") {
    return reject("destination_observation_indeterminate", destinationObservation.detail, {
      claim,
      held,
    });
  }
  if (destinationObservation.kind === "UNVERIFIED") {
    return reject("destination_observation_unverified", destinationObservation.detail, {
      claim,
      held,
    });
  }

  // Distinct observation ROWS even when both project genesis (move parity).
  if (sourceObservation.observationId === destinationObservation.observationId) {
    return reject(
      "shared_t0_observation",
      `both formation baselines cite observation ${sourceObservation.observationId}`,
      { claim, held },
    );
  }

  const captured = captureSendBaselines({
    operationId: claim.operationId,
    sourceWalletPublicKey: claim.sourcePubkey,
    destinationAddress: claim.destinationAddress,
    sourceLease: held.lease,
    sourceBaseline: sourceObservation.projection,
    destinationBaseline: destinationObservation.projection,
    amountZkz: claim.amountZkz,
    capturedAt: input.capturedAt,
  });
  if (!captured.ok) {
    return reject(captured.reason, captured.detail, { claim, held });
  }

  return {
    ok: true,
    claim,
    held,
    sourceT0ObservationId: sourceObservation.observationId,
    destinationFormationObservationId: destinationObservation.observationId,
    capture: captured.capture,
  };
}

// ─── SQL catalogue for the composition-root claim (send_operations shape) ────
// Driver stays outside node-core. Tests pin these exact strings.

export const CLAIM_AND_OBSERVE_SQL = {
  /**
   * Step 1 against the send_operations surface. FOR UPDATE serialises
   * concurrent formation workers on the same row; status/formation_state guards refuse
   * anything that is not still waiting for first formation. source_pubkey is taken from
   * the resolved wallets row (create-time rule: never from a request field).
   */
  CLAIM_APPROVED_SEND_OPERATION:
    "SELECT o.operation_id, o.status, o.formation_state, o.row_version, " +
    "o.source_wallet_id, w.public_key AS source_pubkey, o.destination_address, o.amount_zkz " +
    "FROM send_operations o " +
    "JOIN wallets w ON w.id = o.source_wallet_id " +
    "WHERE o.operation_id = $1 AND o.status = 'APPROVED' AND o.formation_state = 'APPROVED_UNSIGNED' " +
    "FOR UPDATE OF o",
} as const;
