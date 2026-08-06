// DB-TX landing commit for RECEIVE_EXTERNAL.
//
// The landing DB-TX writes the ordered lineage path, appends node_events, and serves
// ancestor_proofs; the landing-path oracle is the canonical authority.
//
// On a positive landing-path oracle landing proof this module, in ONE database transaction:
// 1. persists the exact settled body of the expected attempt at attempt_phase
// SETTLED_BODY_PERSISTED, together with the FULL ORDERED PATH T_expected ... T_head in
// exact full-body form;
// 2. derives public execution phase LANDED_VERIFIED;
// 3. transitions READY → RECEIVE_LANDED under a row_version + status CAS;
// 4. appends receive.landed with {terminal_observation_id, landed_at};
// 5. sets proof-access expiry (landed_at + window);
// 6. commits.
//
// The receiver lease is deliberately NOT released here — it stays held. Release follows
// the expiry / verification-complete path and is out of scope for
// this module; callers must never invoke a lease-release path as part of this commit.
//
// The arbiter is the database, never this file: the CAS lives in the UPDATE WHERE clause and
// the exactly-once guarantee lives in a unique index. A race that already landed matches zero
// rows → CONFLICT, no partial write. Two emitters that both reach the event insert collide on
// 23505 and one transaction aborts whole.
//
// Nothing here can turn a fault into a landing. `commitReceiveLanding` accepts only the
// positive members of LandingProofOutcome; every LandingProofFailure is INDETERMINATE and
// authorizes no landing, no non-landing, and no retry/rebuild/resubmit or lease release
// ("there is no generic PROVEN_NOT_LANDED oracle").

import { createHash } from "node:crypto";

import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  verificationMaterialAvailableUntilMs,
} from "../data/retention.js";
import {
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  type LandingPathProof,
  type LandingProofOutcome,
} from "../protocol/reconcile/landing-proof.js";
import type { ParsedSettledTransaction } from "../verifier/gateway-envelope.js";
import {
  proveReceiveLanding,
  type ReadFreshHead,
  type ReceiveLandingOracleInput,
} from "../verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../verifier/transaction-verify.js";

export const READY_STATUS = "READY" as const;
export const RECEIVE_LANDED_STATUS = "RECEIVE_LANDED" as const;
export const SETTLED_BODY_PERSISTED_PHASE = "SETTLED_BODY_PERSISTED" as const;
export const LANDED_VERIFIED_PHASE = "LANDED_VERIFIED" as const;
export const RECEIVE_LANDED_EVENT = "receive.landed" as const;
export const RECEIVER_PATH_ROLE = "RECEIVER" as const;

/** SHA-256 hex of UTF-8 text — manifest identity (the byte-exact signing rule discipline). */
export function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** lineage_path_bodies.source_kind, narrowed to what this walk can produce. */
export type ReceivePathBodySourceKind =
  | "EXPECTED_OPERATION"
  | "PROOF_CHANNEL"
  | "FRESH_GATEWAY_HEAD";

/** One hop of the persisted ordered path, in lineage_path_bodies shape. */
export interface ReceiveLandingPathBody {
  readonly pathIndex: number;
  readonly sourceKind: ReceivePathBodySourceKind;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
  readonly completedTransactionOctets: number;
  readonly walletRole: "sender" | "receiver";
  readonly sSignature: string;
  readonly pSignature: string;
  readonly bAmount: string;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
}

/** The proof header, collapsed to the single RECEIVER path a receive requires. */
export interface ReceiveLandingProofRecord {
  readonly operationId: string;
  readonly attemptPhase: typeof SETTLED_BODY_PERSISTED_PHASE;
  readonly publicExecutionPhase: typeof LANDED_VERIFIED_PHASE;
  readonly pathRole: typeof RECEIVER_PATH_ROLE;
  readonly walletPublicKey: string;
  readonly t0ObservationId: string;
  readonly freshHeadObservationId: string;
  readonly terminalObservationId: string;
  readonly expectedCompletedTransactionSha256: string;
  readonly freshHeadCompletedTransactionSha256: string;
  readonly verdict: LandingPathProof["kind"];
  readonly bodyCount: number;
  readonly pathDepth: number;
  readonly pathManifestText: string;
  readonly pathManifestSha256: string;
  readonly landedAtMs: number;
  readonly verificationMaterialAvailableUntilMs: number;
}

export interface ReceiveLandedEvent {
  readonly operationId: string;
  readonly eventType: typeof RECEIVE_LANDED_EVENT;
  readonly terminalObservationId: string;
  readonly landedAtMs: number;
  readonly dataText: string;
}

export interface CommitReceiveLandingCommand {
  readonly operationId: string;
  /** The row_version the caller read the operation at — half of the CAS. */
  readonly expectedRowVersion: number;
  readonly expectedStatus: typeof READY_STATUS;
  readonly proof: ReceiveLandingProofRecord;
  /** Ascending by pathIndex, index 0 the expected attempt, last the fresh head. */
  readonly path: readonly ReceiveLandingPathBody[];
  readonly event: ReceiveLandedEvent;
}

export type CommitReceiveLandingOutcome =
  | {
      readonly outcome: "APPLIED";
      readonly status: typeof RECEIVE_LANDED_STATUS;
      readonly proof: ReceiveLandingProofRecord;
      readonly path: readonly ReceiveLandingPathBody[];
      readonly event: ReceiveLandedEvent;
      /** Always true after a successful land — lease release is out of scope. */
      readonly receiverLeaseStillHeld: true;
    }
  | {
      readonly outcome: "CONFLICT";
      readonly reason: ReceiveLandingConflictReason;
      readonly detail: string;
    }
  | {
      readonly outcome: "REJECTED";
      readonly reason: ReceiveLandingRejectReason;
      readonly detail: string;
    };

export type ReceiveLandingConflictReason =
  | "STATUS_GUARD_MISMATCH"
  | "ALREADY_LANDED"
  | "LEASE_MISSING"
  | "PATH_INCOMPLETE";

export type ReceiveLandingRejectReason =
  | "PROOF_NOT_POSITIVE"
  | "WALLET_MISMATCH"
  | "PATH_BODY_UNVERIFIED"
  | "PATH_DEPTH_MISMATCH"
  | "PATH_EXPECTED_ANCHOR_MISMATCH"
  | "PATH_HEAD_ANCHOR_MISMATCH"
  | "PATH_BACKLINK_BROKEN";

/**
 * Persistence port for the landing DB-TX. Implementations MUST run the guarded status
 * transition, proof-header insert, ordered path insert, and event append in a single
 * transaction. Implementations MUST NOT delete, update or re-insert wallet_active_leases rows.
 */
export interface ReceiveLandingStore {
  /**
   * Atomically land the operation. `applied: false` when the CAS matched no row (already
   * landed, wrong status, wrong row_version, or missing) or the persisted path was refused.
   * MUST leave the receiver lease row byte-identical.
   */
  commitLanding(command: CommitReceiveLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: ReceiveLandingConflictReason;
    readonly receiverLeaseStillHeld: boolean;
  }>;
}

/**
 * Build the persisted path from the ordered bodies the oracle proved, re-verifying each one
 * so every persisted row is byte-exact signed text this module itself checked. The persisted
 * artifact is therefore self-attesting: an independent verifier reading these rows is reading
 * bodies that reverified at persist time, not a projection of the oracle's internal state.
 *
 * Returns the ordered path, or the index of the first body that failed to verify.
 */
export function buildReceiveLandingPath(
  bodies: readonly ParsedSettledTransaction[],
  walletPubkeyBase64Urlsafe: string,
): { readonly path: readonly ReceiveLandingPathBody[] } | { readonly unverifiedIndex: number } {
  const path: ReceiveLandingPathBody[] = [];
  const lastIndex = bodies.length - 1;
  for (let index = 0; index < bodies.length; index += 1) {
    const body = bodies[index]!;
    const verdict = verifySettledTransaction(body, walletPubkeyBase64Urlsafe);
    if (verdict.verdict !== "VERIFIED") {
      return { unverifiedIndex: index };
    }
    // I is the inner digest, already derived from the exact reconstructed preimage.
    // A verified body always carries one; the genesis projection (I = null) has no body and
    // cannot reach this loop.
    const innerSha256 = verdict.projection.I;
    if (innerSha256 === null) {
      return { unverifiedIndex: index };
    }
    path.push({
      pathIndex: index,
      // Index 0 is the operation's own expected attempt; the terminal hop of a buried path is
      // the freshly read gateway head; everything between arrived over the proof channel. At
      // depth 0 the single body is the expected attempt (that it also reads as the head is the
      // header's exact-head identity, not a different provenance).
      sourceKind:
        index === 0
          ? "EXPECTED_OPERATION"
          : index === lastIndex
            ? "FRESH_GATEWAY_HEAD"
            : "PROOF_CHANNEL",
      completedTransactionText: verdict.completedTransactionText,
      completedTransactionSha256: verdict.completedTransactionSha256,
      completedTransactionOctets: Buffer.byteLength(verdict.completedTransactionText, "utf8"),
      walletRole: verdict.projection.role === "sender" ? "sender" : "receiver",
      sSignature: verdict.projection.S,
      pSignature: verdict.projection.P,
      bAmount: verdict.projection.B,
      innerPreimageText: verdict.innerPreimageText,
      innerSha256,
      step1Signature: verdict.transaction.step_1_signature,
      step2Signature: verdict.transaction.step_2_signature,
    });
  }
  return { path };
}

/**
 * The ancestor-proof manifest: byte-stable, fixed insertion sequence, one entry per hop.
 * An independent verifier re-derives this text from the persisted rows and compares digests to
 * confirm it walked the identical path.
 */
export function buildPathManifestText(
  proof: LandingPathProof,
  freshHeadSha256: string,
  path: readonly ReceiveLandingPathBody[],
): string {
  return JSON.stringify({
    verdict: proof.kind,
    path_role: RECEIVER_PATH_ROLE,
    wallet_public_key: proof.walletPubkeyBase64Urlsafe,
    expected_completed_transaction_sha256: proof.expectedBodySha256,
    fresh_head_completed_transaction_sha256: freshHeadSha256,
    fresh_head_observation_id: proof.freshHeadObservationId,
    path_depth: proof.depth,
    body_count: path.length,
    bodies: path.map((body) => ({
      path_index: body.pathIndex,
      completed_transaction_sha256: body.completedTransactionSha256,
      s_signature: body.sSignature,
      p_signature: body.pSignature,
    })),
  });
}

/** Receive.landed data: terminal_observation_id, landed_at. Byte-stable field sequence. */
export function buildReceiveLandedEvent(
  operationId: string,
  terminalObservationId: string,
  landedAtMs: number,
): ReceiveLandedEvent {
  return {
    operationId,
    eventType: RECEIVE_LANDED_EVENT,
    terminalObservationId,
    landedAtMs,
    dataText: JSON.stringify({
      terminal_observation_id: terminalObservationId,
      landed_at: new Date(landedAtMs).toISOString(),
    }),
  };
}

export interface CommitReceiveLandingInput {
  readonly operationId: string;
  readonly expectedRowVersion: number;
  readonly walletPubkeyBase64Urlsafe: string;
  readonly t0ObservationId: string;
  /** The observation-ledger row the terminal confirm-read landed. */
  readonly terminalObservationId: string;
  /** [expected attempt, ...supplied successors] — the same sequence the oracle proved. */
  readonly bodies: readonly ParsedSettledTransaction[];
  readonly landedAtMs?: number;
  readonly proofAccessWindowMs?: number;
}

/**
 * Turn a positive landing-path oracle proof into the committed landing. Never lands on a
 * LandingProofFailure, and never on a path that does not re-derive to the proof it claims.
 *
 * Every cross-check below is falsifiable and independently reachable: each has a test that
 * supplies evidence failing exactly that check while the others hold.
 */
export async function commitReceiveLanding(
  outcome: LandingProofOutcome,
  input: CommitReceiveLandingInput,
  store: ReceiveLandingStore,
): Promise<CommitReceiveLandingOutcome> {
  if (outcome.kind === "PROOF_INCOMPLETE") {
    return {
      outcome: "REJECTED",
      reason: "PROOF_NOT_POSITIVE",
      detail: `landing commit requires a positive landing proof, got PROOF_INCOMPLETE/${outcome.fault}`,
    };
  }
  // structural impostors are not landing authority even when field-shaped.
  if (!isLandingPathProof(outcome)) {
    return {
      outcome: "REJECTED",
      reason: "PROOF_NOT_POSITIVE",
      detail: "landing commit requires an issued landing-oracle capability",
    };
  }
  if (outcome.walletPubkeyBase64Urlsafe !== input.walletPubkeyBase64Urlsafe) {
    return {
      outcome: "REJECTED",
      reason: "WALLET_MISMATCH",
      detail: "the proof was minted for a different wallet than the one being landed",
    };
  }

  const built = buildReceiveLandingPath(input.bodies, input.walletPubkeyBase64Urlsafe);
  if ("unverifiedIndex" in built) {
    return {
      outcome: "REJECTED",
      reason: "PATH_BODY_UNVERIFIED",
      detail: `path body at index ${built.unverifiedIndex} did not reverify at persist time`,
    };
  }
  const path = built.path;

  if (path.length !== outcome.depth + 1) {
    return {
      outcome: "REJECTED",
      reason: "PATH_DEPTH_MISMATCH",
      detail: `proof depth ${outcome.depth} requires ${outcome.depth + 1} bodies, got ${path.length}`,
    };
  }
  const first = path[0]!;
  const head = path[path.length - 1]!;
  if (first.completedTransactionSha256 !== outcome.expectedBodySha256) {
    return {
      outcome: "REJECTED",
      reason: "PATH_EXPECTED_ANCHOR_MISMATCH",
      detail: "path index 0 is not the attempt the proof was minted for",
    };
  }
  // A LANDED_EXACT path is one body, so its head anchor is its expected anchor; a buried path
  // must terminate at a body distinct from the attempt it started at.
  if (outcome.kind === "LANDED_COMPLETE_PATH" && head.completedTransactionSha256 === outcome.expectedBodySha256) {
    return {
      outcome: "REJECTED",
      reason: "PATH_HEAD_ANCHOR_MISMATCH",
      detail: "a buried landing cannot terminate at the expected attempt itself",
    };
  }
  // Terminal confirm-read observation id must equal the proof's changed-response observation ledger fresh-head anchor.
  // Durable proof row and receive.landed event must cite the same observation.
  if (input.terminalObservationId !== outcome.freshHeadObservationId) {
    return {
      outcome: "REJECTED",
      reason: "PATH_HEAD_ANCHOR_MISMATCH",
      detail:
        "terminalObservationId must equal the issued proof freshHeadObservationId (head anchor)",
    };
  }
  // Independent of free proof strings: bind wallet + expected + rebuilt head digest + the
  // terminal ledger observation id against the issued capability (never self-compare).
  if (
    !revalidateLandingPathProofBindings(outcome, {
      walletPubkeyBase64Urlsafe: input.walletPubkeyBase64Urlsafe,
      expectedBodySha256: first.completedTransactionSha256,
      freshHeadBodySha256: head.completedTransactionSha256,
      freshHeadObservationId: input.terminalObservationId,
    })
  ) {
    return {
      outcome: "REJECTED",
      reason: "PATH_HEAD_ANCHOR_MISMATCH",
      detail: "issued proof bindings failed revalidation against rebuilt path digests",
    };
  }
  for (let index = 1; index < path.length; index += 1) {
    if (path[index]!.pSignature !== path[index - 1]!.sSignature) {
      return {
        outcome: "REJECTED",
        reason: "PATH_BACKLINK_BROKEN",
        detail: `backlink P(T[${index}]) != S(T[${index - 1}]) in the path being persisted`,
      };
    }
  }

  const landedAtMs = input.landedAtMs ?? Date.now();
  const windowMs = input.proofAccessWindowMs ?? DEFAULT_PROOF_ACCESS_WINDOW_MS;
  const manifestText = buildPathManifestText(outcome, head.completedTransactionSha256, path);
  const proof: ReceiveLandingProofRecord = {
    operationId: input.operationId,
    attemptPhase: SETTLED_BODY_PERSISTED_PHASE,
    publicExecutionPhase: LANDED_VERIFIED_PHASE,
    pathRole: RECEIVER_PATH_ROLE,
    walletPublicKey: outcome.walletPubkeyBase64Urlsafe,
    t0ObservationId: input.t0ObservationId,
    freshHeadObservationId: outcome.freshHeadObservationId,
    terminalObservationId: input.terminalObservationId,
    expectedCompletedTransactionSha256: outcome.expectedBodySha256,
    freshHeadCompletedTransactionSha256: head.completedTransactionSha256,
    verdict: outcome.kind,
    bodyCount: path.length,
    pathDepth: outcome.depth,
    pathManifestText: manifestText,
    pathManifestSha256: sha256HexUtf8(manifestText),
    landedAtMs,
    verificationMaterialAvailableUntilMs: verificationMaterialAvailableUntilMs(landedAtMs, windowMs),
  };

  const event = buildReceiveLandedEvent(input.operationId, input.terminalObservationId, landedAtMs);
  const result = await store.commitLanding({
    operationId: input.operationId,
    expectedRowVersion: input.expectedRowVersion,
    expectedStatus: READY_STATUS,
    proof,
    path,
    event,
  });

  if (!result.applied) {
    return {
      outcome: "CONFLICT",
      reason: result.reason ?? "STATUS_GUARD_MISMATCH",
      detail: "CAS matched no row or the persisted path was refused; no partial landing write",
    };
  }
  if (!result.receiverLeaseStillHeld) {
    // A store that released the lease has violated step 5. Surface as conflict so no
    // caller can treat a lease-releasing implementation as a successful land.
    return {
      outcome: "CONFLICT",
      reason: "LEASE_MISSING",
      detail: "landing store reported the receiver lease not held after commit — F breach",
    };
  }
  return {
    outcome: "APPLIED",
    status: RECEIVE_LANDED_STATUS,
    proof,
    path,
    event,
    receiverLeaseStillHeld: true,
  };
}

/**
 * End to end for one already-observed candidate: run the landing-path oracle against
 * a live confirm-read, then commit the landing it proves.
 *
 * A fault from the oracle is INDETERMINATE — it returns REJECTED/PROOF_NOT_POSITIVE and
 * nothing is written. A bare head mismatch proves neither landed nor
 * non-landed, so this function never rebuilds, resubmits, or releases the receiver lease on
 * any outcome.
 */
export async function verifyAndCommitReceiveLanding(
  oracleInput: ReceiveLandingOracleInput,
  commitInput: Omit<CommitReceiveLandingInput, "walletPubkeyBase64Urlsafe" | "bodies">,
  readFreshHead: ReadFreshHead,
  store: ReceiveLandingStore,
): Promise<CommitReceiveLandingOutcome> {
  const outcome = await proveReceiveLanding(oracleInput, readFreshHead);
  // bind the terminal observation to the oracle's own confirmed fresh-head
  // read, not a preliminary read that may differ on a byte-changed wrapper (changed-response observation ledger).
  // The oracle's freshHeadObservationId is the authoritative durable confirm-read row.
  const terminalObservationId =
    "freshHeadObservationId" in outcome
      ? outcome.freshHeadObservationId
      : commitInput.terminalObservationId;
  return commitReceiveLanding(
    outcome,
    {
      ...commitInput,
      terminalObservationId,
      walletPubkeyBase64Urlsafe: oracleInput.walletPubkeyBase64Urlsafe,
      bodies: [oracleInput.expectedBody, ...oracleInput.successorBodies],
    },
    store,
  );
}
