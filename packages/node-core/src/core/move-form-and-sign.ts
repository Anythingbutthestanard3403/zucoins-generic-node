// MOVE_INTERNAL: sign both steps under leases.
// The signer signs an already-persisted exact preimage and never chooses parameters or
// retry policy; the one-in-flight-per-wallet and byte-exact signing rules, 4, 5 all bind here.
//
// Sequence (steps 3–8), each DB-TX committing before the signer call it authorizes:
// 3. SIGN(inner_preimage) under the SOURCE lease. The preimage is read back out of
// operation_transactions — an in-memory inner cannot reach the signer.
// 4. DB-TX: step-1 signature, phase → STEP1_SIGNATURE_PERSISTED.
// 5. Round-trip guard on the persisted inner text, then splice {inner, step_1_signature}.
// 6. DB-TX: exact step-2 preimage + SHA-256, phase → STEP2_PREIMAGE_PERSISTED. Commits
// BEFORE the destination signer is called.
// 7. SIGN(step_2_preimage) under the DESTINATION lease, again read back from the row.
// 8. DB-TX: step-2 signature + completed transaction text, phase → STEP2_SIGNATURE_PERSISTED.
// (The submit decision named in this same canonical DB-TX is slice.)
//
// Structural invariants, in preference to caller discipline:
// * Every preimage handed to a signer is branded DurableMovePreimage, and the only producer
// of that brand is readDurableMovePreimage — a SELECT of the committed row. There is no
// path from a constructed object to a signature — never an arbitrary in-memory object.
// * Both signer calls go through signUnderLease, which re-reads wallet_active_leases and
// requires an exact (wallet_id, operation_id, lease_epoch, permitted role) match before
// the vault is touched. Possession of a key is never sufficient (the one-in-flight-per-wallet rule).
// * Phase advancement runs through advanceAttemptPhase, whose WHERE requires the immediately
// prior phase and NULL targets — an out-of-sequence or replayed write matches zero rows and
// throws rather than overwriting a signed byte. attempt_no is CHECK-pinned to 1, so
// no second attempt is representable (the never-blind-retry rule).
//
// core may not import move/ or leases/ (test/boundaries.test.ts), so the held-lease shape is
// declared structurally here exactly as send-form-and-sign.ts declares FormAndSignHeldLease.

import { advanceAttemptPhase, ONLY_ATTEMPT_NO } from "./transaction-material-store.js";
import type { SqlQueryFn } from "./sql-query-fn.js";
import {
  signUnderLease,
  type MoneyPathSignerGates,
  type SignerBoundaryDeps,
  type SigningPurpose,
  type SigningResult,
} from "./signer-boundary.js";
import {
  assertPersistedInnerRoundTrips,
  buildMoveCompletedTransactionText,
  buildMoveStep2PreimageText,
  hashMovePreimageText,
} from "./move-step2.js";

/**
 * Money-path signer deps for MOVE_INTERNAL. `signUnderLease` fail-closes via
 * `requireMoneyPathGates` when any of the three money-admission ports is missing; this
 * intersection makes the requirement visible at every MOVE call site (and to
 * `createMoneySignerBoundaryDeps` / production composition) rather than only
 * at the first vault touch.
 *
 * `assertHaltAdmitsKind` is kind-scoped operator halt (kind-scoped operator halt). It is
 * required on the deps type so production composition cannot forget it;
 * `signMoveStepsUnderLeases` (first formation) consults it for MOVE_INTERNAL.
 * Crash resume (`resumeMoveStep2FromPersistedStep1`) does not — in-flight work
 * must finish while halted (the one-in-flight-per-wallet rule / hang-gate pre_sign only).
 */
export type MoveSignerBoundaryDeps = SignerBoundaryDeps &
  MoneyPathSignerGates & {
    readonly assertHaltAdmitsKind: (kind: string) => void;
  };

/** Missing kind-scoped operator halt kind-scope port on MOVE first formation. */
export class MoveHaltGateMissingError extends Error {
  constructor() {
    super("signMoveStepsUnderLeases requires assertHaltAdmitsKind");
    this.name = "MoveHaltGateMissingError";
  }
}

/**
 * One lease from the dual-lease group acquired in ascending binary-UUID
 * sequence (step 1). This slice never acquires or re-acquires a lease; it presents the
 * epoch already held.
 */
export interface MoveHeldLease {
  readonly walletId: string;
  readonly leaseEpoch: bigint;
}

export interface MoveSigningLeases {
  readonly source: MoveHeldLease;
  readonly destination: MoveHeldLease;
}

// ── Durable preimage handle (branded — only a committed row produces one) ────────────────────

const DURABLE_MOVE_PREIMAGE_BRAND = Symbol.for("zupayments.DurableMovePreimage");

/**
 * Proof that these exact bytes are committed to operation_transactions. Obtainable only from
 * {@link readDurableMovePreimage}; an in-memory inner or a caller-built string is not
 * assignable to it, so "no signing call before a durable sign intent" is a type property.
 */
export interface DurableMovePreimage {
  readonly [key: symbol]: true | undefined;
  readonly operationId: string;
  readonly walletId: string;
  readonly leaseEpoch: bigint;
  readonly purpose: SigningPurpose;
  /** The exact persisted bytes, never re-serialized. */
  readonly preimageText: string;
  readonly preimageSha256: string;
}

export type MoveSignStep = "STEP_1" | "STEP_2";

export class MoveSigningStateError extends Error {
  constructor(
    message: string,
    readonly code:
      | "ATTEMPT_NOT_FOUND"
      | "WRONG_ATTEMPT_PHASE"
      | "PREIMAGE_MISSING"
      | "PERSISTED_DIGEST_MISMATCH"
      | "SAME_WALLET_BOTH_STEPS"
      | "PREIMAGE_NOT_DURABLE",
  ) {
    super(message);
    this.name = "MoveSigningStateError";
  }
}

const ATTEMPT_SELECT = `SELECT attempt_phase, inner_preimage_text, inner_sha256,
    step_1_signature, step_2_preimage_text, step_2_preimage_sha256
  FROM operation_transactions
  WHERE operation_id = $1 AND attempt_no = ${ONLY_ATTEMPT_NO}`;

/** The row-shaped facts each step reads back, and the phase the row must be at to read them. */
const STEP_READ = {
  STEP_1: {
    requiredPhase: "INNER_PREIMAGE_PERSISTED",
    textColumn: "inner_preimage_text",
    digestColumn: "inner_sha256",
    purpose: "SPLITCHAIN_STEP_1",
  },
  STEP_2: {
    requiredPhase: "STEP2_PREIMAGE_PERSISTED",
    textColumn: "step_2_preimage_text",
    digestColumn: "step_2_preimage_sha256",
    purpose: "SPLITCHAIN_STEP_2",
  },
} as const satisfies Record<
  MoveSignStep,
  { requiredPhase: string; textColumn: string; digestColumn: string; purpose: SigningPurpose }
>;

/**
 * Steps 3 and 7 — the signer reads only the persisted preimage. Reads the committed row,
 * requires it to be at the phase that authorizes this step, and re-derives the digest from the
 * persisted bytes rather than trusting the stored one. A digest that disagrees with its own
 * text means the row was rewritten under us; refuse rather than sign either version.
 */
export async function readDurableMovePreimage(
  query: SqlQueryFn,
  operationId: string,
  step: MoveSignStep,
  lease: MoveHeldLease,
): Promise<DurableMovePreimage> {
  const spec = STEP_READ[step];
  const rows = await query(ATTEMPT_SELECT, [operationId]);
  const row = rows[0];
  if (row === undefined) {
    throw new MoveSigningStateError(
      `operation ${operationId} has no transaction attempt: nothing durable to sign`,
      "ATTEMPT_NOT_FOUND",
    );
  }
  if (row.attempt_phase !== spec.requiredPhase) {
    throw new MoveSigningStateError(
      `operation ${operationId} is at ${String(row.attempt_phase)}, not ${spec.requiredPhase}: ${step} may not sign`,
      "WRONG_ATTEMPT_PHASE",
    );
  }
  const preimageText = row[spec.textColumn];
  const storedDigest = row[spec.digestColumn];
  if (typeof preimageText !== "string" || typeof storedDigest !== "string") {
    throw new MoveSigningStateError(
      `operation ${operationId} has no persisted ${spec.textColumn} to sign`,
      "PREIMAGE_MISSING",
    );
  }
  const recomputed = hashMovePreimageText(preimageText);
  if (recomputed !== storedDigest) {
    throw new MoveSigningStateError(
      `operation ${operationId} ${spec.digestColumn} does not match SHA-256 of the persisted ${spec.textColumn}`,
      "PERSISTED_DIGEST_MISMATCH",
    );
  }
  return Object.freeze({
    operationId,
    walletId: lease.walletId,
    leaseEpoch: lease.leaseEpoch,
    purpose: spec.purpose,
    preimageText,
    preimageSha256: recomputed,
    [DURABLE_MOVE_PREIMAGE_BRAND]: true as const,
  }) as DurableMovePreimage;
}

/** True when value came from {@link readDurableMovePreimage} (brand present). */
export function isDurableMovePreimage(value: unknown): value is DurableMovePreimage {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<symbol, unknown>)[DURABLE_MOVE_PREIMAGE_BRAND] === true
  );
}

/**
 * The SIGN(preimage_id) primitive at the signer boundary: an already-persisted exact
 * preimage plus the current wallet lease capability, and nothing else. Accepts only a
 * DurableMovePreimage — passing a constructed object is a type error.
 */
export function signDurableMovePreimage(
  preimage: DurableMovePreimage,
  deps: MoveSignerBoundaryDeps,
): Promise<SigningResult> {
  // Belt as well as braces: the type keeps a constructed object out at compile time, this keeps
  // it out at runtime, where an `as` cast or a JavaScript caller would otherwise get through.
  if (!isDurableMovePreimage(preimage)) {
    throw new MoveSigningStateError(
      "refusing to sign: the preimage did not come from a committed operation_transactions row",
      "PREIMAGE_NOT_DURABLE",
    );
  }
  return signUnderLease(deps, {
    walletId: preimage.walletId,
    operationId: preimage.operationId,
    leaseEpoch: preimage.leaseEpoch,
    purpose: preimage.purpose,
    preimageText: preimage.preimageText,
    expectedPreimageSha256: preimage.preimageSha256,
  });
}

// ── The two-step ceremony ────────────────────────────────────────────────────────────────────

export interface SignMoveStepsInput {
  readonly operationId: string;
  readonly leases: MoveSigningLeases;
  /** One DB-TX per call; each must commit before returning (steps 4, 6, 8). */
  readonly query: SqlQueryFn;
  /** Must carry the money-path admission gates — see {@link MoveSignerBoundaryDeps}. */
  readonly signerDeps: MoveSignerBoundaryDeps;
}

export interface SignedMoveSteps {
  readonly operationId: string;
  readonly innerPreimageText: string;
  readonly step1Signature: string;
  readonly step2PreimageText: string;
  readonly step2PreimageSha256: string;
  readonly step2Signature: string;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
}

/**
 * Steps 3–8. Consumes an attempt already at INNER_PREIMAGE_PERSISTED and the
 * two leases already held, and leaves it at STEP2_SIGNATURE_PERSISTED with both
 * signatures and the completed transaction durable.
 *
 * Nothing is caught here. A refused signer call or a rejected phase advance propagates with its
 * own typed error, leaving the attempt at its last committed phase for recovery to resume from;
 * swallowing one and continuing would be the blind retry the never-blind-retry rule forbids.
 */
export async function signMoveStepsUnderLeases(
  input: SignMoveStepsInput,
): Promise<SignedMoveSteps> {
  const { operationId, leases, query, signerDeps } = input;

  // MOVE first formation refuses under engaged halt before any vault call.
  // Injected (core ↛ operator); RECEIVE stays open because it never calls this path.
  if (typeof signerDeps.assertHaltAdmitsKind !== "function") {
    throw new MoveHaltGateMissingError();
  }
  signerDeps.assertHaltAdmitsKind("MOVE_INTERNAL");

  // Admission already refuses a self-move; assert it here too because signing the
  // same wallet twice would need two leases on one wallet, which the one-in-flight-per-wallet rule forbids outright.
  if (leases.source.walletId === leases.destination.walletId) {
    throw new MoveSigningStateError(
      `operation ${operationId}: source and destination are the same wallet`,
      "SAME_WALLET_BOTH_STEPS",
    );
  }

  // Step 3 — source signs the persisted inner.
  const inner = await readDurableMovePreimage(query, operationId, "STEP_1", leases.source);
  const step1 = await signDurableMovePreimage(inner, signerDeps);

  // Step 4 — DB-TX: step-1 signature, phase → STEP1_SIGNATURE_PERSISTED.
  // the one-in-flight-per-wallet rule: same capability the source signer used, re-checked under a
  // row lock in the statement that makes the signature durable (AttemptLeaseGuard).
  await advanceAttemptPhase(
    query,
    operationId,
    "STEP1_SIGNATURE_PERSISTED",
    {
      step_1_signature: step1.signature,
    },
    {
      walletId: leases.source.walletId,
      operationId,
      leaseEpoch: leases.source.leaseEpoch,
    },
  );

  return completeMoveStep2(
    query,
    signerDeps,
    operationId,
    leases.destination,
    inner.preimageText,
    step1.signature,
  );
}

/**
 * Crash row: the step-1 signature is durable but the step-2 preimage is not (between
 * steps 4 and 6). Re-derives the step-2 preimage from the *persisted* inner text and the
 * *persisted* step-1 signature — the same two byte strings the first pass used — so the resumed
 * build is byte-identical by construction rather than by luck. Never re-signs step 1: that
 * signature already exists and the frozen phase CHECKs make it unoverwritable.
 */
export async function resumeMoveStep2FromPersistedStep1(input: {
  readonly operationId: string;
  readonly destinationLease: MoveHeldLease;
  readonly query: SqlQueryFn;
  /** Must carry the money-path admission gates — see {@link MoveSignerBoundaryDeps}. */
  readonly signerDeps: MoveSignerBoundaryDeps;
}): Promise<SignedMoveSteps> {
  const { operationId, destinationLease, query, signerDeps } = input;
  const rows = await query(ATTEMPT_SELECT, [operationId]);
  const row = rows[0];
  if (row === undefined) {
    throw new MoveSigningStateError(
      `operation ${operationId} has no transaction attempt to resume`,
      "ATTEMPT_NOT_FOUND",
    );
  }
  if (row.attempt_phase !== "STEP1_SIGNATURE_PERSISTED") {
    throw new MoveSigningStateError(
      `operation ${operationId} is at ${String(row.attempt_phase)}, not STEP1_SIGNATURE_PERSISTED: nothing to resume`,
      "WRONG_ATTEMPT_PHASE",
    );
  }
  const innerPreimageText = row.inner_preimage_text;
  const step1Signature = row.step_1_signature;
  if (typeof innerPreimageText !== "string" || typeof step1Signature !== "string") {
    throw new MoveSigningStateError(
      `operation ${operationId} is missing the persisted inner or step-1 signature`,
      "PREIMAGE_MISSING",
    );
  }
  return completeMoveStep2(
    query,
    signerDeps,
    operationId,
    destinationLease,
    innerPreimageText,
    step1Signature,
  );
}

/** Steps 5–8, from an attempt whose step-1 signature is already durable. */
async function completeMoveStep2(
  query: SqlQueryFn,
  signerDeps: MoveSignerBoundaryDeps,
  operationId: string,
  destinationLease: MoveHeldLease,
  innerPreimageText: string,
  step1Signature: string,
): Promise<SignedMoveSteps> {
  // Step 5 — round-trip guard on the persisted inner, then splice the two-key step-2 preimage.
  // buildMoveStep2PreimageText re-asserts the guard; asserting here as well keeps the
  // step-5 sequencing explicit at the call site rather than incidental to the builder.
  assertPersistedInnerRoundTrips(innerPreimageText);
  const step2PreimageText = buildMoveStep2PreimageText(innerPreimageText, step1Signature);
  const step2PreimageSha256 = hashMovePreimageText(step2PreimageText);

  // Step 6 — DB-TX: exact step-2 preimage + digest. Commits before the destination signer.
  await advanceAttemptPhase(query, operationId, "STEP2_PREIMAGE_PERSISTED", {
    step_2_preimage_text: step2PreimageText,
    step_2_preimage_sha256: step2PreimageSha256,
  });

  // Step 7 — destination signs the persisted step-2 preimage, read back out of the row.
  const step2Preimage = await readDurableMovePreimage(
    query,
    operationId,
    "STEP_2",
    destinationLease,
  );
  const step2 = await signDurableMovePreimage(step2Preimage, signerDeps);

  // Step 8 — DB-TX: step-2 signature + completed transaction, phase → STEP2_SIGNATURE_PERSISTED.
  const completedTransactionText = buildMoveCompletedTransactionText(
    step2Preimage.preimageText,
    step2.signature,
  );
  const completedTransactionSha256 = hashMovePreimageText(completedTransactionText);
  // the one-in-flight-per-wallet rule: destination lease capability re-checked as the signature commits.
  await advanceAttemptPhase(
    query,
    operationId,
    "STEP2_SIGNATURE_PERSISTED",
    {
      step_2_signature: step2.signature,
      completed_transaction_text: completedTransactionText,
      completed_transaction_sha256: completedTransactionSha256,
    },
    {
      walletId: destinationLease.walletId,
      operationId,
      leaseEpoch: destinationLease.leaseEpoch,
    },
  );

  return {
    operationId,
    innerPreimageText,
    step1Signature,
    step2PreimageText: step2Preimage.preimageText,
    step2PreimageSha256: step2Preimage.preimageSha256,
    step2Signature: step2.signature,
    completedTransactionText,
    completedTransactionSha256,
  };
}
