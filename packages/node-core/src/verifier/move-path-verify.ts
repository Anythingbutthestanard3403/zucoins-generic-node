// MOVE_INTERNAL dual-path verification.
//
// A MOVE lands only when BOTH wallet paths confirm independently:
// Source path (debit): observation evidence links M to Ts0, balance delta == amount.
// Destination path (credit): observation evidence links M to Td0, balance delta == amount.
//
// Asymmetric confirmation (one path verified, the other not) yields NEEDS_ATTENTION —
// never a partial settlement. This module is pure: typed input, typed verdict out;
// no DB write, no state mutation, no retry authority.
import { compareAmounts, subtractAmounts } from "@zucoins/generic-node-contracts/amounts";

export const MOVE_PATH_VERIFY_OUTCOMES = [
  "BOTH_PATHS_VERIFIED",
  "SOURCE_ONLY_VERIFIED",
  "DESTINATION_ONLY_VERIFIED",
  "NEITHER_PATH_VERIFIED",
] as const;

export type MovePathVerifyOutcome = (typeof MOVE_PATH_VERIFY_OUTCOMES)[number];

export const MOVE_PATH_REJECTION_REASONS = [
  "SOURCE_PREDECESSOR_MISMATCH",
  "SOURCE_BALANCE_DELTA_MISMATCH",
  "SOURCE_KEY_MISMATCH",
  "DESTINATION_PREDECESSOR_MISMATCH",
  "DESTINATION_BALANCE_DELTA_MISMATCH",
  "DESTINATION_KEY_MISMATCH",
  "OBSERVATION_EVIDENCE_MISSING",
  "OPERATION_LINKAGE_MISMATCH",
] as const;

export type MovePathRejectionReason = (typeof MOVE_PATH_REJECTION_REASONS)[number];

export interface PathObservation {
  readonly walletPublicKey: string;
  readonly stateSignature: string;
  readonly balance: string;
  readonly transactionSignature: string;
}

export interface MovePathEvidence {
  readonly baselineObservation: PathObservation;
  readonly settledObservation: PathObservation;
  readonly operationId: string;
}

export interface MoveArtifact {
  readonly sourcePublicKey: string;
  readonly destinationPublicKey: string;
  readonly amountZkz: string;
  readonly operationId: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
  readonly previousStep1StateSignature: string;
  readonly previousStep2StateSignature: string;
}

export interface PathVerificationFailure {
  readonly path: "source" | "destination";
  readonly reason: MovePathRejectionReason;
}

export interface MovePathVerifyVerdict {
  readonly outcome: MovePathVerifyOutcome;
  readonly sourceVerified: boolean;
  readonly destinationVerified: boolean;
  readonly failures: readonly PathVerificationFailure[];
}

function verifySourcePath(
  evidence: MovePathEvidence,
  artifact: MoveArtifact,
): PathVerificationFailure[] {
  const failures: PathVerificationFailure[] = [];
  const { baselineObservation, settledObservation, operationId } = evidence;

  if (!baselineObservation || !settledObservation) {
    failures.push({ path: "source", reason: "OBSERVATION_EVIDENCE_MISSING" });
    return failures;
  }

  if (operationId !== artifact.operationId) {
    failures.push({ path: "source", reason: "OPERATION_LINKAGE_MISMATCH" });
  }

  if (baselineObservation.walletPublicKey !== artifact.sourcePublicKey) {
    failures.push({ path: "source", reason: "SOURCE_KEY_MISMATCH" });
  }

  // Predicate 4: M.inner.previous_step_1_state_signature == Ts0.S
  if (baselineObservation.stateSignature !== artifact.previousStep1StateSignature) {
    failures.push({ path: "source", reason: "SOURCE_PREDECESSOR_MISMATCH" });
  }

  // Predicate 6 (source leg): Ts0.B - Ts1.B == amount_zkz
  const debit = subtractAmounts(baselineObservation.balance, settledObservation.balance);
  if (compareAmounts(debit, artifact.amountZkz) !== 0) {
    failures.push({ path: "source", reason: "SOURCE_BALANCE_DELTA_MISMATCH" });
  }

  return failures;
}

function verifyDestinationPath(
  evidence: MovePathEvidence,
  artifact: MoveArtifact,
): PathVerificationFailure[] {
  const failures: PathVerificationFailure[] = [];
  const { baselineObservation, settledObservation, operationId } = evidence;

  if (!baselineObservation || !settledObservation) {
    failures.push({ path: "destination", reason: "OBSERVATION_EVIDENCE_MISSING" });
    return failures;
  }

  if (operationId !== artifact.operationId) {
    failures.push({ path: "destination", reason: "OPERATION_LINKAGE_MISMATCH" });
  }

  if (baselineObservation.walletPublicKey !== artifact.destinationPublicKey) {
    failures.push({ path: "destination", reason: "DESTINATION_KEY_MISMATCH" });
  }

  // Predicate 5: M.inner.previous_step_2_state_signature == Td0.S
  if (baselineObservation.stateSignature !== artifact.previousStep2StateSignature) {
    failures.push({ path: "destination", reason: "DESTINATION_PREDECESSOR_MISMATCH" });
  }

  // Predicate 6 (destination leg): Td1.B - Td0.B == amount_zkz
  const credit = subtractAmounts(settledObservation.balance, baselineObservation.balance);
  if (compareAmounts(credit, artifact.amountZkz) !== 0) {
    failures.push({ path: "destination", reason: "DESTINATION_BALANCE_DELTA_MISMATCH" });
  }

  return failures;
}

export function verifyMoveDualPath(
  sourceEvidence: MovePathEvidence,
  destinationEvidence: MovePathEvidence,
  artifact: MoveArtifact,
): MovePathVerifyVerdict {
  const sourceFailures = verifySourcePath(sourceEvidence, artifact);
  const destinationFailures = verifyDestinationPath(destinationEvidence, artifact);

  const sourceVerified = sourceFailures.length === 0;
  const destinationVerified = destinationFailures.length === 0;

  let outcome: MovePathVerifyOutcome;
  if (sourceVerified && destinationVerified) {
    outcome = "BOTH_PATHS_VERIFIED";
  } else if (sourceVerified) {
    outcome = "SOURCE_ONLY_VERIFIED";
  } else if (destinationVerified) {
    outcome = "DESTINATION_ONLY_VERIFIED";
  } else {
    outcome = "NEITHER_PATH_VERIFIED";
  }

  return {
    outcome,
    sourceVerified,
    destinationVerified,
    failures: [...sourceFailures, ...destinationFailures],
  };
}
