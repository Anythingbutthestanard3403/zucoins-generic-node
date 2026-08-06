// the MOVE_INTERNAL operation proof policy.
//
// ("MOVE_INTERNAL proof"), frozen as MOVE_INTERNAL_POLICY.verificationSteps.
// A move is one dual-signed transaction observed twice — once from each leased wallet — so
// both paths must confirm the SAME transaction. (node-generated, leased, blessed,
// recovery-verified) are custody facts the policy cannot read itself; they arrive as typed
// evidence and fold into the two role predicates alongside the computed role. All amounts
// are ZKZ.
import { evaluateInternalMoveDelta } from "../../protocol/economic-predicates.js";
import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import type { ParsedSettledTransaction } from "../../verifier/gateway-envelope.js";
import {
  verifySettledTransaction,
  type TransactionVerifyVerdict,
} from "../../verifier/transaction-verify.js";
import type { EvidenceKind } from "../types.js";
import {
  AMOUNT_DELTA_REASONS,
  DESTINATION_DELTA_DETAIL_PREFIX,
  attributeDelta,
  decide,
  describeArtifactRejection,
  describeTransactionRejection,
  finalizeOperationProof,
  held,
  mismatch,
  undecided,
  type ArtifactVerification,
  type DeltaPredicateOwner,
  type EvaluatedPredicate,
  type OperationProofResult,
} from "./shared.js";

/** the source wallet's custody facts, read from the node's own lease records. */
export interface MoveSourceCustody {
  readonly walletId: string;
  readonly nodeGenerated: boolean;
  readonly leaseGroupId: string;
  readonly continuouslyLeased: boolean;
}

/** the destination wallet's custody facts. */
export interface MoveDestinationCustody {
  readonly walletId: string;
  readonly nodeGenerated: boolean;
  readonly blessedUnderB1: boolean;
  readonly recoveryVerified: boolean;
}

export interface MoveSourcePath {
  readonly walletPublicKey: string;
  readonly baseline: WalletStateProjection;
  /** The source wallet's own observation of the move transaction M. */
  readonly observation: ParsedSettledTransaction;
  readonly custody: MoveSourceCustody;
}

export interface MoveDestinationPath {
  readonly walletPublicKey: string;
  readonly baseline: WalletStateProjection;
  /** The destination wallet's own, independently read observation of M. */
  readonly observation: ParsedSettledTransaction;
  readonly custody: MoveDestinationCustody;
}

export interface MoveExpectedArtifact {
  readonly amount_zkz: string;
  readonly source_wallet_id: string;
  readonly destination_wallet_id: string;
  readonly source_pubkey: string;
  readonly destination_pubkey: string;
  /** The parent receive's step_2_signature for a spawned move; null for an ordinary one. */
  readonly spawn_reference: string | null;
}

/** the parent receive a spawned move must remain one hop from, under one lease group. */
export interface SpawnedMoveParent {
  readonly receiveTransactionStepTwoSignature: string;
  readonly leaseGroupId: string;
}

export interface MovePolicyInput {
  readonly artifact: MoveExpectedArtifact;
  readonly artifactVerification: ArtifactVerification;
  readonly source: MoveSourcePath | null;
  readonly destination: MoveDestinationPath | null;
  readonly spawnedFrom?: SpawnedMoveParent | null;
}

const MOVE_PREDICATE_ORDER = [
  "send_artifact_verify",
  "source_role_verify",
  "source_predecessor_bind",
  "destination_role_verify",
  "destination_predecessor_bind",
  "source_balance_delta",
  "destination_balance_delta",
  "artifact_key_bindsource",
  "spawn_continuity",
] as const;

// The one `evaluateInternalMoveDelta` call answers four frozen predicates. Attribution is by
// rejection reason, and the two balance legs are told apart by own detail label
// pinned by move.test.ts so a relabel there fails a test instead of mislabelling a proof.
const MOVE_DELTA_OWNERS: readonly DeltaPredicateOwner[] = [
  {
    predicate: "source_balance_delta",
    owns: (rejection) =>
      AMOUNT_DELTA_REASONS.includes(rejection.reason) &&
      !rejection.detail.startsWith(DESTINATION_DELTA_DETAIL_PREFIX),
  },
  {
    predicate: "destination_balance_delta",
    owns: (rejection) =>
      AMOUNT_DELTA_REASONS.includes(rejection.reason) &&
      rejection.detail.startsWith(DESTINATION_DELTA_DETAIL_PREFIX),
  },
  { predicate: "artifact_key_bindsource", owns: (rejection) => rejection.reason === "artifact_binding_mismatch" },
  { predicate: "spawn_continuity", owns: (rejection) => rejection.reason === "spawn_continuity_mismatch" },
];

export function evaluateMoveProof(input: MovePolicyInput): OperationProofResult {
  const { artifact, destination, source } = input;
  const evidencePresent: EvidenceKind[] = [
    ...(source === null ? [] : (["source_path_confirmation"] as const)),
    ...(destination === null ? [] : (["destination_path_confirmation"] as const)),
  ];

  const predicates: EvaluatedPredicate[] = [
    evaluateArtifact(input),
  ];

  if (source === null || destination === null) {
    return finalizeOperationProof("MOVE_INTERNAL", MOVE_PREDICATE_ORDER, predicates, evidencePresent);
  }

  const sourceVerdict = verifySettledTransaction(source.observation, source.walletPublicKey);
  const destinationVerdict = verifySettledTransaction(
    destination.observation,
    destination.walletPublicKey,
  );

  predicates.push(evaluateSourceRole(source, sourceVerdict));
  predicates.push(evaluateDestinationRole(source, destination, destinationVerdict));

  if (sourceVerdict.verdict !== "VERIFIED" || destinationVerdict.verdict !== "VERIFIED") {
    predicates.push(
      undecided("source_predecessor_bind", "not decided: a path observation did not verify"),
      undecided("destination_predecessor_bind", "not decided: a path observation did not verify"),
      ...MOVE_DELTA_OWNERS.map(({ predicate }) =>
        undecided(predicate, "not decided: a path observation did not verify"),
      ),
    );
    return finalizeOperationProof("MOVE_INTERNAL", MOVE_PREDICATE_ORDER, predicates, evidencePresent);
  }

  predicates.push(
    decide(
      "source_predecessor_bind",
      sourceVerdict.projection.P === source.baseline.S,
      `source P (${sourceVerdict.projection.P}) against source baseline S (${source.baseline.S})`,
    ),
    decide(
      "destination_predecessor_bind",
      destinationVerdict.projection.P === destination.baseline.S,
      `destination P (${destinationVerdict.projection.P}) against destination baseline S (${destination.baseline.S})`,
    ),
  );

  const delta = attributeDelta(
    evaluateInternalMoveDelta({
      source: {
        baseline: source.baseline,
        candidateTx: sourceVerdict.transaction,
        walletPublicKey: source.walletPublicKey,
      },
      destination: {
        baseline: destination.baseline,
        candidateTx: destinationVerdict.transaction,
        walletPublicKey: destination.walletPublicKey,
      },
      operation: {
        amountZkz: artifact.amount_zkz,
        sourcePubkey: artifact.source_pubkey,
        destinationPubkey: artifact.destination_pubkey,
      },
      ...(input.spawnedFrom
        ? {
            spawnedFromReceive: {
              receiveTransactionStepTwoSignature: input.spawnedFrom.receiveTransactionStepTwoSignature,
            },
          }
        : {}),
    }),
    MOVE_DELTA_OWNERS,
  );

  // 8's lease half: one-hop continuity is only continuity if the spawned move stayed
  // inside the parent receive's lease group without interruption. The chain half is the
  // delta evaluator's; this is the custody half it cannot see.
  predicates.push(
    ...delta.map((evaluated) =>
      evaluated.predicate === "spawn_continuity" && evaluated.passed
        ? spawnLeaseContinuity(source, input.spawnedFrom ?? null)
        : evaluated,
    ),
  );

  return finalizeOperationProof("MOVE_INTERNAL", MOVE_PREDICATE_ORDER, predicates, evidencePresent);
}

function evaluateArtifact(input: MovePolicyInput): EvaluatedPredicate {
  if (!input.artifactVerification.ok) {
    return mismatch(
      "send_artifact_verify",
      `move expected-artifact envelope rejected: ${describeArtifactRejection(input.artifactVerification)}`,
    );
  }
  const { artifact, destination, source, spawnedFrom } = input;
  const expectedSpawnReference = spawnedFrom?.receiveTransactionStepTwoSignature ?? null;
  if (artifact.spawn_reference !== expectedSpawnReference) {
    return mismatch(
      "send_artifact_verify",
      `artifact spawn_reference ${String(artifact.spawn_reference)} does not match the parent receive ${String(expectedSpawnReference)}`,
    );
  }
  if (source !== null && artifact.source_wallet_id !== source.custody.walletId) {
    return mismatch("send_artifact_verify", "artifact source_wallet_id is not the leased source wallet");
  }
  if (destination !== null && artifact.destination_wallet_id !== destination.custody.walletId) {
    return mismatch(
      "send_artifact_verify",
      "artifact destination_wallet_id is not the leased destination wallet",
    );
  }
  return held("send_artifact_verify", "move artifact envelope verified and bound to both leased wallets");
}

/** 4a — the source is the step-1 sender of a verified M, node-generated and leased throughout. */
function evaluateSourceRole(
  source: MoveSourcePath,
  verdict: TransactionVerifyVerdict,
): EvaluatedPredicate {
  if (verdict.verdict !== "VERIFIED") return describeUnverified("source", verdict);
  const verified = verdict;
  if (verified.projection.role !== "sender") {
    return mismatch("source_role_verify", `source wallet role in M is ${verified.projection.role}, not sender`);
  }
  if (!source.custody.nodeGenerated) {
    return mismatch("source_role_verify", "source wallet is not node-generated");
  }
  if (!source.custody.continuouslyLeased) {
    return mismatch("source_role_verify", "source wallet was not continuously leased across the move");
  }
  return held("source_role_verify", "source wallet is the step-1 sender of a verified M, node-generated and leased");
}

/** 5a — the destination is the step-2 receiver of the SAME verified M, blessed and recovery-verified. */
function evaluateDestinationRole(
  source: MoveSourcePath,
  destination: MoveDestinationPath,
  verdict: TransactionVerifyVerdict,
): EvaluatedPredicate {
  if (verdict.verdict !== "VERIFIED") return describeUnverified("destination", verdict);
  const verified = verdict;
  if (verified.projection.role !== "receiver") {
    return mismatch(
      "destination_role_verify",
      `destination wallet role in M is ${verified.projection.role}, not receiver`,
    );
  }
  // Two independently-read observations that happen to agree on the amount are not a move:
  // requires both paths to confirm one transaction, identified by its step_2_signature.
  if (destination.observation.step_2_signature !== source.observation.step_2_signature) {
    return mismatch(
      "destination_role_verify",
      "destination path observed a different transaction from the source path (step_2_signature differs)",
    );
  }
  if (!destination.custody.nodeGenerated) {
    return mismatch("destination_role_verify", "destination wallet is not node-generated");
  }
  if (!destination.custody.blessedUnderB1) {
    return mismatch("destination_role_verify", "destination wallet is not blessed under B1");
  }
  if (!destination.custody.recoveryVerified) {
    return mismatch("destination_role_verify", "destination wallet is not recovery-verified");
  }
  return held(
    "destination_role_verify",
    "destination wallet is the step-2 receiver of the same verified M, blessed and recovery-verified",
  );
}

function describeUnverified(
  leg: "source" | "destination",
  verdict: Exclude<TransactionVerifyVerdict, { verdict: "VERIFIED" }>,
): EvaluatedPredicate {
  const predicate = leg === "source" ? "source_role_verify" : "destination_role_verify";
  switch (verdict.verdict) {
    case "MALFORMED_TRANSACTION":
      return mismatch(
        predicate,
        `${leg} path observation rejected: ${describeTransactionRejection(verdict.rejection)}`,
      );
    case "UNVERIFIED_SIGNATURE":
      return mismatch(predicate, `${leg} path observation step ${verdict.failedStep} signature did not verify`);
    case "WALLET_ROLE_INVALID":
      return mismatch(predicate, `${leg} path: ${verdict.detail}`);
  }
}

function spawnLeaseContinuity(
  source: MoveSourcePath,
  spawnedFrom: SpawnedMoveParent | null,
): EvaluatedPredicate {
  if (spawnedFrom === null) {
    return held("spawn_continuity", "not a spawned move — one-hop continuity does not apply");
  }
  if (source.custody.leaseGroupId !== spawnedFrom.leaseGroupId) {
    return mismatch(
      "spawn_continuity",
      `source lease group ${source.custody.leaseGroupId} is not the parent receive's ${spawnedFrom.leaseGroupId}`,
    );
  }
  if (!source.custody.continuouslyLeased) {
    return mismatch("spawn_continuity", "lease was interrupted between the parent receive and this move");
  }
  return held("spawn_continuity", "spawned move is one hop from the parent receive under an unbroken lease");
}
