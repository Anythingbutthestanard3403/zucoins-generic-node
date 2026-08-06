// Move-formation steps 2-5 for MOVE_INTERNAL: observe both wallets while
// both leases are held, halt on any ambiguous read, recheck the destination after both reads, and
// persist the operation's one exact `zp-move-internal-expected-v1` artifact plus both T0 bindings
// BEFORE formation begins. Generic-core neutrality, the landing-path oracle and the
// canonical ZKZ amount contract all bind here.
//
// Why durable: 09-operations-recovery.md axiom 3 — "persist before crossing an irreversible
// boundary; exact preimage precedes signing". A crash after this function returns must be
// resumable from the persisted bytes alone, never from anything re-derived in memory.
//
// Schema contract: ../schema/move-baseline-binding.sql (+ .contract.ts). This module is
// driver-agnostic and never imports `pg` (node-core is network-contained): the composition root
// injects an executor. The frozen port exposes no transaction seam, so the caller passes a
// transaction-scoped executor — every money-path write, this one included, belongs
// in one SERIALIZABLE transaction. The writes are sequenced so the exclusive claim
// (move_observation_evidence, primary key on operation_id) lands first: a concurrent second
// capture for the same operation is rejected by the database before any other row exists.

import {
  captureDualBaselines,
  type DualBaselineCapture,
  type DualBaselineRejectionReason,
} from "../protocol/move-baseline.js";
import { parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";
import { buildMoveInternalExpectedArtifact } from "../protocol/suite/builders.js";
import type { WalletStateProjection } from "../protocol/wallet-role.js";
import type { WalletLease } from "@zucoins/generic-node-contracts/wallet-state";

export const MOVE_INTERNAL_ARTIFACT_PURPOSE = "zp-move-internal-expected-v1" as const;
export const MOVE_INTERNAL_CANONICAL_VERSION = 1 as const;

/** Step 2: the two observation roles a move captures, one per wallet. */
export const MOVE_T0_OBSERVATION_ROLES = ["MOVE_SOURCE_T0", "MOVE_DESTINATION_T0"] as const;
export type MoveT0ObservationRole = (typeof MOVE_T0_OBSERVATION_ROLES)[number];

/** The `operation_observation_bindings.evidence_role` values this step writes. */
export const MOVE_T0_EVIDENCE_ROLES = ["SOURCE_T0", "DESTINATION_T0"] as const;

/**
 * For a validated never-used node-generated wallet, S0="", P0="", and B0="0": empty strings
 * are the canonical genesis projection, while `null` means a projection was unavailable and
 * therefore cannot be armed or verified. Any response that cannot support an unambiguous
 * projection is INDETERMINATE; it must never be treated as an empty wallet or a zero
 * balance. INDETERMINATE is therefore its own outcome, not a projection with null fields — the
 * type makes "treat it as zero" unrepresentable rather than merely discouraged.
 */
export type ObservationOutcome =
  | {
      readonly kind: "VERIFIED";
      readonly observationId: string;
      readonly projection: WalletStateProjection;
    }
  | { readonly kind: "INDETERMINATE"; readonly detail: string }
  | { readonly kind: "UNVERIFIED"; readonly detail: string };

export interface MoveBaselineObserver {
  observe(walletPublicKey: string, role: MoveT0ObservationRole): Promise<ObservationOutcome>;
}

/**
 * Step 4: the destination recheck AFTER both reads. Distinct from the admission-time check
 * it closes the window in which a destination blessed at admission is retired or
 * loses recovery verification before its baseline is observed.
 */
export interface DestinationRecheck {
  readonly eligible: boolean;
  readonly detail: string;
}

export interface DestinationEligibilityReader {
  recheckDestination(destinationId: string): Promise<DestinationRecheck>;
}

/**
 * The key-custody rule: node-core never holds a private key. The node identity key that signs the
 * artifact lives in the node vault, and the composition root
 * injects this narrow signing capability.
 */
export interface NodeIdentitySignature {
  readonly signingKeyId: string;
  readonly signature: string;
}

export interface NodeIdentitySigner {
  signWithNodeIdentity(preimageBytes: Uint8Array): Promise<NodeIdentitySignature>;
}

/** The node-postgres-shaped surface this module depends on; `pg.PoolClient` satisfies it. */
export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

// Statement catalogue. The real-PostgreSQL suite drives these exact strings, so a column-list
// change that the schema does not carry fails loudly rather than drifting.
export const STATEMENTS = {
  INSERT_EVIDENCE:
    "INSERT INTO move_observation_evidence (operation_id, source_t0_observation_id, destination_t0_observation_id) VALUES ($1, $2, $3)",
  INSERT_BINDING:
    "INSERT INTO operation_observation_bindings (operation_id, observation_id, evidence_role, wallet_public_key) VALUES ($1, $2, $3, $4)",
  INSERT_ARTIFACT:
    "INSERT INTO operation_expected_artifacts (id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
} as const;

export type MoveBaselineBindingRejectionReason =
  | DualBaselineRejectionReason
  | "source_observation_indeterminate"
  | "destination_observation_indeterminate"
  | "source_observation_unverified"
  | "destination_observation_unverified"
  | "shared_t0_observation"
  | "destination_not_eligible"
  | "invalid_artifact_field"
  | "already_captured";

export interface PersistedExpectedArtifact {
  readonly id: string;
  readonly operationId: string;
  readonly purpose: typeof MOVE_INTERNAL_ARTIFACT_PURPOSE;
  readonly canonicalVersion: typeof MOVE_INTERNAL_CANONICAL_VERSION;
  readonly signingKeyId: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signature: string;
}

export interface MoveBaselineBinding {
  readonly capture: DualBaselineCapture;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly artifact: PersistedExpectedArtifact;
}

export type MoveBaselineBindingResult =
  | { readonly ok: true; readonly binding: MoveBaselineBinding }
  | {
      readonly ok: false;
      readonly reason: MoveBaselineBindingRejectionReason;
      readonly detail: string;
    };

export interface MoveBaselineBindingInput {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly expectedArtifactId: string;
  readonly sourceWalletId: string;
  readonly sourceWalletPublicKey: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly destinationWalletPublicKey: string;
  readonly amountZkz: string;
  readonly spawnedFromOperationId: string | null;
  readonly referencesOperationId: string | null;
  readonly sourceLease: WalletLease;
  readonly destinationLease: WalletLease;
  readonly capturedAt: number;
  readonly observer: MoveBaselineObserver;
  readonly destinations: DestinationEligibilityReader;
  readonly signer: NodeIdentitySigner;
  readonly sql: SqlExecutor;
}

function reject(
  reason: MoveBaselineBindingRejectionReason,
  detail: string,
): MoveBaselineBindingResult {
  return { ok: false, reason, detail };
}

const SQLSTATE_UNIQUE_VIOLATION = "23505";

function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === SQLSTATE_UNIQUE_VIOLATION;
}

/**
 * Steps 2-5. Returns only after the artifact and both T0 bindings are durable, so a caller
 * that receives `ok: true` may begin formation knowing a crash resumes from persisted
 * bytes. Every rejection path returns BEFORE the first write and before the signer is invoked:
 * an ambiguous read, an ineligible destination, or a failed predicate leaves no partial evidence
 * and produces no signature.
 */
export async function captureAndBindMoveBaselines(
  input: MoveBaselineBindingInput,
): Promise<MoveBaselineBindingResult> {
  // Step 2 — OBSERVE both wallets while both leases remain held.
  const sourceObservation = await input.observer.observe(
    input.sourceWalletPublicKey,
    "MOVE_SOURCE_T0",
  );
  const destinationObservation = await input.observer.observe(
    input.destinationWalletPublicKey,
    "MOVE_DESTINATION_T0",
  );

  // Step 3 (first half) — both observations verified, both balances unambiguous. An
  // INDETERMINATE read halts the flow; it is never coerced into a genesis or zero baseline.
  if (sourceObservation.kind === "INDETERMINATE") {
    return reject("source_observation_indeterminate", sourceObservation.detail);
  }
  if (sourceObservation.kind === "UNVERIFIED") {
    return reject("source_observation_unverified", sourceObservation.detail);
  }
  if (destinationObservation.kind === "INDETERMINATE") {
    return reject("destination_observation_indeterminate", destinationObservation.detail);
  }
  if (destinationObservation.kind === "UNVERIFIED") {
    return reject("destination_observation_unverified", destinationObservation.detail);
  }

  // The two T0s must be distinct observation ROWS even when both wallets project
  // identical genesis state. The database CHECK is the authority; this returns the typed
  // rejection instead of letting an observer bug surface as a constraint exception.
  if (sourceObservation.observationId === destinationObservation.observationId) {
    return reject(
      "shared_t0_observation",
      `both T0 baselines cite observation ${sourceObservation.observationId}`,
    );
  }

  // Step 3 (second half) — lease roles, distinct wallets, canonical positive amount, exact
  // decimal B0 >= amount, and role-consistent projections.
  const captured = captureDualBaselines({
    operationId: input.operationId,
    sourceWalletPublicKey: input.sourceWalletPublicKey,
    destinationWalletPublicKey: input.destinationWalletPublicKey,
    sourceLease: input.sourceLease,
    destinationLease: input.destinationLease,
    sourceBaseline: sourceObservation.projection,
    destinationBaseline: destinationObservation.projection,
    amountZkz: input.amountZkz,
    capturedAt: input.capturedAt,
  });
  if (!captured.ok) return reject(captured.reason, captured.detail);

  // Step 4 — recheck the destination AFTER both reads.
  const recheck = await input.destinations.recheckDestination(input.destinationId);
  if (!recheck.eligible) {
    return reject("destination_not_eligible", recheck.detail);
  }

  // Step 5 — construct the one exact artifact. Field sequence and byte assembly are the frozen
  // suite serializer's (generic core neutrality); this module supplies values and never re-stringifies the result.
  let preimage;
  try {
    preimage = buildMoveInternalExpectedArtifact({
      node_id: parseUuid(input.nodeId),
      implementer_id: parseUuid(input.implementerId),
      operation_id: parseUuid(input.operationId),
      source_wallet_id: parseUuid(input.sourceWalletId),
      source_pubkey: parseWalletPublicKey(input.sourceWalletPublicKey),
      destination_id: parseUuid(input.destinationId),
      destination_wallet_id: parseUuid(input.destinationWalletId),
      destination_pubkey: parseWalletPublicKey(input.destinationWalletPublicKey),
      amount_zkz: captured.capture.amountZkz,
      spawned_from_operation_id:
        input.spawnedFromOperationId === null ? null : parseUuid(input.spawnedFromOperationId),
      references_operation_id:
        input.referencesOperationId === null ? null : parseUuid(input.referencesOperationId),
    });
  } catch (error) {
    return reject("invalid_artifact_field", (error as Error).message);
  }

  const signed = await input.signer.signWithNodeIdentity(preimage.preimageBytes);

  try {
    // Exclusive claim first: one move-evidence row per operation.
    await input.sql.query(STATEMENTS.INSERT_EVIDENCE, [
      input.operationId,
      sourceObservation.observationId,
      destinationObservation.observationId,
    ]);
    await input.sql.query(STATEMENTS.INSERT_BINDING, [
      input.operationId,
      sourceObservation.observationId,
      "SOURCE_T0",
      input.sourceWalletPublicKey,
    ]);
    await input.sql.query(STATEMENTS.INSERT_BINDING, [
      input.operationId,
      destinationObservation.observationId,
      "DESTINATION_T0",
      input.destinationWalletPublicKey,
    ]);
    await input.sql.query(STATEMENTS.INSERT_ARTIFACT, [
      input.expectedArtifactId,
      input.operationId,
      MOVE_INTERNAL_ARTIFACT_PURPOSE,
      MOVE_INTERNAL_CANONICAL_VERSION,
      signed.signingKeyId,
      preimage.preimageText,
      preimage.sha256,
      signed.signature,
    ]);
  } catch (error) {
    if (isUniqueViolation(error)) {
      return reject(
        "already_captured",
        `operation ${input.operationId} already has durable move baselines`,
      );
    }
    throw error;
  }

  return {
    ok: true,
    binding: {
      capture: captured.capture,
      sourceT0ObservationId: sourceObservation.observationId,
      destinationT0ObservationId: destinationObservation.observationId,
      artifact: {
        id: input.expectedArtifactId,
        operationId: input.operationId,
        purpose: MOVE_INTERNAL_ARTIFACT_PURPOSE,
        canonicalVersion: MOVE_INTERNAL_CANONICAL_VERSION,
        signingKeyId: signed.signingKeyId,
        preimageText: preimage.preimageText,
        preimageSha256: preimage.sha256,
        signature: signed.signature,
      },
    },
  };
}
