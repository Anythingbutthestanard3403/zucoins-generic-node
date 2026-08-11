// SEND_EXTERNAL single formation-and-signing act.
// Formation steps 6–8 plus the post-sign commit; exact partial only.
//
// Sequence (steps 4–10):
// 1. Construct the exact sender inner from the held lease + two observations (step 6).
// 2. DB-TX durable sign intent: insert external_send_sign_intents + operation_transactions
// at INNER_PREIMAGE_PERSISTED; CAS formation_state APPROVED_UNSIGNED → SIGNING_CLAIMED.
// Commit BEFORE any signer call.
// 3. SIGN the persisted inner_preimage_text under the source lease capability.
// 4. Build the transfer code from the *persisted* inner text + *persisted* step-1 signature
// without parsing/reserializing either (step 2).
// 5. DB-TX: persist step-1 signature + partial at STEP1_SIGNATURE_PERSISTED; transition
// APPROVED → AWAITING_REDEMPTION; append external_send.awaiting_redemption; commit.
// 6. Only after that commit may delivery return the transfer code.
//
// Structural invariant: the signer function's only public caller path requires a
// DurableSignIntent — a branded handle produced exclusively by persist paths after the
// durable row commits. An in-memory ConstructedSendInner is not assignable.

import {
  insertPartial,
  insertSignIntent,
  insertTransactionAttempt,
  advanceAttemptPhase,
  type PartialRow,
  type SignIntentRow,
} from "./transaction-material-store.js";
import type { SqlQueryFn } from "./sql-query-fn.js";
import {
  signUnderLease,
  type SignerBoundaryDeps,
  type SigningResult,
} from "./signer-boundary.js";
import {
  constructSendInner,
  type ConstructedSendInner,
} from "../protocol/send-inner.js";
import {
  buildSendTransferCodeText,
  hashTransferCodeText,
} from "../protocol/send-transfer-code.js";
import type { SendBaselineCapture } from "../protocol/send-baseline.js";
import { TransactionConstructionError } from "../protocol/transactions.js";

export {
  constructSendInner,
  SEND_REDEMPTION_WINDOW_SECS,
  type ConstructedSendInner,
  type ConstructSendInnerInput,
} from "../protocol/send-inner.js";
export {
  buildSendTransferCodeText,
  hashTransferCodeText,
  SEND_TRANSFER_CODE_TYPE,
  SEND_TRANSFER_CODE_WIRE_VERSION,
} from "../protocol/send-transfer-code.js";
export {
  deriveSendRedemptionExpiryUnixSecs,
  redemptionExpiryAtFromSecs,
} from "../protocol/send-redemption.js";

export const EXTERNAL_SEND_AWAITING_REDEMPTION_EVENT =
  "external_send.awaiting_redemption" as const;

/** Formation-state CAS cells (`external_formation_state`). */
export const FORMATION_STATE = {
  APPROVED_UNSIGNED: "APPROVED_UNSIGNED",
  SIGNING_CLAIMED: "SIGNING_CLAIMED",
  PARTIAL_PERSISTED: "PARTIAL_PERSISTED",
} as const;

export type FormationStateCas =
  (typeof FORMATION_STATE)[keyof typeof FORMATION_STATE];

// ─── Claim / lease shapes (duplicated from send/ to keep core→send forbidden) ─
// Core may not import send/ (boundary: core → protocol|data|gateway|verifier).
// These are the structural fields formation needs; identical to claim-and-observe's.

export interface FormAndSignClaim {
  readonly operationId: string;
  readonly status: "APPROVED";
  readonly formationState: "APPROVED_UNSIGNED";
  readonly rowVersion: number;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
}

export interface FormAndSignHeldLease {
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly operationId: string;
}

// ─── Durable sign intent (branded — only produced after DB commit) ────────────

const DURABLE_SIGN_INTENT_BRAND = Symbol.for("zupayments.DurableSignIntent");

/**
 * Opaque handle proving a sign-intent row is durable. The only way to obtain one is
 * a successful commitSignIntent / persistSendSignIntentSql. The signer path accepts only
 * this type — an in-memory ConstructedSendInner is not assignable.
 */
export interface DurableSignIntent {
  readonly [key: symbol]: true | undefined; // brand via DURABLE_SIGN_INTENT_BRAND
  readonly operationId: string;
  readonly approvalId: string;
  readonly sourceWalletId: string;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly expiryUnixTimeSecs: string;
  readonly redemptionExpiryAt: string;
  readonly preparedAt: string;
}

function brandDurableSignIntent(
  fields: {
    readonly operationId: string;
    readonly approvalId: string;
    readonly sourceWalletId: string;
    readonly sourceT0ObservationId: string;
    readonly destinationT0ObservationId: string;
    readonly leaseGroupId: string;
    readonly leaseEpoch: bigint;
    readonly innerPreimageText: string;
    readonly innerSha256: string;
    readonly expiryUnixTimeSecs: string;
    readonly redemptionExpiryAt: string;
    readonly preparedAt: string;
  },
): DurableSignIntent {
  return Object.freeze({
    ...fields,
    [DURABLE_SIGN_INTENT_BRAND]: true as const,
  }) as DurableSignIntent;
}

/** True when value was produced by a durable commit path (brand present). */
export function isDurableSignIntent(value: unknown): value is DurableSignIntent {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<symbol, unknown>)[DURABLE_SIGN_INTENT_BRAND] === true
  );
}

// ─── Persistence ports ───────────────────────────────────────────────────────

export interface PersistSignIntentInput {
  readonly claim: FormAndSignClaim;
  readonly held: FormAndSignHeldLease;
  readonly approvalId: string;
  readonly sourceT0ObservationId: string;
  readonly destinationFormationObservationId: string;
  readonly constructed: ConstructedSendInner;
  readonly preparedAt: string;
}

export type PersistSignIntentResult =
  | { readonly ok: true; readonly intent: DurableSignIntent }
  | { readonly ok: false; readonly reason: string; readonly detail: string };

/**
 * Recheck + durable write surface for the sign-intent DB-TX (step 8).
 * Composition root supplies a real transaction; tests supply an in-memory adapter.
 *
 * Contract: commitSignIntent MUST insert the sign-intent row (and the
 * operation_transactions INNER_PREIMAGE_PERSISTED attempt) and CAS
 * APPROVED_UNSIGNED → SIGNING_CLAIMED in one atomic unit, then return only after commit.
 */
export interface SignIntentPersistPort {
  commitSignIntent(input: PersistSignIntentInput): Promise<PersistSignIntentResult>;
}

export interface PersistPartialInput {
  readonly intent: DurableSignIntent;
  readonly step1Signature: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly persistedAt: string;
}

export type PersistPartialResult =
  | {
      readonly ok: true;
      readonly transferCodeText: string;
      readonly transferCodeSha256: string;
      readonly step1Signature: string;
    }
  | { readonly ok: false; readonly reason: string; readonly detail: string };

/**
 * Post-sign DB-TX (step 3): step-1 signature + partial + APPROVED→AWAITING_REDEMPTION
 * + external_send.awaiting_redemption in one commit. Delivery is forbidden until this returns ok.
 */
export interface PartialPersistPort {
  commitPartialAndAwaitRedemption(input: PersistPartialInput): Promise<PersistPartialResult>;
}

// ─── SQL catalogue (composition-root wiring; tests pin exact strings) ────────

export const FORM_AND_SIGN_SQL = {
  /**
   * Step 5 — CAS after the sign-intent row is durable. Zero rows = lost race or
   * wrong phase; never force the transition.
   */
  CAS_APPROVED_UNSIGNED_TO_SIGNING_CLAIMED:
    "UPDATE send_operations SET formation_state = 'SIGNING_CLAIMED', " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 AND status = 'APPROVED' " +
    "AND formation_state = 'APPROVED_UNSIGNED' " +
    "RETURNING operation_id, formation_state, row_version",

  /**
   * Step 3 — PARTIAL_PERSISTED + AWAITING_REDEMPTION in the same statement as the
   * partial row insert (caller sequences both inside one DB-TX).
   */
  CAS_SIGNING_CLAIMED_TO_AWAITING_REDEMPTION:
    "UPDATE send_operations SET status = 'AWAITING_REDEMPTION', " +
    "formation_state = 'PARTIAL_PERSISTED', " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 AND status = 'APPROVED' " +
    "AND formation_state = 'SIGNING_CLAIMED' " +
    "RETURNING operation_id, status, formation_state, row_version",

  RECHECK_APPROVED_FOR_FORMATION:
    "SELECT o.operation_id, o.status, o.formation_state, o.row_version, " +
    "o.source_wallet_id, o.destination_address, o.amount_zkz, " +
    "a.id AS approval_id " +
    "FROM send_operations o " +
    "JOIN operation_approvals a ON a.operation_id = o.operation_id " +
    "WHERE o.operation_id = $1 AND o.status = 'APPROVED' " +
    "AND o.formation_state = 'APPROVED_UNSIGNED' AND a.id = $2 " +
    "FOR UPDATE OF o",
} as const;

// ─── SQL-backed ports (driver-free; injected SqlQueryFn) ──────────────────────

export async function persistSendSignIntentSql(
  query: SqlQueryFn,
  input: PersistSignIntentInput,
): Promise<PersistSignIntentResult> {
  const { claim, held, approvalId, constructed, preparedAt } = input;

  if (held.operationId !== claim.operationId) {
    return {
      ok: false,
      reason: "lease_operation_mismatch",
      detail: `lease operation ${held.operationId} ≠ claim ${claim.operationId}`,
    };
  }
  if (held.walletId !== claim.sourceWalletId) {
    return {
      ok: false,
      reason: "lease_wallet_mismatch",
      detail: `lease wallet ${held.walletId} ≠ claim source ${claim.sourceWalletId}`,
    };
  }

  const row: SignIntentRow = {
    operationId: claim.operationId,
    approvalId,
    sourceWalletId: claim.sourceWalletId,
    sourceT0ObservationId: input.sourceT0ObservationId,
    destinationT0ObservationId: input.destinationFormationObservationId,
    leaseGroupId: held.leaseGroupId,
    leaseEpoch: held.leaseEpoch.toString(),
    innerPreimageText: constructed.innerPreimageText,
    innerSha256: constructed.innerSha256,
    redemptionExpiryAt: constructed.redemptionExpiryAt,
    preparedAt,
  };

  try {
    await insertSignIntent(query, row);
    await insertTransactionAttempt(query, {
      operationId: claim.operationId,
      innerPreimageText: constructed.innerPreimageText,
      innerSha256: constructed.innerSha256,
      formedAt: preparedAt,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: "sign_intent_insert_rejected", detail: message };
  }

  const cas = await query(FORM_AND_SIGN_SQL.CAS_APPROVED_UNSIGNED_TO_SIGNING_CLAIMED, [
    claim.operationId,
  ]);
  if (cas[0] === undefined) {
    return {
      ok: false,
      reason: "formation_cas_lost",
      detail: "APPROVED_UNSIGNED → SIGNING_CLAIMED matched zero rows",
    };
  }

  return {
    ok: true,
    intent: brandDurableSignIntent({
      operationId: claim.operationId,
      approvalId,
      sourceWalletId: claim.sourceWalletId,
      sourceT0ObservationId: input.sourceT0ObservationId,
      destinationT0ObservationId: input.destinationFormationObservationId,
      leaseGroupId: held.leaseGroupId,
      leaseEpoch: held.leaseEpoch,
      innerPreimageText: constructed.innerPreimageText,
      innerSha256: constructed.innerSha256,
      expiryUnixTimeSecs: constructed.expiryUnixTimeSecs,
      redemptionExpiryAt: constructed.redemptionExpiryAt,
      preparedAt,
    }),
  };
}

export async function persistSendPartialSql(
  query: SqlQueryFn,
  input: PersistPartialInput,
): Promise<PersistPartialResult> {
  const { intent, step1Signature, transferCodeText, transferCodeSha256, persistedAt } = input;

  const recomputed = hashTransferCodeText(transferCodeText);
  if (recomputed !== transferCodeSha256) {
    return {
      ok: false,
      reason: "transfer_code_digest_mismatch",
      detail: "caller-supplied transfer_code_sha256 does not match SHA-256 of the exact text",
    };
  }

  try {
    // the one-in-flight-per-wallet rule: signUnderLease and this write are separate autocommit
    // statements. Re-check the same capability the signer used under a row lock as the
    // signature becomes durable — same AttemptLeaseGuard RECEIVE took in.
    await advanceAttemptPhase(
      query,
      intent.operationId,
      "STEP1_SIGNATURE_PERSISTED",
      {
        step_1_signature: step1Signature,
      },
      {
        walletId: intent.sourceWalletId,
        operationId: intent.operationId,
        leaseEpoch: intent.leaseEpoch,
      },
    );
    const partial: PartialRow = {
      operationId: intent.operationId,
      approvalId: intent.approvalId,
      innerSha256: intent.innerSha256,
      step1Signature,
      transferCodeText,
      transferCodeSha256,
      persistedAt,
    };
    await insertPartial(query, partial);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: "partial_insert_rejected", detail: message };
  }

  const cas = await query(FORM_AND_SIGN_SQL.CAS_SIGNING_CLAIMED_TO_AWAITING_REDEMPTION, [
    intent.operationId,
  ]);
  if (cas[0] === undefined) {
    return {
      ok: false,
      reason: "awaiting_redemption_cas_lost",
      detail: "SIGNING_CLAIMED → AWAITING_REDEMPTION matched zero rows",
    };
  }

  return {
    ok: true,
    transferCodeText,
    transferCodeSha256,
    step1Signature,
  };
}

// ─── Signer path (DurableSignIntent only) ────────────────────────────────────

/**
 * Steps 6–7: revalidate lease/digest via the shared boundary, sign exactly the
 * persisted preimage text. Accepts only DurableSignIntent — constructing an inner in
 * memory and calling this is a type error.
 */
export async function signDurableSendIntent(
  intent: DurableSignIntent,
  deps: SignerBoundaryDeps,
): Promise<SigningResult> {
  return signUnderLease(deps, {
    walletId: intent.sourceWalletId,
    operationId: intent.operationId,
    leaseEpoch: intent.leaseEpoch,
    purpose: "SPLITCHAIN_STEP_1",
    preimageText: intent.innerPreimageText,
    expectedPreimageSha256: intent.innerSha256,
  });
}

// ─── Full happy-path orchestration ───────────────────────────────────────────

export type FormAndSignRejectionReason =
  | "construction_rejected"
  | "sign_intent_persist_failed"
  | "signer_rejected"
  | "partial_persist_failed";

export type FormAndSignResult =
  | {
      readonly ok: true;
      readonly intent: DurableSignIntent;
      readonly step1Signature: string;
      readonly transferCodeText: string;
      readonly transferCodeSha256: string;
    }
  | {
      readonly ok: false;
      readonly reason: FormAndSignRejectionReason;
      readonly detail: string;
      /** Present once the sign intent is durable (crash-resume may complete from here). */
      readonly intent?: DurableSignIntent;
    };

export interface FormAndSignInput {
  readonly claim: FormAndSignClaim;
  readonly held: FormAndSignHeldLease;
  readonly approvalId: string;
  readonly sourceT0ObservationId: string;
  readonly destinationFormationObservationId: string;
  readonly capture: SendBaselineCapture;
  /** Node clock at formation (ms). Used once for T2 + unix_time_secs. */
  readonly nodeClockMs: number;
  readonly preparedAt: string;
  readonly persistedAt: string;
  readonly signIntentPort: SignIntentPersistPort;
  readonly partialPort: PartialPersistPort;
  readonly signerDeps: SignerBoundaryDeps;
}

/**
 * Steps 6–8 plus post-sign steps 1–4, happy path.
 *
 * Ordering is structural:
 * construct → persistSignIntent (commit) → signDurableSendIntent → build code →
 * commitPartialAndAwaitRedemption → return code.
 * The transfer code is never returned before the partial DB-TX commits.
 */
export async function formAndSignSendExternal(
  input: FormAndSignInput,
): Promise<FormAndSignResult> {
  let constructed: ConstructedSendInner;
  try {
    constructed = constructSendInner({
      capture: input.capture,
      nodeClockMs: input.nodeClockMs,
    });
  } catch (err) {
    // Receiver+empty S (or any invalid GENESIS/HEAD link) must not throw through the
    // money-worker tick — surface as rejected so the op stays APPROVED for retry/attention.
    const detail =
      err instanceof TransactionConstructionError
        ? err.reason
        : err instanceof Error
          ? err.message
          : String(err);
    return { ok: false, reason: "construction_rejected", detail };
  }

  const persisted = await input.signIntentPort.commitSignIntent({
    claim: input.claim,
    held: input.held,
    approvalId: input.approvalId,
    sourceT0ObservationId: input.sourceT0ObservationId,
    destinationFormationObservationId: input.destinationFormationObservationId,
    constructed,
    preparedAt: input.preparedAt,
  });
  if (!persisted.ok) {
    return {
      ok: false,
      reason: "sign_intent_persist_failed",
      detail: `${persisted.reason}: ${persisted.detail}`,
    };
  }
  const intent = persisted.intent;

  let signed: SigningResult;
  try {
    signed = await signDurableSendIntent(intent, input.signerDeps);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      reason: "signer_rejected",
      detail: message,
      intent,
    };
  }

  const transferCodeText = buildSendTransferCodeText(
    intent.innerPreimageText,
    signed.signature,
  );
  const transferCodeDigest = hashTransferCodeText(transferCodeText);

  const partial = await input.partialPort.commitPartialAndAwaitRedemption({
    intent,
    step1Signature: signed.signature,
    transferCodeText,
    transferCodeSha256: transferCodeDigest,
    persistedAt: input.persistedAt,
  });
  if (!partial.ok) {
    return {
      ok: false,
      reason: "partial_persist_failed",
      detail: `${partial.reason}: ${partial.detail}`,
      intent,
    };
  }

  return {
    ok: true,
    intent,
    step1Signature: partial.step1Signature,
    transferCodeText: partial.transferCodeText,
    transferCodeSha256: partial.transferCodeSha256,
  };
}

/**
 * Crash row: durable sign intent exists, no partial yet.
 * Signs the identical persisted preimage and persists the deterministic result.
 * Never reconstructs a new inner.
 */
export async function completeSigningFromDurableIntent(input: {
  readonly intent: DurableSignIntent;
  readonly persistedAt: string;
  readonly partialPort: PartialPersistPort;
  readonly signerDeps: SignerBoundaryDeps;
}): Promise<FormAndSignResult> {
  let signed: SigningResult;
  try {
    signed = await signDurableSendIntent(input.intent, input.signerDeps);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      reason: "signer_rejected",
      detail: message,
      intent: input.intent,
    };
  }

  const transferCodeText = buildSendTransferCodeText(
    input.intent.innerPreimageText,
    signed.signature,
  );
  const transferCodeDigest = hashTransferCodeText(transferCodeText);

  const partial = await input.partialPort.commitPartialAndAwaitRedemption({
    intent: input.intent,
    step1Signature: signed.signature,
    transferCodeText,
    transferCodeSha256: transferCodeDigest,
    persistedAt: input.persistedAt,
  });
  if (!partial.ok) {
    return {
      ok: false,
      reason: "partial_persist_failed",
      detail: `${partial.reason}: ${partial.detail}`,
      intent: input.intent,
    };
  }

  return {
    ok: true,
    intent: input.intent,
    step1Signature: partial.step1Signature,
    transferCodeText: partial.transferCodeText,
    transferCodeSha256: partial.transferCodeSha256,
  };
}

// ─── In-memory reference adapter (unit tests; mirrors SQL cardinality) ───────

export interface InMemoryFormAndSignState {
  status: "APPROVED" | "AWAITING_REDEMPTION";
  formationState: FormationStateCas | "PARTIAL_DELIVERED";
  signIntents: Map<string, DurableSignIntent>;
  /** approval_id → operation_id uniqueness fence. */
  signIntentsByApproval: Map<string, string>;
  partials: Map<
    string,
    {
      operationId: string;
      approvalId: string;
      step1Signature: string;
      transferCodeText: string;
      transferCodeSha256: string;
      firstDeliveredAt: string | null;
      redeliveryCount: number;
    }
  >;
  partialsByApproval: Map<string, string>;
  events: Array<{ operationId: string; eventType: string; at: string }>;
  /** Attempt phase ladder for the one attempt. */
  attemptPhase: Map<string, "INNER_PREIMAGE_PERSISTED" | "STEP1_SIGNATURE_PERSISTED">;
}

export function createInMemoryFormAndSignState(
  initial: {
    status?: "APPROVED" | "AWAITING_REDEMPTION";
    formationState?: FormationStateCas | "PARTIAL_DELIVERED";
  } = {},
): InMemoryFormAndSignState {
  return {
    status: initial.status ?? "APPROVED",
    formationState: initial.formationState ?? "APPROVED_UNSIGNED",
    signIntents: new Map(),
    signIntentsByApproval: new Map(),
    partials: new Map(),
    partialsByApproval: new Map(),
    events: [],
    attemptPhase: new Map(),
  };
}

export function createInMemorySignIntentPort(
  state: InMemoryFormAndSignState,
): SignIntentPersistPort {
  return {
    async commitSignIntent(input) {
      if (state.status !== "APPROVED") {
        return {
          ok: false,
          reason: "not_approved",
          detail: `status is ${state.status}`,
        };
      }
      if (state.formationState !== "APPROVED_UNSIGNED") {
        return {
          ok: false,
          reason: "formation_not_unsigned",
          detail: `formation_state is ${state.formationState}`,
        };
      }
      if (state.signIntents.has(input.claim.operationId)) {
        return {
          ok: false,
          reason: "sign_intent_exists",
          detail: `operation ${input.claim.operationId} already has a sign intent`,
        };
      }
      if (state.signIntentsByApproval.has(input.approvalId)) {
        return {
          ok: false,
          reason: "approval_already_bound",
          detail: `approval ${input.approvalId} already bound to a sign intent`,
        };
      }

      const intent = brandDurableSignIntent({
        operationId: input.claim.operationId,
        approvalId: input.approvalId,
        sourceWalletId: input.claim.sourceWalletId,
        sourceT0ObservationId: input.sourceT0ObservationId,
        destinationT0ObservationId: input.destinationFormationObservationId,
        leaseGroupId: input.held.leaseGroupId,
        leaseEpoch: input.held.leaseEpoch,
        innerPreimageText: input.constructed.innerPreimageText,
        innerSha256: input.constructed.innerSha256,
        expiryUnixTimeSecs: input.constructed.expiryUnixTimeSecs,
        redemptionExpiryAt: input.constructed.redemptionExpiryAt,
        preparedAt: input.preparedAt,
      });

      // Atomic: intent row + attempt + CAS.
      state.signIntents.set(intent.operationId, intent);
      state.signIntentsByApproval.set(intent.approvalId, intent.operationId);
      state.attemptPhase.set(intent.operationId, "INNER_PREIMAGE_PERSISTED");
      state.formationState = "SIGNING_CLAIMED";
      return { ok: true, intent };
    },
  };
}

export function createInMemoryPartialPort(
  state: InMemoryFormAndSignState,
): PartialPersistPort {
  return {
    async commitPartialAndAwaitRedemption(input) {
      if (!state.signIntents.has(input.intent.operationId)) {
        return {
          ok: false,
          reason: "no_sign_intent",
          detail: "partial requires a durable sign intent",
        };
      }
      if (state.formationState !== "SIGNING_CLAIMED") {
        return {
          ok: false,
          reason: "formation_not_signing_claimed",
          detail: `formation_state is ${state.formationState}`,
        };
      }
      if (state.partials.has(input.intent.operationId)) {
        return {
          ok: false,
          reason: "partial_exists",
          detail: `operation ${input.intent.operationId} already has a partial`,
        };
      }
      if (state.partialsByApproval.has(input.intent.approvalId)) {
        return {
          ok: false,
          reason: "approval_partial_exists",
          detail: `approval ${input.intent.approvalId} already has a partial`,
        };
      }
      const recomputed = hashTransferCodeText(input.transferCodeText);
      if (recomputed !== input.transferCodeSha256) {
        return {
          ok: false,
          reason: "transfer_code_digest_mismatch",
          detail: "sha256 of transfer_code_text does not match supplied digest",
        };
      }

      state.partials.set(input.intent.operationId, {
        operationId: input.intent.operationId,
        approvalId: input.intent.approvalId,
        step1Signature: input.step1Signature,
        transferCodeText: input.transferCodeText,
        transferCodeSha256: input.transferCodeSha256,
        firstDeliveredAt: null,
        redeliveryCount: 0,
      });
      state.partialsByApproval.set(input.intent.approvalId, input.intent.operationId);
      state.attemptPhase.set(input.intent.operationId, "STEP1_SIGNATURE_PERSISTED");
      state.formationState = "PARTIAL_PERSISTED";
      state.status = "AWAITING_REDEMPTION";
      state.events.push({
        operationId: input.intent.operationId,
        eventType: EXTERNAL_SEND_AWAITING_REDEMPTION_EVENT,
        at: input.persistedAt,
      });

      return {
        ok: true,
        transferCodeText: input.transferCodeText,
        transferCodeSha256: input.transferCodeSha256,
        step1Signature: input.step1Signature,
      };
    },
  };
}

/**
 * Set-once delivery stamp: first_delivered_at is written once; later calls only
 * bump redelivery_count.
 */
export function recordInMemoryPartialDelivery(
  state: InMemoryFormAndSignState,
  operationId: string,
  deliveredAt: string,
): number {
  const row = state.partials.get(operationId);
  if (row === undefined) {
    throw new Error(
      `no persisted partial for operation ${operationId}: delivery is forbidden until the partial row commits`,
    );
  }
  if (row.firstDeliveredAt === null) {
    row.firstDeliveredAt = deliveredAt;
    return 0;
  }
  row.redeliveryCount += 1;
  return row.redeliveryCount;
}
