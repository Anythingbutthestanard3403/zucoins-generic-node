// MOVE_INTERNAL formation: construct exact inner + durable attempt-1 record.
// Persist before crossing an irreversible boundary; one of the three public money operations.
//
// Sequence (steps 1–2 only — signing is a separate slice):
// 1. Construct the exact SplitChain inner from dual-baseline capture.
// 2. DB-TX: insert operation_transactions at INNER_PREIMAGE_PERSISTED with
// inner_preimage_text + inner_sha256; commit BEFORE any signer call.
//
// Does NOT change operations.status (already CREATED by) and does NOT write
// operation_expected_artifacts (inserted once upstream; UNIQUE on operation_id).
// T0 observation references live on move_observation_evidence; this slice
// only owns the attempt row.
//
// Structural invariant: DurableMoveInner is a branded handle produced exclusively by
// persist paths after the durable row commits. An in-memory ConstructedMoveInner is not
// assignable to the signer path.

import {
  insertTransactionAttempt,
  ONLY_ATTEMPT_NO,
  type AttemptInsertRow,
} from "./transaction-material-store.js";
import type { SqlQueryFn } from "./sql-query-fn.js";
import {
  constructMoveInner,
  type ConstructedMoveInner,
  MoveInnerBuildError,
} from "../protocol/move-inner.js";
import type { DualBaselineCapture } from "../protocol/move-baseline.js";
import type { PersistedExpectedArtifact } from "./move-baseline-binding.js";

export {
  constructMoveInner,
  MoveInnerBuildError,
  type ConstructedMoveInner,
  type ConstructMoveInnerInput,
  type MoveInnerBuildFailureReason,
} from "../protocol/move-inner.js";

export { ONLY_ATTEMPT_NO };

// ─── Durable move inner (branded — only produced after DB commit) ─────────────

const DURABLE_MOVE_INNER_BRAND = Symbol.for("zupayments.DurableMoveInner");

/**
 * Opaque handle proving an operation_transactions row is durable at
 * INNER_PREIMAGE_PERSISTED with step_1_signature IS NULL. The only way to obtain one is
 * a successful commitMoveInnerAttempt. signer path accepts only this type.
 */
export interface DurableMoveInner {
  readonly [key: symbol]: true | undefined;
  readonly operationId: string;
  readonly attemptNo: typeof ONLY_ATTEMPT_NO;
  readonly attemptPhase: "INNER_PREIMAGE_PERSISTED";
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  /** Byte-frozen expected-artifact preimage text this inner's economics must match. */
  readonly expectedArtifactPreimageText: string;
  readonly expectedArtifactPreimageSha256: string;
  readonly formedAt: string;
}

function brandDurableMoveInner(
  fields: Omit<DurableMoveInner, typeof DURABLE_MOVE_INNER_BRAND | symbol>,
): DurableMoveInner {
  const branded = {
    ...fields,
    [DURABLE_MOVE_INNER_BRAND]: true as const,
  };
  return Object.freeze(branded) as DurableMoveInner;
}

/** True when value carries the durable-move-inner brand (post-commit only). */
export function isDurableMoveInner(value: unknown): value is DurableMoveInner {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<symbol, unknown>)[DURABLE_MOVE_INNER_BRAND] === true
  );
}

// ─── Persist port ────────────────────────────────────────────────────────────

export type PersistMoveInnerRejectionReason =
  | "attempt_exists"
  | "attempt_insert_rejected"
  | "artifact_missing"
  | "artifact_purpose_mismatch"
  | "economics_mismatch"
  | "lease_operation_mismatch";

export type PersistMoveInnerResult =
  | { readonly ok: true; readonly durable: DurableMoveInner }
  | {
      readonly ok: false;
      readonly reason: PersistMoveInnerRejectionReason;
      readonly detail: string;
    };

export interface PersistMoveInnerInput {
  readonly operationId: string;
  readonly constructed: ConstructedMoveInner;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  /** Already-persisted artifact — read-only; never re-inserted. */
  readonly expectedArtifact: PersistedExpectedArtifact;
  readonly formedAt: string;
}

export interface MoveInnerPersistPort {
  commitMoveInnerAttempt(input: PersistMoveInnerInput): Promise<PersistMoveInnerResult>;
}

/**
 * SQL adapter: inserts the one attempt at INNER_PREIMAGE_PERSISTED via the shared
 * transaction-material store. Does not touch operations.status or expected artifacts.
 */
export async function persistMoveInnerAttemptSql(
  query: SqlQueryFn,
  input: PersistMoveInnerInput,
): Promise<PersistMoveInnerResult> {
  const economics = checkEconomicsAgainstArtifact(input.constructed, input.expectedArtifact);
  if (economics !== null) {
    return { ok: false, reason: "economics_mismatch", detail: economics };
  }
  if (input.expectedArtifact.purpose !== "zp-move-internal-expected-v1") {
    return {
      ok: false,
      reason: "artifact_purpose_mismatch",
      detail: `expected purpose zp-move-internal-expected-v1, got ${input.expectedArtifact.purpose}`,
    };
  }
  if (input.expectedArtifact.operationId !== input.operationId) {
    return {
      ok: false,
      reason: "lease_operation_mismatch",
      detail: `artifact operation ${input.expectedArtifact.operationId} ≠ ${input.operationId}`,
    };
  }

  const row: AttemptInsertRow = {
    operationId: input.operationId,
    innerPreimageText: input.constructed.innerPreimageText,
    innerSha256: input.constructed.innerSha256,
    formedAt: input.formedAt,
    // payerStep1Signature omitted → INNER_PREIMAGE_PERSISTED, step_1_signature NULL
  };

  try {
    const phase = await insertTransactionAttempt(query, row);
    if (phase !== "INNER_PREIMAGE_PERSISTED") {
      return {
        ok: false,
        reason: "attempt_insert_rejected",
        detail: `unexpected phase ${phase}`,
      };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/unique|duplicate|23505/i.test(message)) {
      return { ok: false, reason: "attempt_exists", detail: message };
    }
    return { ok: false, reason: "attempt_insert_rejected", detail: message };
  }

  return {
    ok: true,
    durable: brandDurableMoveInner({
      operationId: input.operationId,
      attemptNo: ONLY_ATTEMPT_NO,
      attemptPhase: "INNER_PREIMAGE_PERSISTED",
      innerPreimageText: input.constructed.innerPreimageText,
      innerSha256: input.constructed.innerSha256,
      sourceT0ObservationId: input.sourceT0ObservationId,
      destinationT0ObservationId: input.destinationT0ObservationId,
      expectedArtifactPreimageText: input.expectedArtifact.preimageText,
      expectedArtifactPreimageSha256: input.expectedArtifact.preimageSha256,
      formedAt: input.formedAt,
    }),
  };
}

// ─── Full formation orchestration (construct → persist; no signer) ───────────

export type FormMoveInnerRejectionReason =
  | "construction_rejected"
  | "persist_failed";

export type FormMoveInnerResult =
  | { readonly ok: true; readonly durable: DurableMoveInner }
  | {
      readonly ok: false;
      readonly reason: FormMoveInnerRejectionReason;
      readonly detail: string;
      /** Present only when construction succeeded but persist failed. */
      readonly constructed?: ConstructedMoveInner;
    };

export interface FormMoveInnerInput {
  readonly operationId: string;
  readonly capture: DualBaselineCapture;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly expectedArtifact: PersistedExpectedArtifact;
  readonly nodeClockMs: number;
  readonly formedAt: string;
  readonly persistPort: MoveInnerPersistPort;
}

/**
 * Steps 1–2 happy path.
 *
 * Ordering is structural:
 * constructMoveInner → commitMoveInnerAttempt (commit) → return DurableMoveInner.
 * No signer is invoked. A crash after commit resumes from the durable row.
 */
export async function formMoveInner(input: FormMoveInnerInput): Promise<FormMoveInnerResult> {
  if (input.capture.operationId !== input.operationId) {
    return {
      ok: false,
      reason: "construction_rejected",
      detail: `capture operation ${input.capture.operationId} ≠ ${input.operationId}`,
    };
  }

  let constructed: ConstructedMoveInner;
  try {
    constructed = constructMoveInner({
      capture: input.capture,
      nodeClockMs: input.nodeClockMs,
    });
  } catch (err) {
    const detail =
      err instanceof MoveInnerBuildError
        ? `${err.reason}: ${err.message}`
        : err instanceof Error
          ? err.message
          : String(err);
    return { ok: false, reason: "construction_rejected", detail };
  }

  const persisted = await input.persistPort.commitMoveInnerAttempt({
    operationId: input.operationId,
    constructed,
    sourceT0ObservationId: input.sourceT0ObservationId,
    destinationT0ObservationId: input.destinationT0ObservationId,
    expectedArtifact: input.expectedArtifact,
    formedAt: input.formedAt,
  });
  if (!persisted.ok) {
    return {
      ok: false,
      reason: "persist_failed",
      detail: `${persisted.reason}: ${persisted.detail}`,
      constructed,
    };
  }

  return { ok: true, durable: persisted.durable };
}

// ─── Economic consistency with expected artifact ──────────────────────

/**
 * Parse amount_zkz + source/destination pubkeys from the frozen expected-artifact
 * preimage JSON body (after the purpose\n prefix) and compare to the constructed inner.
 * Does not re-serialize the artifact — only reads the already-persisted text.
 * Field comparison only; never re-stringifies the inner as a signing source (Byte-exact).
 */
function checkEconomicsAgainstArtifact(
  constructed: ConstructedMoveInner,
  artifact: PersistedExpectedArtifact,
): string | null {
  const lf = artifact.preimageText.indexOf("\n");
  if (lf < 0) {
    return "expected artifact preimage missing purpose/body separator";
  }
  const bodyText = artifact.preimageText.slice(lf + 1);
  let body: {
    purpose?: unknown;
    amount_zkz?: unknown;
    source_pubkey?: unknown;
    destination_pubkey?: unknown;
  };
  try {
    body = JSON.parse(bodyText) as typeof body;
  } catch {
    return "expected artifact body is not JSON";
  }
  if (body.purpose !== "zp-move-internal-expected-v1") {
    return `artifact purpose ${String(body.purpose)} is not zp-move-internal-expected-v1`;
  }
  if (typeof body.amount_zkz !== "string") {
    return "artifact amount_zkz missing";
  }
  if (typeof body.source_pubkey !== "string" || typeof body.destination_pubkey !== "string") {
    return "artifact source/destination pubkey missing";
  }

  let inner: {
    step_1_key_public__base64urlsafe?: unknown;
    step_2_key_public__base64urlsafe?: unknown;
  };
  try {
    inner = JSON.parse(constructed.innerPreimageText) as typeof inner;
  } catch {
    return "constructed inner preimage is not JSON";
  }

  if (inner.step_1_key_public__base64urlsafe !== body.source_pubkey) {
    return "inner step_1 key !== artifact source_pubkey";
  }
  if (inner.step_2_key_public__base64urlsafe !== body.destination_pubkey) {
    return "inner step_2 key !== artifact destination_pubkey";
  }
  // Transfer amount frozen at construction must equal the artifact's economic intent.
  if (constructed.amountZkz !== body.amount_zkz) {
    return `inner amount ${constructed.amountZkz} !== artifact amount_zkz ${body.amount_zkz}`;
  }
  return null;
}

// ─── In-memory reference adapter (unit tests; mirrors SQL cardinality) ───────

export interface InMemoryMoveFormState {
  /** operation_id → durable attempt. */
  attempts: Map<string, DurableMoveInner>;
  /** Count of signer invocations — must stay 0 across formation (crash-inject proof). */
  signerCalls: number;
  /** Snapshot of expected-artifact preimage bytes at bind time (must stay unchanged). */
  artifactPreimageByOperation: Map<string, string>;
}

export function createInMemoryMoveFormState(): InMemoryMoveFormState {
  return {
    attempts: new Map(),
    signerCalls: 0,
    artifactPreimageByOperation: new Map(),
  };
}

export function createInMemoryMoveInnerPersistPort(
  state: InMemoryMoveFormState,
): MoveInnerPersistPort {
  return {
    async commitMoveInnerAttempt(input) {
      if (state.attempts.has(input.operationId)) {
        return {
          ok: false,
          reason: "attempt_exists",
          detail: `operation ${input.operationId} already has attempt 1`,
        };
      }
      if (input.expectedArtifact.purpose !== "zp-move-internal-expected-v1") {
        return {
          ok: false,
          reason: "artifact_purpose_mismatch",
          detail: `purpose ${input.expectedArtifact.purpose}`,
        };
      }
      if (input.expectedArtifact.operationId !== input.operationId) {
        return {
          ok: false,
          reason: "lease_operation_mismatch",
          detail: `artifact op ${input.expectedArtifact.operationId}`,
        };
      }
      const economics = checkEconomicsAgainstArtifact(
        input.constructed,
        input.expectedArtifact,
      );
      if (economics !== null) {
        return { ok: false, reason: "economics_mismatch", detail: economics };
      }

      // Record artifact bytes as they stood at commit — tests assert no mutation.
      const prior = state.artifactPreimageByOperation.get(input.operationId);
      if (prior === undefined) {
        state.artifactPreimageByOperation.set(
          input.operationId,
          input.expectedArtifact.preimageText,
        );
      } else if (prior !== input.expectedArtifact.preimageText) {
        return {
          ok: false,
          reason: "artifact_purpose_mismatch",
          detail: "expected artifact preimage changed between bind and formation",
        };
      }

      const durable = brandDurableMoveInner({
        operationId: input.operationId,
        attemptNo: ONLY_ATTEMPT_NO,
        attemptPhase: "INNER_PREIMAGE_PERSISTED",
        innerPreimageText: input.constructed.innerPreimageText,
        innerSha256: input.constructed.innerSha256,
        sourceT0ObservationId: input.sourceT0ObservationId,
        destinationT0ObservationId: input.destinationT0ObservationId,
        expectedArtifactPreimageText: input.expectedArtifact.preimageText,
        expectedArtifactPreimageSha256: input.expectedArtifact.preimageSha256,
        formedAt: input.formedAt,
      });
      state.attempts.set(input.operationId, durable);
      // Intentionally never increments signerCalls — formation never invokes a signer.
      return { ok: true, durable };
    },
  };
}
