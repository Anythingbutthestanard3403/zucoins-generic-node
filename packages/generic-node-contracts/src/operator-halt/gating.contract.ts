import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.ts";
import { isHaltGatedOperationKind } from "./halt.contract.ts";

/**
 * The kill-switch rule; operations recovery (recovery classification, `PROVEN_NOT_STARTED`, boot
 * recovery resuming only classification-authorized actions).
 *
 * the kill-switch rule stops the node from STARTING new fund-moving signing. That boundary is crossed both
 * by a fresh admission and by a recovery-resumed `PROVEN_NOT_STARTED` first formation (09-ops-
 * recovery: "may authorize the first call only when the submit boundary
 * was durably never crossed" — this is still a first signing call, merely triggered by
 * recovery instead of fresh admission). the kill-switch rule draws no exception for recovery-triggered
 * signing, so both triggers are gated identically for gated operation kinds.
 */
export const SIGNING_TRIGGERS = ["FRESH_ADMISSION", "RECOVERY_RESUMED_FIRST_FORMATION"] as const;

export type SigningTrigger = (typeof SIGNING_TRIGGERS)[number];

/**
 * The halt-exempt frozen kind's only node-originated signature is the step-2 co-sign over
 * the counterparty's inbound transaction (inbound co-sign); it is never a "first
 * formation" the node itself initiates, fresh or recovery-resumed, so its signing purpose is
 * fixed at `COSIGN_INBOUND`. Both halt-gated kinds are node-initiated first formations in
 * both triggers. Derived from the named concern's coarse scope (`isHaltGatedOperationKind`), never
 * hand-typed per kind, so this file and `halt.contract.ts` cannot silently drift apart.
 */
export const SIGNING_PURPOSE_BY_OPERATION_KIND: Readonly<Record<OperationKind, string>> = Object.fromEntries(
  OPERATION_KINDS.map((operationKind) => [
    operationKind,
    isHaltGatedOperationKind(operationKind) ? "FIRST_FORMATION" : "COSIGN_INBOUND",
  ]),
) as Readonly<Record<OperationKind, string>>;

export interface MoneyMutationHaltEntry {
  readonly operationKind: OperationKind;
  readonly trigger: SigningTrigger;
  readonly signingPurpose: string;
  readonly haltGated: boolean;
}

/**
 * Exhaustive `OPERATION_KINDS x SIGNING_TRIGGERS` enumeration (imported from the generic-core scan concern, never
 * redeclared). `haltGated` is derived from the coarse the named concern scope
 * (`isHaltGatedOperationKind`), not restated by hand, so the two files cannot silently drift.
 */
export const MONEY_MUTATION_HALT_MAP: readonly MoneyMutationHaltEntry[] = OPERATION_KINDS.flatMap(
  (operationKind) =>
    SIGNING_TRIGGERS.map((trigger) => ({
      operationKind,
      trigger,
      signingPurpose: SIGNING_PURPOSE_BY_OPERATION_KIND[operationKind],
      haltGated: isHaltGatedOperationKind(operationKind),
    })),
);

/** Fail-closed pure predicate: throws on an uncovered combination rather than defaulting open. */
export const isHaltGated = (operationKind: OperationKind, trigger: SigningTrigger): boolean => {
  const entry = MONEY_MUTATION_HALT_MAP.find(
    (row) => row.operationKind === operationKind && row.trigger === trigger,
  );
  if (!entry) {
    throw new Error(`no halt-gating entry for ${operationKind}/${trigger}`);
  }
  return entry.haltGated;
};

/** Compile-time canary: a `never` default only type-checks while the switch is exhaustive. */
const assertNeverOperationKind = (value: never): never => {
  throw new Error(`unhandled operation kind in gating manifest: ${JSON.stringify(value)}`);
};

/** Exhaustive-switch fixture (mirrors the generic-core scan concern's `operations.drift-gate.test.ts` pattern).*/
export const describeHaltGating = (operationKind: OperationKind): string => {
  switch (operationKind) {
    case "MOVE_INTERNAL":
      return "first formation, fresh or recovery-resumed; always halt-gated";
    case "SEND_EXTERNAL":
      return "first formation, fresh or recovery-resumed; always halt-gated";
    case "RECEIVE_EXTERNAL":
      return "co-sign only; never halt-gated (revenue exemption)";
    default:
      return assertNeverOperationKind(operationKind);
  }
};

export const SOURCE = "operator-kill-switch; operations recovery; inbound co-sign boundary" as const;
