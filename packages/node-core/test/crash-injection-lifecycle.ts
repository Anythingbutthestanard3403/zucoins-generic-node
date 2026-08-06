/**
 * Phase-by-phase crash-injection harness — lifecycle driver + crash boundary.
 *
 * Drives the submit-capable operation lifecycle (creation -> signing -> submit -> landing)
 * as a sequence of atomic durable-commit steps. `runLifecycle` can start from any step and
 * stop after any step, so a test can crash at any phase boundary and recovery can resume
 * from the correct step; `crashAndRecover` enforces the crash axiom mechanically (JSON
 * round-trip of the durable store + brand-new runtime, volatile state discarded).
 *
 * Step map (each step is one DB-TX; a crash after step N leaves steps 0..N durable):
 *   0 CREATE          — acquire source lease, mark READY       (lease held)
 *   1 INNER_PREIMAGE  — build + persist inner preimage         (INNER_PREIMAGE_PERSISTED)
 *   2 SIGN_STEP1      — sign persisted inner + persist sig     (STEP1_SIGNATURE_PERSISTED)
 *   3 STEP2_PREIMAGE  — build + persist step-2 preimage        (STEP2_PREIMAGE_PERSISTED)
 *   4 SIGN_STEP2      — sign step-2 + persist completed tx     (STEP2_SIGNATURE_PERSISTED)
 *   5 SUBMIT          — single-shot submit claim + invoke once (submit claimed, ->SUBMITTED)
 *   6 LAND            — persist settled body, land, release lease, emit event
 *   7 DELIVER_PARTIAL — mint the partial once, then deliver its exact persisted bytes
 *
 * Not every kind performs every step (PERFORMS_STEP): RECEIVE_EXTERNAL skips 1-2 because the
 * payer supplied and the node persisted those bytes at acceptance — the node has no rebuild
 * path for them. SEND_EXTERNAL skips 3-6 and ends at 7: it has
 * no submit port at all, so no submit call can occur on any of its paths.
 * Step indices are global and stable across
 * kinds, so a residue classification names the same resume step for every kind.
 *
 * Every step is idempotent against its own durable output: if the output already survived a
 * crash, the step is a no-op. This is what lets recovery re-run a step range safely without
 * creating a second attempt, a second signature, a second submit call, or a second partial.
 */
import { digestPreimage } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  buildCompletedTransactionText,
  buildInnerPreimage,
  buildPartialCode,
  createRuntime,
  findOperation,
  makeAttemptRow,
  signWithSeed,
  type OperationKind,
  type Scenario,
  type SubmitOutcome,
  type SubmitPort,
} from "./crash-injection-model.ts";

export const LIFECYCLE_STEPS = [
  "CREATE",
  "INNER_PREIMAGE",
  "SIGN_STEP1",
  "STEP2_PREIMAGE",
  "SIGN_STEP2",
  "SUBMIT",
  "LAND",
  "DELIVER_PARTIAL",
] as const;
export type LifecycleStep = (typeof LIFECYCLE_STEPS)[number];

export const STEP_CREATE = 0;
export const STEP_INNER_PREIMAGE = 1;
export const STEP_SIGN_STEP1 = 2;
export const STEP_STEP2_PREIMAGE = 3;
export const STEP_SIGN_STEP2 = 4;
export const STEP_SUBMIT = 5;
export const STEP_LAND = 6;
export const STEP_DELIVER_PARTIAL = 7;

/** Which lifecycle steps each kind performs. A step outside a kind's set is skipped by
 *  runLifecycle and refused outright by the step body, so an unreachable path cannot become
 *  reachable through a resume-index bug. */
export const PERFORMS_STEP: Record<OperationKind, ReadonlySet<LifecycleStep>> = {
  MOVE_INTERNAL: new Set<LifecycleStep>([
    "CREATE",
    "INNER_PREIMAGE",
    "SIGN_STEP1",
    "STEP2_PREIMAGE",
    "SIGN_STEP2",
    "SUBMIT",
    "LAND",
  ]),
  RECEIVE_EXTERNAL: new Set<LifecycleStep>([
    "CREATE",
    "STEP2_PREIMAGE",
    "SIGN_STEP2",
    "SUBMIT",
    "LAND",
  ]),
  SEND_EXTERNAL: new Set<LifecycleStep>([
    "CREATE",
    "INNER_PREIMAGE",
    "SIGN_STEP1",
    "DELIVER_PARTIAL",
  ]),
};

/** Each crash point names the last step that committed durable state before the crash — the
 *  process dies at the boundary immediately after it, so the named step's output survives and
 *  the next step's does not. One distinct durable residue per phase. */
export const CRASH_POINTS = {
  AFTER_CREATE: STEP_CREATE,
  AFTER_INNER_PREIMAGE: STEP_INNER_PREIMAGE,
  AFTER_SIGN_STEP1: STEP_SIGN_STEP1,
  AFTER_STEP2_PREIMAGE: STEP_STEP2_PREIMAGE,
  AFTER_SIGN_STEP2: STEP_SIGN_STEP2,
  AFTER_SUBMIT: STEP_SUBMIT,
  AFTER_DELIVER_PARTIAL: STEP_DELIVER_PARTIAL,
} as const;
export type CrashPoint = keyof typeof CRASH_POINTS;

const setStatus = (scenario: Scenario, operationId: string, next: "READY" | "SUBMITTED" | "LANDED"): void => {
  const operation = findOperation(scenario.durable, operationId);
  if (operation.status === next) {
    return;
  }
  scenario.runtime.log.statusTransitions.push({ operationId, from: operation.status, to: next });
  operation.status = next;
};

/** Acquire the source lease. For RECEIVE_EXTERNAL this same transaction durably accepts the
 *  PAYER-signed inbound bytes: the inner preimage and step-1 signature are inputs the node
 *  received, not outputs it formed, so they are durable from the first boundary onward and the
 * node's signer is never invoked for them. */
const createStep = (scenario: Scenario, operationId: string, payerStep1Signature?: string): void => {
  const { durable, runtime } = scenario;
  const operation = findOperation(durable, operationId);
  if (!operation.leaseHeld) {
    operation.leaseHeld = true;
    runtime.log.leaseAcquisitions += 1;
  }
  if (operation.kind === "RECEIVE_EXTERNAL" && attemptRowFor(durable, operationId) === undefined) {
    if (payerStep1Signature === undefined) {
      throw new Error("crash-injection lifecycle: receive accepted without payer step-1 signature");
    }
    const innerPreimageText = buildInnerPreimage("RECEIVE_EXTERNAL", operationId);
    const attempt = makeAttemptRow(operationId);
    attempt.innerPreimageText = innerPreimageText;
    attempt.innerSha256 = digestPreimage(innerPreimageText);
    attempt.step1Signature = payerStep1Signature;
    attempt.attemptPhase = "STEP1_SIGNATURE_PERSISTED";
    durable.attempts.push(attempt);
    runtime.log.attemptCreations += 1;
  }
  setStatus(scenario, operationId, "READY");
};

const attemptRowFor = (durable: Scenario["durable"], operationId: string) =>
  durable.attempts.find((row) => row.operationId === operationId);

/** Refuses on RECEIVE_EXTERNAL: the inbound inner bytes are payer-signed, so re-forming them
 *  would replace a signature the node cannot produce. Receive has no rebuild path. */
const innerPreimageStep = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  const operation = findOperation(durable, operationId);
  if (operation.kind === "RECEIVE_EXTERNAL") {
    throw new Error("crash-injection lifecycle: receive has no rebuild path for inner bytes");
  }
  const existing = attemptRowFor(durable, operationId);
  if (existing !== undefined && existing.innerPreimageText !== null) {
    runtime.volatile.innerPreimageText = existing.innerPreimageText;
    return;
  }
  if (existing !== undefined) {
    throw new Error("crash-injection lifecycle: attempt row exists without an inner preimage");
  }
  const innerPreimageText = buildInnerPreimage(operation.kind, operationId);
  runtime.volatile.innerPreimageText = innerPreimageText;
  const attempt = makeAttemptRow(operationId);
  attempt.innerPreimageText = innerPreimageText;
  attempt.innerSha256 = digestPreimage(innerPreimageText);
  durable.attempts.push(attempt);
  runtime.log.attemptCreations += 1;
};

const signStep1Step = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  if (findOperation(durable, operationId).kind === "RECEIVE_EXTERNAL") {
    throw new Error("crash-injection lifecycle: the node never signs step 1 of a receive");
  }
  const attempt = attemptRowFor(durable, operationId);
  if (attempt === undefined || attempt.innerPreimageText === null || attempt.innerSha256 === null) {
    throw new Error("crash-injection lifecycle: step-1 signing without a persisted inner preimage");
  }
  if (attempt.step1Signature !== null) {
    runtime.volatile.step1Signature = attempt.step1Signature;
    return;
  }
  const signature = signWithSeed(attempt.innerPreimageText, runtime.seedByte);
  runtime.log.signerCalls.push({ operationId, step: 1, preimageText: attempt.innerPreimageText, signature });
  durable.signerAudit.push({ operationId, step: 1, preimageSha256: attempt.innerSha256, signature });
  attempt.step1Signature = signature;
  attempt.attemptPhase = "STEP1_SIGNATURE_PERSISTED";
  runtime.volatile.step1Signature = signature;
};

const step2PreimageStep = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  const attempt = durable.attempts.find((row) => row.operationId === operationId);
  if (attempt === undefined || attempt.step1Signature === null || attempt.innerPreimageText === null) {
    throw new Error("crash-injection lifecycle: step-2 preimage without a persisted step-1 signature");
  }
  if (attempt.step2PreimageText !== null) {
    runtime.volatile.step2PreimageText = attempt.step2PreimageText;
    return;
  }
  const step2PreimageText = `${attempt.innerPreimageText}|"step_1_signature":"${attempt.step1Signature}"`;
  attempt.step2PreimageText = step2PreimageText;
  attempt.step2PreimageSha256 = digestPreimage(step2PreimageText);
  attempt.attemptPhase = "STEP2_PREIMAGE_PERSISTED";
  runtime.volatile.step2PreimageText = step2PreimageText;
};

const signStep2Step = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  const attempt = durable.attempts.find((row) => row.operationId === operationId);
  if (
    attempt === undefined ||
    attempt.step2PreimageText === null ||
    attempt.step2PreimageSha256 === null ||
    attempt.innerPreimageText === null ||
    attempt.step1Signature === null
  ) {
    throw new Error("crash-injection lifecycle: step-2 signing without a persisted step-2 preimage");
  }
  if (attempt.step2Signature !== null && attempt.completedTransactionText !== null) {
    runtime.volatile.step2Signature = attempt.step2Signature;
    runtime.volatile.completedTransactionText = attempt.completedTransactionText;
    return;
  }
  const signature = signWithSeed(attempt.step2PreimageText, runtime.seedByte);
  runtime.log.signerCalls.push({ operationId, step: 2, preimageText: attempt.step2PreimageText, signature });
  durable.signerAudit.push({ operationId, step: 2, preimageSha256: attempt.step2PreimageSha256, signature });
  attempt.step2Signature = signature;
  attempt.completedTransactionText = buildCompletedTransactionText(
    attempt.innerPreimageText,
    attempt.step1Signature,
    signature,
  );
  attempt.completedTransactionSha256 = digestPreimage(attempt.completedTransactionText);
  attempt.attemptPhase = "STEP2_SIGNATURE_PERSISTED";
  runtime.volatile.step2Signature = signature;
  runtime.volatile.completedTransactionText = attempt.completedTransactionText;
};

/** Single-shot submit. The claim and the call are one atomic step; if the claim already
 *  survived a crash the step is a no-op and the port is never invoked again (the never-blind-retry rule —
 *  never blind-retry a submit). */
const submitStep = (scenario: Scenario, operationId: string, submitPort: SubmitPort): SubmitOutcome | undefined => {
  const { durable, runtime } = scenario;
  if (findOperation(durable, operationId).kind === "SEND_EXTERNAL") {
    throw new Error("crash-injection lifecycle: external send never reaches a submit port");
  }
  const attempt = attemptRowFor(durable, operationId);
  if (attempt === undefined || attempt.completedTransactionText === null) {
    throw new Error("crash-injection lifecycle: submit without a persisted completed transaction");
  }
  if (attempt.submitClaimed) {
    return undefined;
  }
  attempt.submitClaimed = true;
  const outcome = submitPort({
    operationId,
    attemptNo: attempt.attemptNo,
    completedTransactionText: attempt.completedTransactionText,
  });
  runtime.log.submitCalls.push({ operationId, attemptNo: attempt.attemptNo });
  attempt.submitResponseRecorded = true;
  runtime.volatile.submitOutcome = outcome;
  setStatus(scenario, operationId, "SUBMITTED");
  return outcome;
};

/** The single landing implementation — the crash-free path reaches it as step 6, and recovery
 *  reaches it only through a verified settlement observation. Terminal-guarded, so landing an
 *  already-landed operation emits no second event and releases no second lease: a duplicated
 *  landing is a duplicated irreversible boundary crossing (the one-in-flight-per-wallet rule). */
export const landStep = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  const operation = findOperation(durable, operationId);
  if (operation.terminal) {
    return;
  }
  const attempt = attemptRowFor(durable, operationId);
  // Only an operation that formed a completed transaction has a settled body to persist; an
  // external send has none, so its phase is left at the formation phase it reached.
  if (attempt !== undefined && attempt.completedTransactionText !== null) {
    attempt.attemptPhase = "SETTLED_BODY_PERSISTED";
  }
  operation.terminal = true;
  operation.leaseHeld = false;
  runtime.log.leaseReleases += 1;
  runtime.log.landings.push(operationId);
  setStatus(scenario, operationId, "LANDED");
  durable.events.push(LANDED_EVENT[operation.kind]);
  runtime.log.eventsEmitted.push(LANDED_EVENT[operation.kind]);
};

export const LANDED_EVENT: Record<OperationKind, string> = {
  MOVE_INTERNAL: "internal_move.landed",
  RECEIVE_EXTERNAL: "external_receive.landed",
  SEND_EXTERNAL: "external_send.delivered",
};

/** Mint the external-send partial ONCE per approval, then deliver its exact persisted bytes.
 *  If a partial row already survived a crash the code is never re-formed and never replaced —
 * recovery delivers those bytes verbatim (the custody rules forbids "re-sign
 *  or re-form" and "mint a replacement partial"). Re-delivery is permitted; re-formation is not. */
const deliverPartialStep = (scenario: Scenario, operationId: string): void => {
  const { durable, runtime } = scenario;
  const operation = findOperation(durable, operationId);
  if (operation.kind !== "SEND_EXTERNAL") {
    throw new Error("crash-injection lifecycle: only an external send forms a partial");
  }
  const attempt = attemptRowFor(durable, operationId);
  if (attempt === undefined || attempt.innerPreimageText === null || attempt.step1Signature === null) {
    throw new Error("crash-injection lifecycle: partial delivery without persisted formation bytes");
  }
  let partial = durable.externalPartials.find((row) => row.operationId === operationId);
  if (partial === undefined) {
    const code = buildPartialCode(attempt.innerPreimageText, attempt.step1Signature);
    partial = { operationId, code, codeSha256: digestPreimage(code), deliveries: 0 };
    durable.externalPartials.push(partial);
    runtime.log.partialMints.push(operationId);
  }
  partial.deliveries += 1;
  runtime.volatile.partialCode = partial.code;
  runtime.log.partialDeliveries.push({ operationId, code: partial.code });
};

/** The last step index a kind performs — the default `stopAfterStep`, and the point a
 *  crash-free run of that kind reaches. */
export const finalStepFor = (kind: OperationKind): number => {
  return lastPerformedStepAtOrBefore(kind, LIFECYCLE_STEPS.length - 1);
};

/** The last step index recovery may re-run. LAND is excluded: on a recovery path landing is
 *  decided by a verified settlement observation, never by re-running the lifecycle's own
 *  landing step, so a resumed lifecycle can neither land on acknowledgement alone nor land a
 *  second time on top of the reconciliation that follows it. */
export const recoveryStopStepFor = (kind: OperationKind): number =>
  PERFORMS_STEP[kind].has("LAND")
    ? lastPerformedStepAtOrBefore(kind, STEP_LAND - 1)
    : finalStepFor(kind);

const lastPerformedStepAtOrBefore = (kind: OperationKind, upperStep: number): number => {
  for (let step = upperStep; step >= 0; step -= 1) {
    const name = LIFECYCLE_STEPS[step];
    if (name !== undefined && PERFORMS_STEP[kind].has(name)) {
      return step;
    }
  }
  throw new Error(`crash-injection lifecycle: kind ${kind} performs no step at or before ${upperStep}`);
};

/** Runs the lifecycle from `startFromStep` to `stopAfterStep` (default: the kind's last step).
 *  Steps this kind does not perform are skipped, so the index space stays shared across kinds.
 *  Steps are atomic durable commits and idempotent against their own surviving output, so a
 *  recovered lifecycle may safely re-enter at the step matching its durable residue. */
export const runLifecycle = (
  scenario: Scenario,
  submitPort: SubmitPort,
  startFromStep: number = STEP_CREATE,
  stopAfterStep?: number,
): void => {
  const operation = scenario.durable.operations[0];
  if (operation === undefined) {
    throw new Error("crash-injection lifecycle: scenario has no operation row");
  }
  const operationId = operation.operationId;
  const kind = operation.kind;
  const lastStep = stopAfterStep ?? finalStepFor(kind);
  for (let step = startFromStep; step <= lastStep; step += 1) {
    const name = LIFECYCLE_STEPS[step];
    if (name === undefined || !PERFORMS_STEP[kind].has(name)) {
      continue;
    }
    switch (name) {
      case "CREATE":
        createStep(scenario, operationId, scenario.runtime.payerStep1Signature);
        break;
      case "INNER_PREIMAGE":
        innerPreimageStep(scenario, operationId);
        break;
      case "SIGN_STEP1":
        signStep1Step(scenario, operationId);
        break;
      case "STEP2_PREIMAGE":
        step2PreimageStep(scenario, operationId);
        break;
      case "SIGN_STEP2":
        signStep2Step(scenario, operationId);
        break;
      case "SUBMIT":
        submitStep(scenario, operationId, submitPort);
        break;
      case "LAND":
        landStep(scenario, operationId);
        break;
      case "DELIVER_PARTIAL":
        deliverPartialStep(scenario, operationId);
        break;
    }
  }
};

/** The crash boundary: discard all volatile state, JSON round-trip the durable store so only
 *  committed bytes cross, and construct a brand-new runtime with an empty effect log. A fresh
 *  submit port is supplied by the recovery caller — the crashed port died with the old runtime. */
export const crashAndRecover = (scenario: Scenario): Scenario => ({
  durable: JSON.parse(JSON.stringify(scenario.durable)) as Scenario["durable"],
  runtime: createRuntime(
    scenario.runtime.workerId,
    scenario.runtime.seedByte,
    scenario.runtime.payerStep1Signature,
  ),
});

/** Drives the lifecycle to the durable residue that characterizes a crash point, then crashes.
 *  `submitOutcome` selects the gateway behavior for the SUBMIT step (only reached by crash
 *  points at/after SUBMIT). Returns the recovered scenario (brand-new runtime). */
export const crashAt = (
  scenario: Scenario,
  submitPort: SubmitPort,
  crashPoint: CrashPoint,
): Scenario => {
  runLifecycle(scenario, submitPort, STEP_CREATE, CRASH_POINTS[crashPoint]);
  return crashAndRecover(scenario);
};
