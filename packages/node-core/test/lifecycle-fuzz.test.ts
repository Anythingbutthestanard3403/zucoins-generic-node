/**
 * Lifecycle & recovery sequence fuzzer: CORE PROPERTIES.
 *
 * Acceptance: no crash, permissive parse, normalization, secret leak, or unauthorized
 * transition; every observed transition ∈ state/event (RUNTIME_FIREABLE); no forbidden alias
 *; crash-injected sequences resolve to exactly one recovery classification; no reserved
 * PROVEN_NOT_LANDED transition fires. Deterministic: pinned seed + numRuns + endOnFailure.
 *
 * TEST-ONLY; runs under packages/node-core/test/** so setup-network-guard.ts is active.
 */
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import { SEND_EXTERNAL_TRANSITIONS } from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  RECONCILE_CLASSIFICATION_KINDS,
  classifyReceiveReconcile,
  classifyMoveReconcile,
  classifySendReconcile,
} from "../src/protocol/reconcile/index.js";
import { FORBIDDEN_EFFECT_DETECTORS, snapshotDurable } from "./crash-replay-recovery.ts";
import { OPERATION_ID } from "./crash-replay-fixtures.ts";
import {
  ANOMALOUS_VARIANTS,
  DURABLE_STATES,
  acquisitionAttemptArb,
  crashReplayActionArb,
  moveInputArb,
  receiveInputArb,
  runCrashReplay,
  sendInputArb,
  simulateWalletAcquisitions,
} from "./lifecycle-fuzz-alphabet.ts";
import {
  FUZZ_NUM_RUNS,
  FUZZ_SEED,
  assertNoSecretLeak,
  assertObservedStateAllowed,
  classifyObservedTransition,
  isReconcileClassificationKind,
} from "./lifecycle-fuzz-oracles.ts";

const CFG = { seed: FUZZ_SEED, numRuns: FUZZ_NUM_RUNS, endOnFailure: true } as const;

// Coverage-floor accumulators (amendment 10) — populated inside properties, asserted after.
const seenDurableStates = new Set<string>();
const seenAnomalousVariants = new Set<string>();
let sawReleasedLeaseDuringReconcile = false;
let sawTwoPlusSameWalletAcquisitions = false;

beforeAll(async () => {
  await ready();
});

describe("network containment guard is installed", () => {
  it("fetch is network-contained", async () => {
    await expect(globalThis.fetch("http://127.0.0.1/should-not-reach")).rejects.toThrow(
      /network-contained/i,
    );
  });
});

describe("JC1 — classification vocabulary is the 5-member closed set", () => {
  it("RECONCILE_CLASSIFICATION_KINDS has exactly 5 members and no PROVEN_NOT_LANDED", () => {
    expect(RECONCILE_CLASSIFICATION_KINDS.length).toBe(5);
    expect([...RECONCILE_CLASSIFICATION_KINDS]).not.toContain("PROVEN_NOT_LANDED");
  });
});

describe("classification closure + totality (no crash)", () => {
  it("classifyReceiveReconcile: output kind ∈ closed set; never crashes", () => {
    fc.assert(
      fc.property(receiveInputArb, (input) => {
        if (input.boundary === "POST_SUBMIT" && input.receiverLeaseState === "RELEASED") {
          sawReleasedLeaseDuringReconcile = true;
        }
        const out = classifyReceiveReconcile(input);
        expect(isReconcileClassificationKind(out.kind)).toBe(true);
        // JC1.3 — no inbound rebuild authority after the submit boundary.
        if (input.boundary === "POST_SUBMIT") {
          expect(out.kind).not.toBe("PROVEN_NOT_STARTED");
        }
      }),
      CFG,
    );
  });

  it("classifyMoveReconcile: output kind ∈ closed set; never crashes", () => {
    fc.assert(
      fc.property(moveInputArb, (input) => {
        const out = classifyMoveReconcile(input);
        expect(isReconcileClassificationKind(out.kind)).toBe(true);
        // move has no NEEDS_ATTENTION→CREATED rebuild member — it can never be CREATED-bound.
        expect(out.kind).not.toBe("PROVEN_NOT_LANDED");
      }),
      CFG,
    );
  });

  it("classifySendReconcile: output kind ∈ closed set; never REJECTED (reserved transition)", () => {
    fc.assert(
      fc.property(sendInputArb, (input) => {
        if (input.boundary === "DELIVERED" && input.sourceLeaseState === "RELEASED") {
          sawReleasedLeaseDuringReconcile = true;
        }
        const out = classifySendReconcile(input);
        expect(isReconcileClassificationKind(out.kind)).toBe(true);
        // send's outcome union structurally excludes REJECTED — the reserved
        // NEEDS_ATTENTION→REJECTED transition can never originate here (JC1.2).
        expect(out.kind).not.toBe("REJECTED");
      }),
      CFG,
    );
  });
});

describe("crash-replay lane — exactly one classification, no unauthorized/reserved transition", () => {
  it("every crash+recover resolves to one classification with no forbidden effect", () => {
    fc.assert(
      fc.property(crashReplayActionArb, (action) => {
        const run = runCrashReplay(action);
        seenDurableStates.add(run.durableState);
        if (action.durableState === "PARTIAL_DELIVERED_HEAD_ANOMALOUS") {
          seenAnomalousVariants.add(action.anomalousVariant);
        }
        // exactly one recovery classification, equal to the driven residue.
        expect(run.outcome.classification).toBe(run.durableState);

        // JC1.4 — PROVEN_NOT_LANDED is never fed, so no terminalization / lease release.
        const { log } = run.scenario.runtime;
        expect(log.leaseReleases).toBe(0);
        expect(log.terminalizations.length).toBe(0);

        // Universally-forbidden effects (the never-blind-retry rule core) never fire on ANY residue: never a
        // second partial, a second sign intent, or a re-sign while a partial exists.
        expect(FORBIDDEN_EFFECT_DETECTORS.MINT_REPLACEMENT_PARTIAL(run.ctx)).toBe(false);
        expect(FORBIDDEN_EFFECT_DETECTORS.CREATE_SECOND_SIGN_INTENT(run.ctx)).toBe(false);
        expect(FORBIDDEN_EFFECT_DETECTORS.RE_SIGN_OR_RE_FORM(run.ctx)).toBe(false);
        // Once a partial exists, the FULL forbidden set must be silent (no new code, no expiry
        // refresh, no re-form, no non-landing inference) — the replacement-forbidden regime.
        if (run.ctx.before.partials >= 1) {
          for (const detect of Object.values(FORBIDDEN_EFFECT_DETECTORS)) {
            expect(detect(run.ctx)).toBe(false);
          }
        }

        // Cardinality: crash yields no partial or the exact one.
        const counts = snapshotDurable(run.scenario.durable, OPERATION_ID);
        expect(counts.partials).toBeLessThanOrEqual(1);
        expect(counts.intents).toBeLessThanOrEqual(1);

        // Transition-allowlist: every public operation-status transition ∈ RUNTIME_FIREABLE and
        // carries an allowed, non-reserved (from,to) — never PROVEN_NOT_LANDED-gated.
        for (const t of log.operationTransitions) {
          const verdict = classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
            from: t.from,
            to: t.to,
          });
          expect(verdict.verdict).toBe("ALLOWED");
          if (t.from !== null) assertObservedStateAllowed(t.from);
          assertObservedStateAllowed(t.to);
        }
      }),
      CFG,
    );
  });

  it("byte-exactness across the crash boundary (the byte-exact signing rule, tested not exercised)", () => {
    fc.assert(
      fc.property(crashReplayActionArb, (action) => {
        const run = runCrashReplay(action);
        const after = snapshotDurable(run.scenario.durable, OPERATION_ID);
        // Every served byte string equals the partial currently persisted (serve FROM STORE).
        for (const served of run.scenario.runtime.log.deliveriesServed) {
          expect(served.transferCodeText).toBe(after.codeText);
          expect(served.transferCodeSha256).toBe(after.codeSha);
        }
      }),
      CFG,
    );
  });
});

describe("wallet-wide lease — one in-flight operation per wallet (the one-in-flight-per-wallet rule)", () => {
  it(">=2 operation-role acquisitions on one wallet: exactly one reaches signing", () => {
    fc.assert(
      fc.property(fc.array(acquisitionAttemptArb, { minLength: 1, maxLength: 8 }), (attempts) => {
        const outcomes = simulateWalletAcquisitions(attempts);
        for (const outcome of outcomes.values()) {
          // wallet-wide invariant: never more than one active operation lease.
          expect(outcome.admittedOperationLeases).toBeLessThanOrEqual(1);
          if (outcome.operationRoleContenders >= 2) {
            sawTwoPlusSameWalletAcquisitions = true;
            expect(outcome.admittedOperationLeases).toBe(1);
            expect(outcome.reachedSigning).not.toBeNull();
          }
        }
      }),
      CFG,
    );
  });
});

describe("secret-leak scan (amendment 8)", () => {
  it("no secret-shaped field is reachable in any generated Action object", () => {
    fc.assert(
      fc.property(
        fc.oneof(receiveInputArb, moveInputArb, sendInputArb, crashReplayActionArb, acquisitionAttemptArb),
        (action) => {
          assertNoSecretLeak(action);
        },
      ),
      CFG,
    );
  });
});

describe("adversarial coverage floor (amendment 10 — no false negative)", () => {
  it("every crash boundary, every anomalous head, RELEASED-lease, and >=2 same-wallet acquisitions occurred", () => {
    for (const s of DURABLE_STATES) expect(seenDurableStates.has(s)).toBe(true);
    for (const v of ANOMALOUS_VARIANTS) expect(seenAnomalousVariants.has(v)).toBe(true);
    expect(sawReleasedLeaseDuringReconcile).toBe(true);
    expect(sawTwoPlusSameWalletAcquisitions).toBe(true);
  });
});
