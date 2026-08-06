/**
 * Restart + independent-observer scenarios.
 *
 * Acceptance criteria:
 * - Every catalogued injection point exercised for ≥1 of the three operations, then full
 * operations recovery boot replay asserted step-by-step. Distinct durable residues per named point.
 *   - Independent observer is a separate instance (ledger/cursor/config); ≥1 scenario
 *     quarantines on node/observer disagreement derived from dual logs (not hand booleans).
 *   - A,A and A,B,C,A run through BOTH node and observer logs; both classifications asserted.
 *   - No silent gap: COMPLETE_PATH only from a real body+head proof; else INDETERMINATE.
 *   - Boot's negative list has an explicit negative test per item (load-bearing probes).
 *
 * Offline only. Extends crash-injection + boot-recovery + observation
 * sequence driver.
 *
 * Deferred (parent chaos matrix, not claimed satisfied here): ACK-without-landing as a
 * named product scenario beyond residue overlays; lag; queue pressure; redelivery matrix
 * beyond SEND outbox pair. Wrapper/EQUIVALENT covered narrowly via SEQ_EQUIVALENT.
 */
import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  ALL_KINDS,
  BT_11_5_INJECTION_POINTS,
  EXPECTED_AA_RELATIONSHIPS,
  EXPECTED_ABCA_RELATIONSHIPS,
  EXPECTED_BOOT_STEPS,
  EXPECTED_EQUIVALENT_RELATIONSHIPS,
  NODE_ENDPOINT_FP,
  NODE_OBSERVER_ID,
  PLATFORM_ENDPOINT_FP,
  PLATFORM_OBSERVER_ID,
  SEQ_AA,
  SEQ_ABCA,
  SEQ_EQUIVALENT,
  SEND_OUTBOX_PAIR,
  SUBMITTING_KINDS,
  baseCrashPointFor,
  bootAfterCrash,
  buildExactLandingProofFromBody,
  classifyResidue,
  classifyTerminalOutcome,
  countingSubmit,
  crashAt,
  crashAtInjection,
  crashPointFor,
  crashRecoverBoot,
  crashThenRecover,
  createIndependentObserver,
  deriveLandingClaim,
  dualObserverAgreement,
  emptyBootState,
  freshScenario,
  heldLeadership,
  makeBootActions,
  makeBootStore,
  mapResidueToBootEvidence,
  mintLandingPathProofFromOracle,
  observeSequence,
  observerAppendedRelationships,
  postSubmitOverlayFor,
  residueFingerprint,
  runDirectVerifierOnCapture,
  settlementCaptureFromBody,
  snapshotDurable,
  type ScenarioTerminalOutcome,
} from "./restart-observer-harness.ts";

import { runDeterministicBootRecovery as runBoot } from "../src/workers/boot-recovery.js";

beforeAll(async () => {
  await ready();
});

const LANDED = { kind: "LANDED_VERIFIED" as const };
const NOT_LANDED = { kind: "NOT_LANDED_YET" as const };
const ANOMALOUS = { kind: "ANOMALOUS" as const };

const isTerminalOutcome = (o: ScenarioTerminalOutcome): boolean =>
  o.kind === "COMPLETE_PATH" ||
  o.kind === "INDETERMINATE" ||
  o.kind === "INVARIANT_BREACH" ||
  o.kind === "QUARANTINED_DISAGREEMENT";

// ── crash injection × boot ────────────────────────────────────────

describe("crash injection + boot replay", () => {
  it("catalogue enumerates all seven catalogued injection points", () => {
    expect(BT_11_5_INJECTION_POINTS).toHaveLength(7);
    expect([...BT_11_5_INJECTION_POINTS]).toEqual([
      "before_signed_bytes_persist",
      "after_persist_before_submit",
      "during_submit_no_response",
      "after_gateway_acceptance_before_local_ack",
      "after_local_ack_before_event_emission",
      "during_reconciliation",
      "before_and_after_outbox_delivery",
    ]);
  });

  it.each(SUBMITTING_KINDS)(
    "%s: seven catalogued names produce seven distinct durable residue fingerprints",
    (kind) => {
      const { port } = countingSubmit();
      const fps = new Set<string>();
      for (const injection of BT_11_5_INJECTION_POINTS) {
        const { fingerprint } = crashAtInjection(kind, injection, port);
        expect(fps.has(fingerprint), `duplicate fingerprint for ${injection}: ${fingerprint}`).toBe(
          false,
        );
        fps.add(fingerprint);
      }
      expect(fps.size).toBe(7);
    },
  );

  it.each(
    BT_11_5_INJECTION_POINTS.flatMap((injection) =>
      (["RECEIVE_EXTERNAL", "MOVE_INTERNAL"] as const).map((kind) => ({ kind, injection })),
    ),
  )(
    "$kind @ $injection → crash → recover → boot (8 steps) → terminal outcome",
    async ({ kind, injection }) => {
      const crashPoint = crashPointFor(kind, injection);
      const overlay = postSubmitOverlayFor(kind, injection);
      // Post-submit residues (any overlay, or AFTER_SUBMIT base) reconcile by observation.
      const isPostSubmit =
        overlay !== null || crashPoint === "AFTER_SUBMIT";
      const landing = isPostSubmit ? NOT_LANDED : LANDED;

      const result = await crashRecoverBoot(kind, injection, landing);

      expect(result.boot.stepsCompleted).toEqual([...EXPECTED_BOOT_STEPS]);
      expect(isTerminalOutcome(result.outcome)).toBe(true);

      if (landing.kind === "NOT_LANDED_YET") {
        expect(result.outcome.kind).toBe("INDETERMINATE");
        expect(result.outcome.kind === "INDETERMINATE" && result.outcome.reason).toBeTruthy();
      } else {
        // COMPLETE_PATH only when dual observers re-derived a real body proof.
        expect(result.outcome.kind).toBe("COMPLETE_PATH");
        expect(result.proof).toBeDefined();
        expect(result.proof && result.proof.kind !== "PROOF_INCOMPLETE").toBe(true);
        expect(result.nodeObserver).not.toBeNull();
        expect(result.platformObserver).not.toBeNull();
        expect(deriveLandingClaim(result.nodeObserver!)).toBe(true);
        expect(deriveLandingClaim(result.platformObserver!)).toBe(true);
      }

      expect(result.submitCalls).toBeLessThanOrEqual(1);

      if (result.outcome.kind === "INDETERMINATE") {
        expect(result.durableSnap.leaseHeld).toBe(true);
      }
    },
  );

  it("SEND_EXTERNAL: before AND after outbox delivery (catalogued pair) never submits", async () => {
    const { port, calls } = countingSubmit();
    for (const crashPoint of SEND_OUTBOX_PAIR) {
      const crashed = crashAt(freshScenario("SEND_EXTERNAL"), port, crashPoint);
      const { scenario, outcome } = crashThenRecover(crashed, port, NOT_LANDED);
      expect(outcome.classification).toMatch(/PARTIAL|SIGNING_CLAIMED/);
      const { report } = await bootAfterCrash(scenario.durable);
      expect(report.stepsCompleted).toEqual([...EXPECTED_BOOT_STEPS]);
      expect(report.counters.submitCalls).toBe(0);
      expect(snapshotDurable(scenario.durable).partials).toBe(1);
    }
    expect(calls).toHaveLength(0);
  });

  it.each(ALL_KINDS)(
    "%s: every applicable catalogued injection produces a non-silent terminal outcome",
    async (kind) => {
      for (const injection of BT_11_5_INJECTION_POINTS) {
        const crashPoint = crashPointFor(kind, injection);
        const overlay = postSubmitOverlayFor(kind, injection);
        const landing =
          overlay !== null ||
          crashPoint === "AFTER_SUBMIT" ||
          crashPoint === "AFTER_DELIVER_PARTIAL"
            ? NOT_LANDED
            : LANDED;
        const result = await crashRecoverBoot(kind, injection, landing);
        expect(isTerminalOutcome(result.outcome)).toBe(true);
        if (result.outcome.kind !== "COMPLETE_PATH") {
          expect(
            "reason" in result.outcome && typeof result.outcome.reason === "string",
          ).toBe(true);
        }
      }
    },
  );
});

// ── operations recovery boot step-by-step over crash residue ────────────────────────────────

describe("operations recovery boot procedure step-by-step over crash residue", () => {
  it("stepsCompleted is exactly the 8-step BOOT_RECOVERY_STEPS order", async () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_SIGN_STEP2");
    const { report } = await bootAfterCrash(crashed.durable, {
      observationBytes: new Uint8Array([9, 9, 9]),
    });
    expect(report.stepsCompleted).toEqual([
      "LEADERSHIP_PRECONDITION",
      "KEY_CORRESPONDENCE",
      "LEASE_AUDIT",
      "PHASE_AUDIT",
      "CLASSIFY",
      "RESUME",
      "REBUILD_QUEUES",
      "READINESS",
    ]);
    expect(report.leadershipHeld).toBe(true);
  });

  it("post-submit residue classifies INDETERMINATE at boot (no re-submit)", async () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_SUBMIT");
    expect(calls).toHaveLength(1);
    const { report, state } = await bootAfterCrash(crashed.durable);
    expect(report.classifications[0]?.classification).toBe("INDETERMINATE");
    expect(report.classifications[0]?.authorizedResume).toBeNull();
    expect(state.submitCalls).toBe(0);
    expect(report.counters.submitCalls).toBe(0);
  });

  it("raw-byte gate loads prior bytes; digest alone never authorizes readiness", async () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_CREATE");
    const mapped = mapResidueToBootEvidence(crashed.durable);
    const state = emptyBootState({
      ops: mapped.ops,
      leases: mapped.leases,
      keys: mapped.keys,
      cursors: [
        {
          streamKey: "w-src:node",
          lastRecordedObservationId: "obs-gone",
          lastRawResponseSha256: "f".repeat(64),
        },
      ],
      rawByObservationId: new Map([["obs-gone", null]]),
    });
    const report = await runBoot({
      leadership: heldLeadership(),
      store: makeBootStore(state),
      actions: makeBootActions(state),
    });
    expect(report.rawByteHydrations[0]?.ok).toBe(false);
    expect(report.rawByteHydrations[0]?.usedDigestShortcut).toBe(false);
    expect(report.ready).toBe(false);
  });
});

// ── Boot does not (six negatives) — load-bearing probes only ──────────────────

describe("operations recovery Boot does not — explicit negative per item", () => {
  it("never deletes a stale lease based on time", async () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_SUBMIT");
    const leaseCountBefore = mapResidueToBootEvidence(crashed.durable).leases.length;
    expect(leaseCountBefore).toBeGreaterThan(0);

    const { report, state } = await bootAfterCrash(crashed.durable, { nowMs: 99_000_000 });

    // Load-bearing: leases inventory unchanged; stale observed but retained.
    expect(state.leases.length).toBe(leaseCountBefore);
    expect(report.leaseFindings.some((f) => f.staleHeartbeatObserved)).toBe(true);
    expect(report.leaseFindings.every((f) => f.severity !== "breach" || !/delet|releas/i.test(f.reason))).toBe(
      true,
    );
    const deleteFindings = report.leaseFindings.filter((f) => /delet|releas/i.test(f.reason));
    expect(deleteFindings).toHaveLength(0);
    expect(report.leaseFindings.every((f) => f.reason !== "lease_deleted_for_stale_heartbeat")).toBe(
      true,
    );
  });

  it("never submits an attempt whose call boundary is ambiguous", async () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_SUBMIT");
    expect(calls).toHaveLength(1);
    const recovered = crashThenRecover(crashed, port, NOT_LANDED);
    expect(calls).toHaveLength(1);
    const { report, state } = await bootAfterCrash(recovered.scenario.durable);
    expect(report.classifications.some((c) => c.classification === "INDETERMINATE")).toBe(true);
    // Load-bearing: authorizedResume is null AND no SUBMIT_ONCE was invoked.
    expect(report.classifications.every((c) => c.authorizedResume === null)).toBe(true);
    expect(state.resumed.filter((a) => a.kind === "SUBMIT_ONCE")).toHaveLength(0);
    expect(state.submitCalls).toBe(0);
  });

  it("never re-forms an external partial", async () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("SEND_EXTERNAL"), port, "AFTER_DELIVER_PARTIAL");
    const before = snapshotDurable(crashed.durable);
    expect(before.partials).toBe(1);
    const codeBefore = before.partialCode;
    const { scenario } = crashThenRecover(crashed, port, NOT_LANDED);
    const after = snapshotDurable(scenario.durable);
    // Load-bearing: exact code bytes unchanged; still exactly one partial row.
    expect(after.partials).toBe(1);
    expect(after.partialCode).toBe(codeBefore);
    expect(after.partialCodeSha256).toBe(before.partialCodeSha256);
    expect(calls).toHaveLength(0);

    const { report, state } = await bootAfterCrash(scenario.durable);
    // Boot resume must not be a formation action that could re-mint.
    const formationKinds = state.resumed.filter(
      (a) => a.kind === "FIRST_FORMATION" || a.kind === "RESUME_T0_AND_CODE_FORMATION",
    );
    expect(formationKinds).toHaveLength(0);
    // Classification is WAITING / CONTINUE_WAITING — never a re-form path.
    expect(
      report.classifications.every(
        (c) =>
          c.authorizedResume === null ||
          c.authorizedResume.kind === "CONTINUE_WAITING" ||
          c.classification === "WAITING",
      ),
    ).toBe(true);
  });

  it("never auto-clears attention", async () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_SUBMIT");
    const { scenario } = crashThenRecover(crashed, port, ANOMALOUS);
    expect(snapshotDurable(scenario.durable).needsAttention).toBe(true);

    const mapped = mapResidueToBootEvidence(scenario.durable);
    const ops = mapped.ops.map((o) => ({ ...o, attentionRequired: true }));
    const state = emptyBootState({
      ops,
      leases: mapped.leases,
      keys: mapped.keys,
    });
    const report = await runBoot({
      leadership: heldLeadership(),
      store: makeBootStore(state),
      actions: makeBootActions(state),
    });
    // Load-bearing: attentionRequired remains true on inventory; boot may SET attention
    // but the fake has no clearAttention port — prove ops still require attention and
    // no resume "cleared" the flag via a side channel.
    expect(state.ops.every((o) => o.attentionRequired === true)).toBe(true);
    expect(state.ops.some((o) => o.attentionRequired === false)).toBe(false);
    expect(report.stepsCompleted).toContain("RESUME");
  });

  it("never auto-accepts a new destination", async () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_CREATE");
    const mappedBefore = mapResidueToBootEvidence(crashed.durable);
    const keyIdsBefore = mappedBefore.keys.map((k) => k.walletId).sort();
    const { report, state } = await bootAfterCrash(crashed.durable);
    // Load-bearing: key correspondence set is exactly the residue set — no new dst accepted.
    const keyIdsAfter = state.keys.map((k) => k.walletId).sort();
    expect(keyIdsAfter).toEqual(keyIdsBefore);
    // No quarantine of dst that would imply silent accept-then-repair of an unknown wallet.
    expect(state.keys).toHaveLength(2); // src + dst already in MOVE residue
    expect(report.stepsCompleted).toEqual([...EXPECTED_BOOT_STEPS]);
    // Resume actions never invent a destination-accept kind (closed set has none).
    expect(
      state.resumed.every(
        (a) =>
          a.kind === "FIRST_FORMATION" ||
          a.kind === "SIGN_PERSISTED_PREIMAGE" ||
          a.kind === "SIGN_PERSISTED_STEP2_PREIMAGE" ||
          a.kind === "SUBMIT_ONCE" ||
          a.kind === "RESUME_T0_AND_CODE_FORMATION" ||
          a.kind === "CONTINUE_WAITING",
      ),
    ).toBe(true);
  });

  it("never synthesizes missing exact bytes from parsed JSON", async () => {
    const { port, calls } = countingSubmit();
    const scenario = freshScenario("MOVE_INTERNAL");
    const crashed = crashAt(scenario, port, "AFTER_SIGN_STEP1");
    const attempt = crashed.durable.attempts[0];
    if (attempt === undefined) throw new Error("expected attempt");
    // Strip exact bytes while leaving the audit row — the forbidden "synthesize from audit".
    const auditBefore = crashed.durable.signerAudit.length;
    expect(auditBefore).toBeGreaterThan(0);
    attempt.innerPreimageText = null;
    attempt.innerSha256 = null;

    const classification = classifyResidue(
      crashed.durable,
      crashed.durable.operations[0]!.operationId,
    );
    expect(classification).toBe("INVARIANT_BREACH");

    const { report, state } = await bootAfterCrash(crashed.durable);
    // Load-bearing: boot classifies breach; does not resume a sign/submit that would need
    // synthesized bytes; preimage still absent on the mapped ops.
    expect(
      report.invariantBreach ||
        report.classifications.some((c) => c.classification === "INVARIANT_BREACH"),
    ).toBe(true);
    expect(state.resumed.filter((a) => a.kind === "SIGN_PERSISTED_PREIMAGE")).toHaveLength(0);
    expect(state.resumed.filter((a) => a.kind === "SUBMIT_ONCE")).toHaveLength(0);
    expect(state.signCalls).toBe(0);
    expect(state.submitCalls).toBe(0);
    // Evidence still reports exactPreimagePersisted false — nothing invented a body.
    expect(state.ops.every((o) => o.exactPreimagePersisted === false || o.signerAuditIndicatesCall)).toBe(
      true,
    );
    expect(calls).toHaveLength(0);
  });
});

// ── Independent observer ───────────────────────────────────

describe("independent observer — separate instance", () => {
  it("node and platform observers have distinct id, endpoint fingerprint, and cursor", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);

    expect(node.observerId).not.toBe(platform.observerId);
    expect(node.endpointFingerprint).not.toBe(platform.endpointFingerprint);
    expect(node.transport).not.toBe(platform.transport);
    expect(node.cursor).not.toBe(platform.cursor);
    expect(node.cursor.rowCount).toBe(0);
    expect(platform.cursor.rowCount).toBe(0);
    expect(node.log).toHaveLength(0);
    expect(platform.log).toHaveLength(0);
  });

  it("A,A is independently exercised in BOTH node and platform logs", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);

    observeSequence(node, SEQ_AA);
    observeSequence(platform, SEQ_AA);

    expect(observerAppendedRelationships(node)).toEqual([...EXPECTED_AA_RELATIONSHIPS]);
    expect(observerAppendedRelationships(platform)).toEqual([...EXPECTED_AA_RELATIONSHIPS]);
    expect(node.cursor.rowCount).toBe(1);
    expect(platform.cursor.rowCount).toBe(1);
    expect(node.cursor.consecutiveRepeatCount).toBe(1);
    expect(platform.cursor.consecutiveRepeatCount).toBe(1);
    expect(node.log).not.toBe(platform.log);
    // platform integration steps 1–7 completed on each stream (no proof → step 9 settlement false).
    expect(node.verifierSteps.every((s) => s.completedSteps.includes(1))).toBe(true);
    expect(platform.verifierSteps.every((s) => s.completedSteps.includes(6))).toBe(true);
  });

  it("A,B,C,A is independently exercised in BOTH node and platform logs", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);

    observeSequence(node, SEQ_ABCA);
    observeSequence(platform, SEQ_ABCA);

    expect(observerAppendedRelationships(node)).toEqual([...EXPECTED_ABCA_RELATIONSHIPS]);
    expect(observerAppendedRelationships(platform)).toEqual([...EXPECTED_ABCA_RELATIONSHIPS]);
    expect(node.cursor.rowCount).toBe(4);
    expect(platform.cursor.rowCount).toBe(4);
    expect(node.log.filter((e) => e.anomalyAppended)).toHaveLength(1);
    expect(platform.log.filter((e) => e.anomalyAppended)).toHaveLength(1);
  });

  it("EQUIVALENT_STATE_DIFFERENT_ENVELOPE on both streams (wrapper change)", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    observeSequence(node, SEQ_EQUIVALENT);
    observeSequence(platform, SEQ_EQUIVALENT);
    expect(observerAppendedRelationships(node)).toEqual([...EXPECTED_EQUIVALENT_RELATIONSHIPS]);
    expect(observerAppendedRelationships(platform)).toEqual([...EXPECTED_EQUIVALENT_RELATIONSHIPS]);
  });

  it("activity on the node stream never mutates the platform cursor (no shared state)", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);

    observeSequence(node, SEQ_ABCA);
    expect(platform.cursor.rowCount).toBe(0);
    expect(platform.log).toHaveLength(0);
    expect(node.cursor.rowCount).toBe(4);
  });

  it("direct platform observation that contradicts the node quarantines (derived claims)", () => {
    const node = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);

    // Node walks a clean settlement body + real proof → claims landed.
    const body = '{"tx":"settled-node-claim","amt":"1"}';
    const proof = buildExactLandingProofFromBody(body, "obs-node-head");
    const capture = settlementCaptureFromBody(body);
    runDirectVerifierOnCapture(node, capture, {
      landingProof: proof,
      expectedBodySha256: proof.expectedBodySha256,
    });
    expect(deriveLandingClaim(node)).toBe(true);

    // Platform independently sees A,B,C,A ending in REGRESSION — no settlement proof.
    observeSequence(platform, SEQ_ABCA);
    expect(deriveLandingClaim(platform)).toBe(false);

    const dual = dualObserverAgreement(node, platform);
    expect(dual.nodeClaimLanded).toBe(true);
    expect(dual.platformClaimLanded).toBe(false);
    expect(dual.agrees).toBe(false);

    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SUBMITTED_RECONCILE",
      landingObservation: LANDED,
      proof,
      nodeClaimLanded: dual.nodeClaimLanded,
      observerAgreesWithNode: dual.agrees,
    });
    expect(outcome.kind).toBe("QUARANTINED_DISAGREEMENT");
    expect(outcome.kind === "QUARANTINED_DISAGREEMENT" && outcome.reason).toMatch(/contradict/i);
  });

  it("platform restart resumes from its OWN observation log, not a node cache", () => {
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    observeSequence(platform, SEQ_AA);
    const savedCursor = {
      ...platform.cursor,
      acceptedStateSignatureHistory: [...platform.cursor.acceptedStateSignatureHistory],
    };

    const restarted = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    restarted.cursor = savedCursor;

    observeSequence(restarted, [SEQ_ABCA[1]!]);
    expect(observerAppendedRelationships(restarted)).toEqual(["SUCCESSOR"]);
    expect(restarted.cursor.rowCount).toBe(2);

    const lost = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    observeSequence(lost, [SEQ_ABCA[1]!]);
    expect(observerAppendedRelationships(lost)).toEqual(["FIRST"]);
  });

  it("forged node success without direct platform observation cannot mark success", () => {
    const platform = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    // Platform has observed nothing. Node would claim COMPLETE_PATH with a proof.
    const body = '{"tx":"forged"}';
    const proof = buildExactLandingProofFromBody(body, "obs-forged");
    const dual = dualObserverAgreement(
      // Node that "saw" the body:
      (() => {
        const n = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
        runDirectVerifierOnCapture(n, settlementCaptureFromBody(body), {
          landingProof: proof,
          expectedBodySha256: proof.expectedBodySha256,
        });
        return n;
      })(),
      platform,
    );
    expect(dual.nodeClaimLanded).toBe(true);
    expect(dual.platformClaimLanded).toBe(false);
    expect(dual.agrees).toBe(false);

    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SUBMITTED_RECONCILE",
      landingObservation: LANDED,
      proof,
      nodeClaimLanded: dual.nodeClaimLanded,
      observerAgreesWithNode: dual.agrees,
    });
    expect(outcome.kind).toBe("QUARANTINED_DISAGREEMENT");
  });
});

// ── INDETERMINATE is a valid terminal outcome (not a test failure) ────────────

describe("INDETERMINATE is a valid terminal outcome", () => {
  it.each(SUBMITTING_KINDS)(
    "%s: gap after submit → INDETERMINATE with recorded reason (not a failure)",
    async (kind) => {
      const result = await crashRecoverBoot(kind, "during_submit_no_response", NOT_LANDED);
      expect(result.outcome.kind).toBe("INDETERMINATE");
      if (result.outcome.kind === "INDETERMINATE") {
        expect(result.outcome.reason.length).toBeGreaterThan(0);
        expect(result.outcome.fault).toBe("GAP");
      }
      expect(result.durableSnap.leaseHeld).toBe(true);
      expect(result.submitCalls).toBe(1);
      // Distinct residue: mid-submit has claim but no response recorded.
      expect(result.overlay).toBe("MID_SUBMIT_NO_RESPONSE");
      expect(result.recoveredScenario.durable.attempts[0]?.submitResponseRecorded).toBe(false);
    },
  );

  it("proof-budget exhaustion folds to INDETERMINATE, never COMPLETE_PATH", () => {
    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SUBMITTED_RECONCILE",
      landingObservation: LANDED,
      proof: { kind: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" },
    });
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.fault).toBe("BUDGET_EXHAUSTED");
    }
  });

  it("anomalous head → INDETERMINATE (fail closed)", () => {
    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SUBMITTED_RECONCILE",
      landingObservation: ANOMALOUS,
    });
    expect(outcome.kind).toBe("INDETERMINATE");
  });

  it("LANDED_VERIFIED without explicit proof is INDETERMINATE (no default mint)", () => {
    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SIGNED_SUBMIT_ONCE",
      landingObservation: LANDED,
      // deliberately no proof
    });
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.reason).toMatch(/without_d9_6_proof|MISSING_BODY/i);
    }
  });

  it("COMPLETE_PATH requires a positive proof built from body bytes + verified observation", () => {
    const body = '{"completed":true,"op":"recv-1"}';
    const proof = buildExactLandingProofFromBody(body, "obs-1");
    expect(proof.kind).toBe("LANDED_EXACT");
    expect(proof.expectedBodySha256.length).toBe(64);
    expect(proof.freshHeadObservationId).toBe("obs-1");

    const outcome = classifyTerminalOutcome({
      recoveryClassification: "SUBMITTED_RECONCILE",
      landingObservation: LANDED,
      proof,
    });
    expect(outcome.kind).toBe("COMPLETE_PATH");
  });

  it("mintLandingPathProofFromOracle alone is not enough without being passed as explicit proof", () => {
    // Regression guard: classifier must not auto-mint.
    const outcome = classifyTerminalOutcome({
      recoveryClassification: "NO_ATTEMPT_RESUME_FORMATION",
      landingObservation: LANDED,
    });
    expect(outcome.kind).not.toBe("COMPLETE_PATH");
    // Keep mint helper available for tests that build proofs deliberately:
    const deliberate = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet",
      expectedBodySha256: "c".repeat(64),
      freshHeadBodySha256: ("c".repeat(64) + "-head"),
      freshHeadObservationId: "obs-1",
      depth: 2,
    });
    expect(deliberate.kind).toBe("LANDED_COMPLETE_PATH");
  });
});

// ── Composition: crash + boot + dual-observer on RECEIVE and MOVE ─────────────

describe("composition: crash → boot → dual-observer re-derives landing", () => {
  it("post-submit RECEIVE: boot parks INDETERMINATE; observers agree not-landed", async () => {
    const result = await crashRecoverBoot(
      "RECEIVE_EXTERNAL",
      "after_gateway_acceptance_before_local_ack",
      NOT_LANDED,
    );
    expect(result.boot.stepsCompleted).toEqual([...EXPECTED_BOOT_STEPS]);
    expect(result.outcome.kind).toBe("INDETERMINATE");
    expect(result.overlay).toBe("GATEWAY_ACCEPTED_NO_LOCAL_ACK");
    // Residue distinct from mid-submit / local-ack / reconciling.
    expect(result.recoveredScenario.durable.attempts[0]?.submitResponseRecorded).toBe(true);
    expect(result.recoveredScenario.durable.events.includes("submit.local_ack")).toBe(false);

    expect(result.nodeObserver).not.toBeNull();
    expect(result.platformObserver).not.toBeNull();
    expect(deriveLandingClaim(result.nodeObserver!)).toBe(false);
    expect(deriveLandingClaim(result.platformObserver!)).toBe(false);
  });

  it("pre-submit RECEIVE crash → COMPLETE_PATH from body proof; dual observers agree", async () => {
    const result = await crashRecoverBoot(
      "RECEIVE_EXTERNAL",
      "before_signed_bytes_persist",
      LANDED,
    );
    expect(result.outcome.kind).toBe("COMPLETE_PATH");
    expect(result.boot.stepsCompleted).toEqual([...EXPECTED_BOOT_STEPS]);
    expect(result.proof?.kind).toBe("LANDED_EXACT");
    expect(result.nodeObserver).not.toBeNull();
    expect(result.platformObserver).not.toBeNull();

    const dual = dualObserverAgreement(result.nodeObserver!, result.platformObserver!);
    expect(dual.nodeClaimLanded).toBe(true);
    expect(dual.platformClaimLanded).toBe(true);
    expect(dual.agrees).toBe(true);
    // platform integration full walk including settlement predicate.
    expect(result.nodeObserver!.verifierSteps[0]?.completedSteps).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(result.nodeObserver!.verifierSteps[0]?.settlementPredicateOk).toBe(true);
    expect(result.platformObserver!.verifierSteps[0]?.settlementPredicateOk).toBe(true);
  });

  it("pre-submit MOVE crash → COMPLETE_PATH; dual observers re-derive from MOVE body", async () => {
    const result = await crashRecoverBoot(
      "MOVE_INTERNAL",
      "after_persist_before_submit",
      LANDED,
    );
    expect(result.outcome.kind).toBe("COMPLETE_PATH");
    expect(result.proof?.kind).toBe("LANDED_EXACT");
    const body = result.recoveredScenario.durable.attempts[0]?.completedTransactionText;
    expect(body).toBeTruthy();
    expect(result.proof && "expectedBodySha256" in result.proof && result.proof.expectedBodySha256)
      .toBeTruthy();

    const dual = dualObserverAgreement(result.nodeObserver!, result.platformObserver!);
    expect(dual.agrees).toBe(true);
    expect(dual.nodeClaimLanded).toBe(true);
  });

  it("during_reconciliation residue is distinct and stays INDETERMINATE without landing proof", async () => {
    const result = await crashRecoverBoot(
      "MOVE_INTERNAL",
      "during_reconciliation",
      NOT_LANDED,
    );
    expect(result.overlay).toBe("RECONCILING");
    expect(result.recoveredScenario.durable.events.includes("reconcile.awaiting_settlement")).toBe(
      true,
    );
    expect(result.outcome.kind).toBe("INDETERMINATE");
  });

  it("after_local_ack_before_event_emission residue carries local_ack, no landed event", async () => {
    const { port } = countingSubmit();
    const { scenario, fingerprint } = crashAtInjection(
      "RECEIVE_EXTERNAL",
      "after_local_ack_before_event_emission",
      port,
    );
    expect(scenario.durable.events.includes("submit.local_ack")).toBe(true);
    expect(scenario.durable.events.some((e) => /landed/i.test(e))).toBe(false);
    // Distinct from gateway-accepted-no-ack:
    const other = crashAtInjection(
      "RECEIVE_EXTERNAL",
      "after_gateway_acceptance_before_local_ack",
      countingSubmit().port,
    );
    expect(fingerprint).not.toBe(other.fingerprint);
  });
});

// Sanity: keep unused exports referenced for typecheck when tree-shaken in some runners
void baseCrashPointFor;
void residueFingerprint;
