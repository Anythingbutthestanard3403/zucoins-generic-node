/**
 * Halt at every durable phase.
 *
 * precedes signing; signature/full transaction precedes submit or delivery; terminal
 * observation precedes landed state") and the per-kind recovery matrices in,
 * 4.1, 5.2; `node-core rules` (verification-complete barrier).
 *
 * WHAT THIS SUITE PROVES. exit criterion is "Restart remains halted; engage and
 * disengage are equally gated and audited; no existing signed attempt is discarded". The last
 * clause is only verifiable by engaging the halt at every durable phase a signed attempt could
 * be mid-flight and confirming the attempt completes or resumes rather than being dropped or
 * duplicated. Halt is deliberately NOT given phase-aware logic of its own: the operation's own
 * durable-phase machinery resumes it, and halt only ever refuses to START new fund-moving
 * signing. So every assertion here is about what the EXISTING durable record permits,
 * with the halt gate layered on top.
 *
 * HOW THE PHASE LIST WAS ENUMERATED (never from this file's own catalogue — that would be
 * circular). Two external sources, both asserted below:
 * 1. The seven execution phases of `the state/event reference`, frozen by
 * as `HALT_RACE_PHASES` / `PHASE_APPLICABILITY` / `HALT_RACE_TABLE` in
 * `operator-halt/races.contract.ts`. `covers every frozen state/event execution phase`
 *      asserts the mapping is count-exact in both directions, and the per-kind phase walk is
 *      DERIVED from `PHASE_APPLICABILITY`, not hand-typed — so a phase added to, removed from,
 *      or re-scoped in the frozen contract reddens this suite instead of silently narrowing it.
 * 2. Three lifecycle boundaries state/event deliberately does not model as execution phases
 *      (lease release, backup/rotation, restart). Each carries its own spec citation, and
 *      `every phase citation resolves to a real spec section` asserts the cited section
 *      exists in the frozen section inventory of the cited specification.
 */

import { describe, expect, it } from "vitest";

import {
  HALTED,
  OperatorHaltError,
  RUNNING,
  assertPhaseAdmissible,
  createGatedAdmission,
  createGatedSigner,
  createGatedWorker,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  restoreHaltState,
  toggleHalt,
  type Admission,
  type DurablePhase,
  type HaltEvidenceRecorder,
  type HaltGate,
  type HaltState,
  type HaltStore,
  type Signer,
  type Worker,
} from "../src/operator/index.js";
import {
  HALT_TOGGLE_AUTH,
  OPERATOR_RECOVERY_ACTIONS,
  classifyRecoveryActionHalt,
  isHaltGatedOperationKind,
  isRecoveryActionAdmitted,
} from "../../generic-node-contracts/src/operator-halt/halt.contract.ts";
import {
  HALT_RACE_PHASES,
  HALT_RACE_TABLE,
  PHASE_APPLICABILITY,
  type HaltRaceAction,
  type HaltRacePhase,
} from "../../generic-node-contracts/src/operator-halt/races.contract.ts";
import {
  OPERATION_KINDS,
  type OperationKind,
} from "../../generic-node-contracts/src/operations/operations.contract.ts";

// ---------------------------------------------------------------------------
// The ten durable phases of the acceptance checklist.
// ---------------------------------------------------------------------------

/**
 * The ten checklist ids. Written out so every lookup keyed by a phase id is exhaustive at
 * compile time; `enumerates the ten checklist phases exactly once each` pins this union
 * against the catalogue's runtime contents and sequence.
 */
type PhaseId =
  | "before_baseline"
  | "after_baseline"
  | "preimage_persisted"
  | "signature_persisted"
  | "submit_claim_recorded"
  | "delivery"
  | "landing"
  | "release"
  | "backup_and_rotation"
  | "restart";

interface DurablePhaseSpec {
  /** Stable id used by the scenario matrix. */
  readonly id: PhaseId;
  /** The checklist term this entry realizes, verbatim from the acceptance criteria. */
  readonly checklistTerm: string;
  /** state/event execution phases this entry sits at, frozen freeze. */
  readonly racePhases: readonly HaltRacePhase[];
  /** Governing document under. */
  readonly doc: string;
  /** Section number asserted to exist in that document. */
  readonly section: string;
}

const HALT_DURABLE_PHASES: readonly DurablePhaseSpec[] = [
  {
    id: "before_baseline",
    checklistTerm: "before baseline",
    racePhases: ["NOT_STARTED"],
    doc: "the recovery rules",
    section: "2",
  },
  {
    id: "after_baseline",
    checklistTerm: "after baseline",
    racePhases: ["NOT_STARTED"],
    doc: "the recovery rules",
    section: "3.2",
  },
  {
    id: "preimage_persisted",
    checklistTerm: "preimage",
    racePhases: ["PREIMAGE_PERSISTED"],
    doc: "the recovery rules",
    section: "3.4",
  },
  {
    id: "signature_persisted",
    checklistTerm: "signature",
    racePhases: ["SIGNED_PERSISTED"],
    doc: "the recovery rules",
    section: "4.1",
  },
  {
    id: "submit_claim_recorded",
    checklistTerm: "submit",
    racePhases: ["SUBMIT_STARTED", "SUBMIT_RETURNED"],
    doc: "the recovery rules",
    section: "4.1",
  },
  {
    id: "delivery",
    checklistTerm: "delivery",
    racePhases: ["DELIVERED"],
    doc: "the recovery rules",
    section: "5.2",
  },
  {
    id: "landing",
    checklistTerm: "landing",
    racePhases: ["LANDED_VERIFIED"],
    doc: "the recovery rules",
    section: "6",
  },
  {
    id: "release",
    checklistTerm: "release",
    racePhases: [],
    doc: "node-core rules",
    section: "7.2",
  },
  {
    id: "backup_and_rotation",
    checklistTerm: "backup and rotation",
    racePhases: [],
    doc: "the recovery rules",
    section: "7.1",
  },
  {
    id: "restart",
    checklistTerm: "restart",
    racePhases: [],
    doc: "the recovery rules",
    section: "7",
  },
];

/**
 * `DurablePhase` is a coarse four-bucket admission model; state/event has seven
 * execution phases. This is the mapping between them, and it is not free-hand: `pre_sign` is
 * sole admission bucket and therefore covers exactly the phases at which no exact
 * preimage is durable yet. Once the exact preimage IS durable, axiom 3 ("exact preimage
 * precedes signing") makes that record the durable proof the first formation was already
 * admitted, and all say the same thing about it — "re-sign only that exact
 * preimage" — so it belongs in a permeable bucket, never behind the admission gate.
 * `agrees with frozen halt-race table at every phase` asserts this mapping against
 * `HALT_RACE_TABLE`, so the two contracts cannot silently drift apart.
 */
const HALT_GATE_PHASE_BY_DURABLE_PHASE: Readonly<Record<PhaseId, DurablePhase>> = {
  before_baseline: "pre_sign",
  after_baseline: "pre_sign",
  preimage_persisted: "post_sign",
  signature_persisted: "pre_submit",
  submit_claim_recorded: "post_submit",
  delivery: "post_submit",
  landing: "post_submit",
  release: "post_submit",
  backup_and_rotation: "post_submit",
  restart: "post_submit",
};

/** Per-kind phase walk, DERIVED from frozen `PHASE_APPLICABILITY`. */
const phasesForKind = (kind: OperationKind): readonly DurablePhaseSpec[] =>
  HALT_DURABLE_PHASES.filter(
    (phase) =>
      phase.racePhases.length === 0 ||
      phase.racePhases.some((racePhase) => PHASE_APPLICABILITY[kind].includes(racePhase)),
  );

const raceAction = (kind: OperationKind, racePhase: HaltRacePhase): HaltRaceAction => {
  const entry = HALT_RACE_TABLE.find(
    (row) => row.operationKind === kind && row.phaseAtEngage === racePhase,
  );
  if (entry === undefined) {
    throw new Error(`halt durable-phase suite: no frozen race row for ${kind}/${racePhase}`);
  }
  return entry.action;
};

/** Derived from the frozen per-kind applicability — never hand-typed per kind. */
const crossesSubmitBoundary = (kind: OperationKind): boolean =>
  PHASE_APPLICABILITY[kind].includes("SUBMIT_STARTED");

// ---------------------------------------------------------------------------
// Durable record, effect log, and the halt store.
// ---------------------------------------------------------------------------

/**
 * Only what axiom 3 requires to be durable before an irreversible boundary. Everything
 * here survives a restart; everything not here is volatile and is discarded by `restart()`.
 */
interface DurableRecord {
  lease: string | null;
  baselineT0: string | null;
  preimage: string | null;
  signature: string | null;
  submitClaim: { readonly attemptId: string; response: string | null } | null;
  transferCode: string | null;
  delivered: boolean;
  terminalObservation: string | null;
  landed: boolean;
  leaseReleased: boolean;
  backupDigest: string | null;
  signingKeyEpoch: number;
}

/** Every effect that must never happen twice, counted rather than trusted. */
interface EffectLog {
  t0Reads: number;
  preimageWrites: number;
  /** The exact bytes handed to the signer, one entry per call. */
  signerCalls: string[];
  /** One entry per submit call — the never-blind-retry rule: never a second entry for one attempt. */
  submitCalls: string[];
  reconcileReads: number;
  /** The exact bytes served to the recipient, one entry per serve. */
  deliveryServes: string[];
  observationReads: number;
  leaseAcquisitions: number;
  leaseReleases: number;
  backupWrites: number;
  keyRotations: number;
  admissionRefusals: number;
}

const emptyDurable = (): DurableRecord => ({
  lease: null,
  baselineT0: null,
  preimage: null,
  signature: null,
  submitClaim: null,
  transferCode: null,
  delivered: false,
  terminalObservation: null,
  landed: false,
  leaseReleased: false,
  backupDigest: null,
  signingKeyEpoch: 1,
});

const emptyLog = (): EffectLog => ({
  t0Reads: 0,
  preimageWrites: 0,
  signerCalls: [],
  submitCalls: [],
  reconcileReads: 0,
  deliveryServes: [],
  observationReads: 0,
  leaseAcquisitions: 0,
  leaseReleases: 0,
  backupWrites: 0,
  keyRotations: 0,
  admissionRefusals: 0,
});

class MemoryHaltStore implements HaltStore {
  private state: HaltState | null;
  /** Durable STATE writes only — not the audit trail. The trail is the evidence recorder. */
  readonly writes: HaltState[] = [];
  corrupt = false;

  constructor(initial: HaltState | null = RUNNING) {
    this.state = initial;
  }

  async read(): Promise<HaltState | null> {
    return this.corrupt ? null : this.state;
  }

  async write(state: HaltState): Promise<void> {
    this.writes.push(state);
    this.state = state;
  }
}

// ---------------------------------------------------------------------------
// The phase engine: one durable step per `advance()`, driven purely by the durable record.
// ---------------------------------------------------------------------------

/**
 * Deliberately has no halt-aware branches of its own beyond the single admission guard: the
 * whole point of is that halt is indistinguishable, from an in-flight operation's
 * point of view, from any other reason a new signing attempt did not start.
 */
class PhaseEngine {
  readonly kind: OperationKind;
  readonly store: MemoryHaltStore;
  readonly log: EffectLog;
  /** The durable audit trail: one row per engage/disengage attempt AND outcome. */
  readonly evidence: HaltEvidenceRecorder = createInMemoryHaltEvidenceRecorder();
  durable: DurableRecord;
  gate: HaltGate;

  constructor(
    kind: OperationKind,
    store: MemoryHaltStore,
    durable: DurableRecord = emptyDurable(),
    log: EffectLog = emptyLog(),
    gate: HaltGate = createHaltGate(RUNNING),
  ) {
    this.kind = kind;
    this.store = store;
    this.durable = durable;
    this.log = log;
    this.gate = gate;
  }

  /** The state/event execution phase the durable record currently sits at. */
  racePhase(): HaltRacePhase {
    if (this.durable.landed) {
      return "LANDED_VERIFIED";
    }
    if (this.durable.submitClaim !== null) {
      return this.durable.submitClaim.response === null ? "SUBMIT_STARTED" : "SUBMIT_RETURNED";
    }
    if (this.durable.delivered) {
      return "DELIVERED";
    }
    if (this.durable.signature !== null) {
      return "SIGNED_PERSISTED";
    }
    if (this.durable.preimage !== null) {
      return "PREIMAGE_PERSISTED";
    }
    return "NOT_STARTED";
  }

  /** The checklist phase the durable record currently sits at. */
  phase(): PhaseId {
    if (this.durable.lease === null) {
      return "before_baseline";
    }
    if (this.durable.preimage === null) {
      return "after_baseline";
    }
    if (this.durable.signature === null) {
      return "preimage_persisted";
    }
    if (crossesSubmitBoundary(this.kind)) {
      if (this.durable.submitClaim === null) {
        return "signature_persisted";
      }
      if (this.durable.terminalObservation === null) {
        return "submit_claim_recorded";
      }
    } else {
      if (!this.durable.delivered) {
        return "signature_persisted";
      }
      if (this.durable.terminalObservation === null) {
        return "delivery";
      }
    }
    if (!this.durable.landed) {
      return "landing";
    }
    if (!this.durable.leaseReleased) {
      return "release";
    }
    if (this.durable.backupDigest === null) {
      return "backup_and_rotation";
    }
    return "restart";
  }

  /**
   * The one halt consultation in the engine. Routed through explicit phase guard so
   * the gate wrapper — not a private copy of its rule — decides.
   */
  private blockedFromStarting(): boolean {
    try {
      assertPhaseAdmissible(this.gate, HALT_GATE_PHASE_BY_DURABLE_PHASE[this.phase()]);
      return false;
    } catch (error) {
      if (error instanceof OperatorHaltError) {
        return true;
      }
      throw error;
    }
  }

  /** One durable step. Returns false when the record can advance no further right now. */
  async advance(): Promise<boolean> {
    const d = this.durable;

    // NOT_STARTED, no lease: admission + baseline capture. first row.
    if (d.lease === null) {
      if (isHaltGatedOperationKind(this.kind) && this.blockedFromStarting()) {
        this.log.admissionRefusals += 1;
        return false;
      }
      d.lease = `lease:${this.kind}`;
      this.log.leaseAcquisitions += 1;
      //: "Lease exists; no T0... resume the original T0/code formation". T0 is captured
      // once and is never re-read on resume — forbids re-forming from a fresh head.
      d.baselineT0 = `T0:${this.kind}`;
      this.log.t0Reads += 1;
      return true;
    }

    // NOT_STARTED, lease and T0 durable, no preimage: the first formation itself.
    if (d.preimage === null) {
      if (isHaltGatedOperationKind(this.kind) && this.blockedFromStarting()) {
        this.log.admissionRefusals += 1;
        return false;
      }
      d.preimage = JSON.stringify({ kind: this.kind, baseline: d.baselineT0, attempt: 1 });
      this.log.preimageWrites += 1;
      return true;
    }

    // PREIMAGE_PERSISTED: — re-sign ONLY the identical persisted preimage.
    if (d.signature === null) {
      d.signature = `sig(${d.preimage})`;
      this.log.signerCalls.push(d.preimage);
      return true;
    }

    if (crossesSubmitBoundary(this.kind)) {
      // SIGNED_PERSISTED, no submit claim: — "submit that exact attempt once".
      if (d.submitClaim === null) {
        const attemptId = `attempt:${this.kind}:1`;
        d.submitClaim = { attemptId, response: null };
        this.log.submitCalls.push(attemptId);
        return true;
      }
      // SUBMIT_STARTED: — "Never submit again. Reconcile by... observation."
      if (d.submitClaim.response === null) {
        d.submitClaim.response = `response:${d.submitClaim.attemptId}`;
        this.log.reconcileReads += 1;
        return true;
      }
    } else if (!d.delivered) {
      // SIGNED_PERSISTED for the send kind: form the partial once, then serve it.
      d.transferCode = `partial(${d.signature})`;
      d.delivered = true;
      this.log.deliveryServes.push(d.transferCode);
      return true;
    }

    // axiom 3: terminal observation precedes landed state — two durable writes, so a halt
    // can land between the proof of landing and the recording of it.
    if (d.terminalObservation === null) {
      d.terminalObservation = `observed(${d.signature})`;
      this.log.observationReads += 1;
      return true;
    }
    if (!d.landed) {
      d.landed = true;
      return true;
    }

    // The verification-complete barrier releases the lease. Not signing.
    if (!d.leaseReleased) {
      d.leaseReleased = true;
      this.log.leaseReleases += 1;
      return true;
    }

    // continuity: backup and key rotation are read/write custody work, never signing.
    if (d.backupDigest === null) {
      d.backupDigest = `backup(${d.signature ?? ""}|${d.terminalObservation})`;
      this.log.backupWrites += 1;
      d.signingKeyEpoch += 1;
      this.log.keyRotations += 1;
      return true;
    }

    return false;
  }

  /** Advance until the durable record stops moving. */
  async drive(): Promise<void> {
    let guard = 0;
    while (await this.advance()) {
      guard += 1;
      if (guard > 32) {
        throw new Error("halt durable-phase suite: engine failed to reach quiescence");
      }
    }
  }

  /** Advance until the named phase is reached, then stop. */
  async driveTo(target: PhaseId): Promise<void> {
    let guard = 0;
    while (this.phase() !== target) {
      if (!(await this.advance())) {
        throw new Error(
          `halt durable-phase suite: stalled at ${this.phase()} before reaching ${target}`,
        );
      }
      guard += 1;
      if (guard > 32) {
        throw new Error(`halt durable-phase suite: never reached ${target}`);
      }
    }
  }

  /**
   * `REDELIVER_EXACT_PARTIAL`: re-serving the identical persisted bytes forms no
   * new signature and is never gated, halted or not.
   */
  serveExistingPartial(): string {
    if (this.durable.transferCode === null) {
      throw new Error("halt durable-phase suite: no persisted partial to re-serve");
    }
    this.log.deliveryServes.push(this.durable.transferCode);
    return this.durable.transferCode;
  }

  async engage(): Promise<HaltState> {
    return await toggleHalt(this.store, this.gate, this.evidence, { actor: "operator" });
  }

  async disengage(): Promise<HaltState> {
    return await toggleHalt(this.store, this.gate, this.evidence, { actor: "operator" });
  }

  /**
   * boot recovery. Volatile state is lost; the durable record survives a JSON round-trip;
   * the live gate is rebuilt from the durable halt record by fail-closed restore
   * BEFORE any money engine starts.
   */
  async restart(): Promise<HaltState> {
    this.durable = JSON.parse(JSON.stringify(this.durable)) as DurableRecord;
    this.gate = createHaltGate(HALTED);
    return await restoreHaltState(this.store, this.gate, { sleep: async () => {} });
  }

  snapshot(): DurableRecord {
    return JSON.parse(JSON.stringify(this.durable)) as DurableRecord;
  }
}

// ---------------------------------------------------------------------------
// 1. Phase enumeration is anchored outside this file.
// ---------------------------------------------------------------------------

// Frozen section inventory of the two cited recovery/node-core specifications: every
// section number that exists in each. A phase citation must land on one of these, so a
// citation edited to a nonexistent section still fails. Regenerate only when the cited
// specifications themselves change.
const SPEC_SECTIONS: Readonly<Record<string, readonly string[]>> = {
  "the recovery rules": [
    "1", "2", "3", "3.1", "3.2", "3.3", "3.4", "3.5", "4", "4.1", "4.2", "4.3",
    "5", "5.1", "5.2", "5.3", "5.4", "6", "7", "7.1", "8", "8.1", "8.2",
    "9", "9.1", "9.2", "9.3", "10", "11", "12", "12.1", "12.2", "12.3", "12.4",
    "12.5", "12.5.1", "12.5.2", "12.5.3", "12.5.4", "12.5.5", "12.6", "12.7",
  ],
  "node-core rules": [
    "1", "2", "2.1", "2.2", "2.3", "2.4", "3", "4", "5", "6", "7", "7.1", "7.2",
    "8", "9", "10",
  ],
};

describe("durable-phase catalogue", () => {
  it("covers every frozen state/event execution phase, count-exact both ways", () => {
    const anchored = HALT_DURABLE_PHASES.filter((phase) => phase.racePhases.length > 0);
    // Seven checklist phases sit at an state/event execution phase; three are lifecycle
    // boundaries deliberately does not model.
    expect(anchored.length).toBe(7);
    expect(HALT_DURABLE_PHASES.length - anchored.length).toBe(3);

    const claimed = anchored.flatMap((phase) => [...phase.racePhases]);
    // Both directions: no frozen phase unclaimed, no claimed phase outside the frozen set.
    expect([...new Set(claimed)].sort()).toEqual([...HALT_RACE_PHASES].sort());

    // `NOT_STARTED` is the one frozen phase the checklist deliberately splits in two
    // (before baseline / after baseline); every other frozen phase is claimed exactly once.
    const counts = new Map<HaltRacePhase, number>();
    for (const racePhase of claimed) {
      counts.set(racePhase, (counts.get(racePhase) ?? 0) + 1);
    }
    expect([...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name)).toEqual([
      "NOT_STARTED",
    ]);
  });

  it("every phase citation resolves to a real spec section", () => {
    for (const phase of HALT_DURABLE_PHASES) {
      const sections = SPEC_SECTIONS[phase.doc];
      expect(
        { phase: phase.id, found: sections !== undefined && sections.includes(phase.section) },
        `${phase.doc} has no section ${phase.section}`,
      ).toEqual({ phase: phase.id, found: true });
    }
  });

  it("enumerates the ten checklist phases exactly once each", () => {
    expect(HALT_DURABLE_PHASES.map((phase) => phase.id)).toEqual([
      "before_baseline",
      "after_baseline",
      "preimage_persisted",
      "signature_persisted",
      "submit_claim_recorded",
      "delivery",
      "landing",
      "release",
      "backup_and_rotation",
      "restart",
    ]);
    expect(new Set(HALT_DURABLE_PHASES.map((phase) => phase.checklistTerm)).size).toBe(10);
  });

  it("derives the per-kind phase walk from the frozen applicability table", () => {
    for (const kind of OPERATION_KINDS) {
      const walk = phasesForKind(kind).map((phase) => phase.id);
      // Every applicable frozen race phase is walked; every inapplicable one is skipped.
      for (const racePhase of HALT_RACE_PHASES) {
        const owner = HALT_DURABLE_PHASES.filter((phase) =>
          phase.racePhases.includes(racePhase),
        ).map((phase) => phase.id);
        const applicable = PHASE_APPLICABILITY[kind].includes(racePhase);
        expect({ kind, racePhase, walked: owner.some((id) => walk.includes(id)) }).toEqual({
          kind,
          racePhase,
          walked: applicable,
        });
      }
      // The three non-execution lifecycle phases apply to every kind.
      expect(walk).toContain("release");
      expect(walk).toContain("backup_and_rotation");
      expect(walk).toContain("restart");
    }
  });

  it("agrees with frozen halt-race table at every phase", () => {
    const gate = createHaltGate(HALTED);
    for (const kind of OPERATION_KINDS) {
      for (const phase of phasesForKind(kind)) {
        for (const racePhase of phase.racePhases) {
          const bucket = HALT_GATE_PHASE_BY_DURABLE_PHASE[phase.id];
          let bucketRefuses = false;
          try {
            assertPhaseAdmissible(gate, bucket);
          } catch {
            bucketRefuses = true;
          }
          // The live guard is the composition phase bucket applies with
          // operation-kind scope — `assertPhaseAdmissible` is deliberately kind-agnostic, so
          // the exempt kind's exemption comes from `isHaltGatedOperationKind`, not from it.
          const refused = bucketRefuses && isHaltGatedOperationKind(kind);
          const expected = raceAction(kind, racePhase) === "BLOCKED_FROM_STARTING";
          expect({ kind, phase: phase.id, racePhase, refused }).toEqual({
            kind,
            phase: phase.id,
            racePhase,
            refused: expected,
          });
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 2. The scenario matrix: engage at every durable phase, for every operation kind.
// ---------------------------------------------------------------------------

/** Assertions that must hold at the end of EVERY scenario, whatever the engage phase. */
const assertNoRepeatsAndNoDiscards = (engine: PhaseEngine, before: DurableRecord): void => {
  const { durable, log } = engine;

  // The operation completed: halt delayed it, never dropped it.
  expect(durable.landed).toBe(true);
  expect(durable.leaseReleased).toBe(true);
  expect(durable.backupDigest).not.toBeNull();

  // Nothing already-completed was repeated.: T0 is captured once and never re-read.
  expect(log.t0Reads).toBe(1);
  expect(log.leaseAcquisitions).toBe(1);
  expect(log.preimageWrites).toBe(1);
  expect(log.leaseReleases).toBe(1);
  expect(log.backupWrites).toBe(1);
  expect(log.keyRotations).toBe(1);

  // No second signature, ever, and only over the identical persisted preimage
  // ("produce a second step-1 signature over different bytes" is
  // a forbidden action).
  expect(log.signerCalls).toEqual([durable.preimage]);
  expect(durable.signature).toBe(`sig(${durable.preimage ?? ""})`);

  // The never-blind-retry rule /: one submit call for one attempt, never a second.
  if (crossesSubmitBoundary(engine.kind)) {
    expect(log.submitCalls).toEqual([durable.submitClaim?.attemptId]);
  } else {
    expect(log.submitCalls).toEqual([]);
    // final row: only identical persisted transfer-code bytes are ever served.
    expect(new Set(log.deliveryServes).size).toBe(1);
    expect(log.deliveryServes[0]).toBe(durable.transferCode);
  }

  // Byte-exactness across the halt: every artifact durable BEFORE the halt is unchanged.
  for (const field of ["baselineT0", "preimage", "signature", "transferCode"] as const) {
    if (before[field] !== null) {
      expect({ field, value: durable[field] }).toEqual({ field, value: before[field] });
    }
  }
  if (before.submitClaim !== null) {
    expect(durable.submitClaim?.attemptId).toBe(before.submitClaim.attemptId);
  }
};

describe.each(OPERATION_KINDS)("halt at every durable phase — %s", (kind) => {
  const gated = isHaltGatedOperationKind(kind);

  describe.each(phasesForKind(kind).map((phase) => [phase.id, phase] as const))(
    "engage at %s",
    (_id, phase) => {
      it("makes no unsafe progress while halted and leaves no partial durable state", async () => {
        const engine = new PhaseEngine(kind, new MemoryHaltStore());
        await engine.driveTo(phase.id);
        const before = engine.snapshot();
        const signerCallsBefore = engine.log.signerCalls.length;
        const submitCallsBefore = engine.log.submitCalls.length;

        expect(await engine.engage()).toBe(HALTED);
        await engine.drive();

        if (phase.id === "before_baseline" && gated) {
          // Nothing durable exists to resume, and nothing was created under halt.
          expect(engine.durable).toEqual(emptyDurable());
          expect(engine.log.admissionRefusals).toBeGreaterThan(0);
          expect(engine.log.signerCalls).toEqual([]);
        } else if (phase.id === "after_baseline" && gated) {
          // The lease and T0 survive untouched; the first formation does not start.
          expect(engine.durable.lease).toBe(before.lease);
          expect(engine.durable.baselineT0).toBe(before.baselineT0);
          expect(engine.durable.preimage).toBeNull();
          expect(engine.log.t0Reads).toBe(1);
          expect(engine.log.signerCalls).toEqual([]);
        } else {
          // Every later phase is COMPLETES_NO_ABORT: the in-flight attempt finishes.
          expect(engine.durable.landed).toBe(true);
          expect(engine.durable.leaseReleased).toBe(true);
        }

        // Never, at any phase, a second signature or a second submit under halt.
        expect(engine.log.signerCalls.length).toBeLessThanOrEqual(signerCallsBefore + 1);
        expect(engine.log.submitCalls.length).toBeLessThanOrEqual(submitCallsBefore + 1);

        // Restart while halted stays halted (fail-closed restore), and the durable
        // record is unchanged by the restart itself.
        const acrossRestart = engine.snapshot();
        expect(await engine.restart()).toBe(HALTED);
        expect(engine.durable).toEqual(acrossRestart);
      });

      it("resumes on disengage without repeating any completed action", async () => {
        const engine = new PhaseEngine(kind, new MemoryHaltStore());
        await engine.driveTo(phase.id);
        const before = engine.snapshot();

        expect(await engine.engage()).toBe(HALTED);
        await engine.drive();
        expect(await engine.disengage()).toBe(RUNNING);
        await engine.drive();

        assertNoRepeatsAndNoDiscards(engine, before);

        // Engage and disengage are equally gated and both are durably audited.
        expect(HALT_TOGGLE_AUTH.engage).toBe(HALT_TOGGLE_AUTH.disengage);
        expect(engine.store.writes).toEqual([HALTED, RUNNING]);
      });

      it("survives a restart taken while halted at this phase", async () => {
        const engine = new PhaseEngine(kind, new MemoryHaltStore());
        await engine.driveTo(phase.id);
        const before = engine.snapshot();

        await engine.engage();
        expect(await engine.restart()).toBe(HALTED);
        // boot recovery classifies and resumes only what the durable record authorizes.
        await engine.drive();
        await engine.disengage();
        await engine.drive();

        assertNoRepeatsAndNoDiscards(engine, before);
      });

      it("fails closed and still resumes when the halt record is unreadable at restart", async () => {
        const engine = new PhaseEngine(kind, new MemoryHaltStore());
        await engine.driveTo(phase.id);
        const before = engine.snapshot();

        engine.store.corrupt = true;
        expect(await engine.restart()).toBe(HALTED);
        await engine.drive();

        // A corrupt setting halts the node; it never discards an existing signed attempt.
        if (before.signature !== null) {
          expect(engine.durable.signature).toBe(before.signature);
          expect(engine.durable.landed).toBe(true);
        }

        // The durable record still says RUNNING — the halt came from unreadability, not from
        // an operator engage — so a readable restart, not a toggle, is what un-pauses it.
        engine.store.corrupt = false;
        expect(await engine.restart()).toBe(RUNNING);
        await engine.drive();
        assertNoRepeatsAndNoDiscards(engine, before);
      });
    },
  );

  it("matches the frozen race action at every applicable execution phase", async () => {
    const reached = new Set<HaltRacePhase>();
    for (const phase of phasesForKind(kind)) {
      const engine = new PhaseEngine(kind, new MemoryHaltStore());
      await engine.driveTo(phase.id);

      // The execution phase the engine is genuinely at — read from the durable record, not
      // asserted from the catalogue, so the frozen table is the oracle and not this file.
      const racePhase = engine.racePhase();
      reached.add(racePhase);
      if (phase.id === "restart") {
        // Terminal: the operation is already complete, so "made no progress" no longer
        // distinguishes a refusal from having nothing left to do.
        continue;
      }
      const before = engine.snapshot();
      await engine.engage();
      await engine.drive();

      const progressed = JSON.stringify(engine.durable) !== JSON.stringify(before);
      expect({ kind, phase: phase.id, racePhase, blocked: !progressed }).toEqual({
        kind,
        phase: phase.id,
        racePhase,
        blocked: raceAction(kind, racePhase) === "BLOCKED_FROM_STARTING",
      });
    }
    // Every execution phase the frozen table scopes to this kind was actually visited, so a
    // phase can never be silently skipped by the walk above.
    expect([...reached].sort()).toEqual([...PHASE_APPLICABILITY[kind]].sort());
  });
});

// ---------------------------------------------------------------------------
// 3. Per-checklist-phase specifics the matrix above cannot express generically.
// ---------------------------------------------------------------------------

describe("per-phase obligations", () => {
  it("never re-reads T0 when formation resumes after a halt (checklist 2)", async () => {
    for (const kind of OPERATION_KINDS) {
      const engine = new PhaseEngine(kind, new MemoryHaltStore());
      await engine.driveTo("after_baseline");
      const baseline = engine.durable.baselineT0;
      await engine.engage();
      await engine.drive();
      await engine.disengage();
      await engine.drive();
      expect({ kind, t0Reads: engine.log.t0Reads, baseline: engine.durable.baselineT0 }).toEqual({
        kind,
        t0Reads: 1,
        baseline,
      });
      // The preimage was formed from the pre-halt T0, not a fresh head.
      expect(engine.durable.preimage).toContain(baseline ?? "");
    }
  });

  it("signs only the identical persisted preimage after a halt at PREIMAGE_PERSISTED (checklist 3)", async () => {
    for (const kind of OPERATION_KINDS) {
      const engine = new PhaseEngine(kind, new MemoryHaltStore());
      await engine.driveTo("preimage_persisted");
      const preimage = engine.durable.preimage;
      await engine.engage();
      await engine.drive();
      await engine.disengage();
      await engine.drive();
      expect({ kind, calls: engine.log.signerCalls, writes: engine.log.preimageWrites }).toEqual({
        kind,
        calls: [preimage],
        writes: 1,
      });
    }
  });

  it("routing a persisted-preimage re-sign through the pre-sign admission seam would discard the attempt", async () => {
    // Negative path for the HALT_GATE_PHASE_BY_DURABLE_PHASE mapping: if `preimage_persisted`
    // were bucketed as `pre_sign`, the existing durable attempt could never be signed while
    // halted — the exact outcome exit criterion forbids.
    const gate = createHaltGate(HALTED);
    expect(() => {
      assertPhaseAdmissible(gate, "pre_sign");
    }).toThrow(OperatorHaltError);
    expect(() => {
      assertPhaseAdmissible(gate, HALT_GATE_PHASE_BY_DURABLE_PHASE.preimage_persisted);
    }).not.toThrow();
  });

  it("submits the exact attempt once and never twice across a halt (checklist 4 and 5)", async () => {
    for (const kind of OPERATION_KINDS.filter(crossesSubmitBoundary)) {
      const atSignature = new PhaseEngine(kind, new MemoryHaltStore());
      await atSignature.driveTo("signature_persisted");
      await atSignature.engage();
      await atSignature.drive();
      await atSignature.disengage();
      await atSignature.drive();
      expect({ kind, calls: atSignature.log.submitCalls.length }).toEqual({ kind, calls: 1 });

      const atSubmitClaim = new PhaseEngine(kind, new MemoryHaltStore());
      await atSubmitClaim.driveTo("submit_claim_recorded");
      const claimedAttempt = atSubmitClaim.durable.submitClaim?.attemptId;
      await atSubmitClaim.engage();
      await atSubmitClaim.drive();
      await atSubmitClaim.disengage();
      await atSubmitClaim.drive();
      // never submit again; the outcome comes from reconciliation.
      expect({
        kind,
        calls: atSubmitClaim.log.submitCalls,
        reconciled: atSubmitClaim.log.reconcileReads > 0,
      }).toEqual({ kind, calls: [claimedAttempt], reconciled: true });
    }
  });

  it("receive has no rebuild path: a halt never produces a second preimage (checklist 5, recovery)", async () => {
    for (const phase of phasesForKind("RECEIVE_EXTERNAL")) {
      const engine = new PhaseEngine("RECEIVE_EXTERNAL", new MemoryHaltStore());
      await engine.driveTo(phase.id);
      const preimage = engine.durable.preimage;
      await engine.engage();
      await engine.drive();
      await engine.restart();
      await engine.drive();
      await engine.disengage();
      await engine.drive();
      expect({ phase: phase.id, writes: engine.log.preimageWrites }).toEqual({
        phase: phase.id,
        writes: 1,
      });
      if (preimage !== null) {
        expect(engine.durable.preimage).toBe(preimage);
      }
    }
  });

  it("re-serves the identical persisted partial while halted (checklist 6)", async () => {
    const engine = new PhaseEngine("SEND_EXTERNAL", new MemoryHaltStore());
    await engine.driveTo("delivery");
    const persisted = engine.durable.transferCode;
    await engine.engage();
    // REDELIVER_EXACT_PARTIAL is HALT_NEVER_GATED — it forms no new signature.
    expect(engine.serveExistingPartial()).toBe(persisted);
    expect(engine.serveExistingPartial()).toBe(persisted);
    expect(new Set(engine.log.deliveryServes).size).toBe(1);
    expect(engine.log.signerCalls.length).toBe(1);
  });

  it("never discards a proof of landing captured before the halt (checklist 7)", async () => {
    for (const kind of OPERATION_KINDS) {
      const engine = new PhaseEngine(kind, new MemoryHaltStore());
      await engine.driveTo("landing");
      const observation = engine.durable.terminalObservation;
      expect(engine.durable.landed).toBe(false);
      await engine.engage();
      await engine.drive();
      expect({ kind, observation: engine.durable.terminalObservation, landed: engine.durable.landed }).toEqual(
        { kind, observation, landed: true },
      );
      expect(engine.log.observationReads).toBe(1);
    }
  });

  it("releases the lease under halt exactly as without it (checklist 8)", async () => {
    for (const kind of OPERATION_KINDS) {
      const halted = new PhaseEngine(kind, new MemoryHaltStore());
      await halted.driveTo("release");
      await halted.engage();
      await halted.drive();

      const running = new PhaseEngine(kind, new MemoryHaltStore());
      await running.driveTo("release");
      await running.drive();

      expect(halted.durable).toEqual(running.durable);
      expect(halted.log.leaseReleases).toBe(running.log.leaseReleases);
    }
  });

  it("takes an identical backup and key rotation under halt (checklist 9)", async () => {
    for (const kind of OPERATION_KINDS) {
      const halted = new PhaseEngine(kind, new MemoryHaltStore());
      await halted.driveTo("backup_and_rotation");
      await halted.engage();
      await halted.drive();

      const running = new PhaseEngine(kind, new MemoryHaltStore());
      await running.driveTo("backup_and_rotation");
      await running.drive();

      expect(halted.durable.backupDigest).toBe(running.durable.backupDigest);
      expect(halted.durable.signingKeyEpoch).toBe(running.durable.signingKeyEpoch);
      expect(halted.log.keyRotations).toBe(1);
    }
  });

  it("keeps halt engaged across restart and still resumes the durable phase (checklist 10)", async () => {
    for (const kind of OPERATION_KINDS) {
      for (const phase of phasesForKind(kind)) {
        const engine = new PhaseEngine(kind, new MemoryHaltStore());
        await engine.driveTo(phase.id);
        await engine.engage();
        expect({ kind, phase: phase.id, state: await engine.restart() }).toEqual({
          kind,
          phase: phase.id,
          state: HALTED,
        });
        // A second restart is still halted: the durable record, not the live gate, decides.
        expect(await engine.restart()).toBe(HALTED);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 4. The admission seams, and the operator surface, under halt.
// ---------------------------------------------------------------------------

describe("admission seams under halt", () => {
  it("mid-worker: an already-claimed tick completes before halt takes the next claim", async () => {
    const gate = createHaltGate(RUNNING);
    const processed: number[] = [];
    let claimCalls = 0;
    const delegate: Worker<number, number> = {
      claim: async () => {
        claimCalls += 1;
        return claimCalls <= 2 ? claimCalls : null;
      },
      process: async (claim) => {
        processed.push(claim);
        return claim;
      },
    };
    const worker = createGatedWorker(gate, delegate);

    const claimed = await worker.claim();
    expect(claimed).toBe(1);
    gate.engage();
    // The claimed tick finishes — "an already-claimed tick completes, no abort".
    await worker.process(claimed ?? 0);
    expect(processed).toEqual([1]);
    // The next claim is refused without reaching the delegate at all.
    expect(await worker.claim()).toBeNull();
    expect(claimCalls).toBe(1);
    gate.release();
    expect(await worker.claim()).toBe(2);
  });

  it("no-new-signature: the gated signer never reaches the delegate while halted", async () => {
    const gate = createHaltGate(HALTED);
    let calls = 0;
    const signer: Signer<string, string> = {
      sign: async (request) => {
        calls += 1;
        return `sig:${request}`;
      },
    };
    await expect(createGatedSigner(gate, signer).sign("preimage")).rejects.toBeInstanceOf(
      OperatorHaltError,
    );
    expect(calls).toBe(0);
  });

  it("no new operation is admitted while halted", async () => {
    const gate = createHaltGate(HALTED);
    let admitted = 0;
    const admission: Admission<string, string> = {
      admit: async (request) => {
        admitted += 1;
        return request;
      },
    };
    const gatedAdmission = createGatedAdmission(gate, admission);
    await expect(gatedAdmission.admit("op")).rejects.toBeInstanceOf(OperatorHaltError);
    expect(admitted).toBe(0);
    gate.release();
    expect(await gatedAdmission.admit("op")).toBe("op");
    expect(admitted).toBe(1);
  });

  it("admits every non-signing recovery action while halted and refuses the re-authorizations", () => {
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      const gatedAction = classifyRecoveryActionHalt(action) === "HALT_GATED";
      expect({ action, admitted: isRecoveryActionAdmitted(action, true) }).toEqual({
        action,
        admitted: !gatedAction,
      });
      // Nothing is refused on a running node.
      expect(isRecoveryActionAdmitted(action, false)).toBe(true);
    }
    // The named breaking input: rebuilding an internal move is a NEW first formation.
    expect(isRecoveryActionAdmitted("REBUILD_INTERNAL_MOVE", true)).toBe(false);
  });

  it("audits engage and disengage identically and durably", async () => {
    const store = new MemoryHaltStore();
    const gate = createHaltGate(RUNNING);
    const evidence = createInMemoryHaltEvidenceRecorder();
    const request = { actor: "operator-7", now: () => 1_700_000_000_000 };

    expect(await toggleHalt(store, gate, evidence, request)).toBe(HALTED);
    expect(gate.isHalted()).toBe(true);
    expect(await toggleHalt(store, gate, evidence, request)).toBe(RUNNING);
    expect(gate.isHalted()).toBe(false);
    expect(store.writes).toEqual([HALTED, RUNNING]);

    // AUDITED, not merely persisted: one row per direction, carrying the same field set
    // and the same actor. `store.writes` above proves persist-before-flip; only these
    // rows prove the toggles were recorded at all.
    expect(await evidence.entries()).toEqual([
      {
        action: "ENGAGE",
        outcome: "APPLIED",
        reason: "operator halt engaged",
        actor: "operator-7",
        at: 1_700_000_000_000,
      },
      {
        action: "DISENGAGE",
        outcome: "APPLIED",
        reason: "operator halt disengaged",
        actor: "operator-7",
        at: 1_700_000_000_000,
      },
    ]);

    expect(HALT_TOGGLE_AUTH.engage).toBe(HALT_TOGGLE_AUTH.disengage);
    expect(HALT_TOGGLE_AUTH.engage).toBe("operator_session_totp");
  });
});
