/**
 * Follow-up — the durable audit trail for operator-halt engage/disengage.
 *
 * Governing spec: ("every toggle writes an `admin.halt.engaged`/
 * `admin.halt.disengaged` audit_log row"; persistence is ONE durable record, no schema
 * migration) and implementation checklist item 5: "an `audit_log`-
 * equivalent row for every engage/disengage attempt AND outcome — including failed/rejected
 * attempts, not just successful toggles", over "a versioned record of
 * `{engaged, reason, actor, time}`".
 *
 * The distinction this suite exists to hold: `store.writes` proves the durable STATE was
 * persisted before the live gate flipped. It proves nothing about auditing. Every assertion
 * below that claims a row was audited reads it back off the RECORDER.
 */
import { describe, expect, it } from "vitest";

import {
  HALT_EVIDENCE_MAX_RECORDS,
  HaltEvidenceCorruptError,
  HaltToggleRejectedError,
  OperatorHaltError,
  createDurableHaltEvidenceRecorder,
  createGatedAdmission,
  createGatedSigner,
  createGatedWorker,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  disengageHalt,
  engageHalt,
  restoreHaltState,
  toggleHalt,
  type Admission,
  type HaltEvidenceRecord,
  type HaltEvidenceRecorder,
  type HaltEvidenceStore,
  type HaltState,
  type HaltStore,
  type Signer,
  type Worker,
} from "../src/operator/index.js";

const NO_SLEEP = async (): Promise<void> => {};

class MemoryHaltStore implements HaltStore {
  private state: HaltState | null;
  /** Durable STATE writes only — NOT the audit trail. */
  readonly writes: HaltState[] = [];

  constructor(initial: HaltState | null = null) {
    this.state = initial;
  }

  async read(): Promise<HaltState | null> {
    return this.state;
  }

  async write(state: HaltState): Promise<void> {
    this.writes.push(state);
    this.state = state;
  }
}

/** Stands in for single durable settings KV record. */
class MemoryEvidenceStore implements HaltEvidenceStore {
  value: string | null;
  readonly writes: string[] = [];

  constructor(initial: string | null = null) {
    this.value = initial;
  }

  async read(): Promise<string | null> {
    return this.value;
  }

  async write(value: string): Promise<void> {
    this.writes.push(value);
    this.value = value;
  }
}

class RecordingSigner implements Signer<string, string> {
  calls = 0;
  async sign(request: string): Promise<string> {
    this.calls += 1;
    return `sig:${request}`;
  }
}

class RecordingWorker implements Worker<number, number> {
  claims: number[];
  processed: number[] = [];
  claimCalls = 0;

  constructor(claims: number[]) {
    this.claims = claims;
  }

  async claim(): Promise<number | null> {
    this.claimCalls += 1;
    const next = this.claims.shift();
    return next === undefined ? null : next;
  }

  async process(claim: number): Promise<number> {
    this.processed.push(claim);
    return claim * 2;
  }
}

class RecordingAdmission implements Admission<string, string> {
  calls = 0;
  async admit(request: string): Promise<string> {
    this.calls += 1;
    return `op:${request}`;
  }
}

const FIXED_NOW = () => 1_700_000_000_000;
const OPERATOR = { actor: "operator-7", now: FIXED_NOW };

const outcomes = (records: readonly HaltEvidenceRecord[]): string[] =>
  records.map((entry) => `${entry.action}:${entry.outcome}`);

describe("operator halt evidence", () => {
  describe("a row for every ATTEMPT and OUTCOME", () => {
    it("records an APPLIED ENGAGE row carrying action, outcome, reason, actor and time", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      const state = await engageHalt(store, gate, recorder, {
        ...OPERATOR,
        reason: "investigating discrepancy",
      });

      expect(state).toBe("HALTED");
      expect(gate.isHalted()).toBe(true);
      expect(await recorder.entries()).toEqual([
        {
          action: "ENGAGE",
          outcome: "APPLIED",
          reason: "investigating discrepancy",
          actor: "operator-7",
          at: 1_700_000_000_000,
        },
      ]);
    });

    it("records an APPLIED DISENGAGE row with the identical field set", async () => {
      const store = new MemoryHaltStore("HALTED");
      const gate = createHaltGate("HALTED");
      const recorder = createInMemoryHaltEvidenceRecorder();

      const state = await disengageHalt(store, gate, recorder, {
        ...OPERATOR,
        reason: "resolved",
      });

      expect(state).toBe("RUNNING");
      expect(gate.isHalted()).toBe(false);
      expect(await recorder.entries()).toEqual([
        {
          action: "DISENGAGE",
          outcome: "APPLIED",
          reason: "resolved",
          actor: "operator-7",
          at: 1_700_000_000_000,
        },
      ]);
    });

    it("records a NO_OP row for a repeat engage — the attempt is audited, the state is not", async () => {
      const store = new MemoryHaltStore("HALTED");
      const gate = createHaltGate("HALTED");
      const recorder = createInMemoryHaltEvidenceRecorder();

      const state = await engageHalt(store, gate, recorder, OPERATOR);

      expect(state).toBe("HALTED");
      expect(gate.isHalted()).toBe(true);
      // no double-counted STATE ...
      expect(store.writes).toEqual([]);
      // ... but the attempt is on the record, with the outcome that says so.
      expect(await recorder.entries()).toEqual([
        {
          action: "ENGAGE",
          outcome: "NO_OP",
          reason: "operator halt engaged",
          actor: "operator-7",
          at: 1_700_000_000_000,
        },
      ]);
    });

    it("records a NO_OP row for a repeat disengage (symmetric with engage)", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      const state = await disengageHalt(store, gate, recorder, OPERATOR);

      expect(state).toBe("RUNNING");
      expect(store.writes).toEqual([]);
      expect(outcomes(await recorder.entries())).toEqual(["DISENGAGE:NO_OP"]);
    });

    it("records a REJECTED row when the caller's authorization refuses the engage", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await expect(
        engageHalt(store, gate, recorder, {
          ...OPERATOR,
          reason: "stale totp",
          authorize: () => false,
        }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError);

      // neither the durable state nor the live gate moved ...
      expect(store.writes).toEqual([]);
      expect(gate.isHalted()).toBe(false);
      // ... and the refused attempt is still on the record.
      expect(await recorder.entries()).toEqual([
        {
          action: "ENGAGE",
          outcome: "REJECTED",
          reason: "stale totp",
          actor: "operator-7",
          at: 1_700_000_000_000,
        },
      ]);
    });

    it("records a REJECTED row when the caller's authorization refuses the disengage", async () => {
      const store = new MemoryHaltStore("HALTED");
      const gate = createHaltGate("HALTED");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await expect(
        disengageHalt(store, gate, recorder, { ...OPERATOR, authorize: () => false }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError);

      expect(store.writes).toEqual([]);
      expect(gate.isHalted()).toBe(true);
      expect(outcomes(await recorder.entries())).toEqual(["DISENGAGE:REJECTED"]);
    });

    it("records a REJECTED row when the authorization check itself throws", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await expect(
        engageHalt(store, gate, recorder, {
          ...OPERATOR,
          authorize: () => {
            throw new Error("totp verifier unreachable");
          },
        }),
      ).rejects.toThrow("totp verifier unreachable");

      expect(store.writes).toEqual([]);
      expect(outcomes(await recorder.entries())).toEqual(["ENGAGE:REJECTED"]);
    });

    it("records a rejected attempt even when the durable store is unreachable", async () => {
      // Authorization is checked BEFORE the store is read, so an infrastructure outage
      // cannot swallow the evidence that someone tried and was refused.
      const store: HaltStore = {
        read: async () => {
          throw new Error("store unreachable");
        },
        write: async () => {
          throw new Error("store unreachable");
        },
      };
      const recorder = createInMemoryHaltEvidenceRecorder();

      await expect(
        engageHalt(store, createHaltGate("RUNNING"), recorder, {
          ...OPERATOR,
          authorize: () => false,
        }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError);

      expect(outcomes(await recorder.entries())).toEqual(["ENGAGE:REJECTED"]);
    });

    it("every attempt against a halted node appends exactly one row, whatever the outcome", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await engageHalt(store, gate, recorder, OPERATOR); // APPLIED
      await engageHalt(store, gate, recorder, OPERATOR); // NO_OP
      await expect(
        engageHalt(store, gate, recorder, { ...OPERATOR, authorize: () => false }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError); // REJECTED
      await disengageHalt(store, gate, recorder, OPERATOR); // APPLIED
      await disengageHalt(store, gate, recorder, OPERATOR); // NO_OP

      expect(outcomes(await recorder.entries())).toEqual([
        "ENGAGE:APPLIED",
        "ENGAGE:NO_OP",
        "ENGAGE:REJECTED",
        "DISENGAGE:APPLIED",
        "DISENGAGE:NO_OP",
      ]);
      // five attempts, five rows — one per attempt, never more, never fewer
      expect((await recorder.entries()).length).toBe(5);
      // but only the two that changed anything touched the durable state
      expect(store.writes).toEqual(["HALTED", "RUNNING"]);
    });

    it("engage and disengage are audited identically — same fields, same outcomes", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await engageHalt(store, gate, recorder, OPERATOR);
      await disengageHalt(store, gate, recorder, OPERATOR);

      const [engaged, disengaged] = await recorder.entries();
      expect(Object.keys(engaged!).sort()).toEqual(Object.keys(disengaged!).sort());
      expect(engaged!.outcome).toBe(disengaged!.outcome);
      expect(engaged!.actor).toBe(disengaged!.actor);
    });

    it("supplies a default reason when none is given", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await engageHalt(store, gate, recorder, OPERATOR);
      await disengageHalt(store, gate, recorder, OPERATOR);

      const entries = await recorder.entries();
      expect(entries[0]?.reason).toBe("operator halt engaged");
      expect(entries[1]?.reason).toBe("operator halt disengaged");
    });

    it("normalises a blank actor rather than refusing the toggle", async () => {
      // Bad audit metadata must never block an emergency engage.
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await engageHalt(store, gate, recorder, { actor: "   ", now: FIXED_NOW });

      expect(gate.isHalted()).toBe(true);
      expect((await recorder.entries())[0]?.actor).toBe("unknown");
    });

    it("keeps the trail in attempt order with monotonic timestamps", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();
      let clock = 1_000;
      const now = () => (clock += 1);

      await engageHalt(store, gate, recorder, { actor: "a", now });
      await disengageHalt(store, gate, recorder, { actor: "a", now });
      await engageHalt(store, gate, recorder, { actor: "a", now });

      const entries = await recorder.entries();
      expect(entries.map((e) => e.action)).toEqual(["ENGAGE", "DISENGAGE", "ENGAGE"]);
      expect(entries[0]!.at).toBeLessThan(entries[1]!.at);
      expect(entries[1]!.at).toBeLessThan(entries[2]!.at);
    });
  });

  describe("crash-safe ordering (an audit failure never un-halts the node)", () => {
    it("persists the durable state, flips the gate, THEN appends evidence", async () => {
      const sequence: string[] = [];
      const store: HaltStore = {
        read: async () => "RUNNING",
        write: async () => {
          sequence.push("write");
        },
      };
      const recorder: HaltEvidenceRecorder = {
        append: async () => {
          sequence.push("evidence");
        },
        entries: async () => [],
      };
      const gate = createHaltGate("RUNNING");

      await engageHalt(store, gate, recorder, OPERATOR);

      expect(sequence).toEqual(["write", "evidence"]);
    });

    it("an evidence-append failure does not roll back the durable halt", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder: HaltEvidenceRecorder = {
        append: async () => {
          throw new Error("audit sink unavailable");
        },
        entries: async () => [],
      };

      await expect(engageHalt(store, gate, recorder, OPERATOR)).rejects.toThrow(
        "audit sink unavailable",
      );

      // durable truth + live gate already flipped: the node stays safely halted
      expect(store.writes).toEqual(["HALTED"]);
      expect(gate.isHalted()).toBe(true);
    });
  });

  describe("durable recorder (one record, no schema migration)", () => {
    it("survives a process restart — a new recorder over the same record reads the trail", async () => {
      const evidenceStore = new MemoryEvidenceStore();
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");

      await engageHalt(store, gate, createDurableHaltEvidenceRecorder(evidenceStore), {
        ...OPERATOR,
        reason: "freeze",
      });

      // a fresh recorder, as after a restart: the trail is in the durable record, not in memory
      const reopened = createDurableHaltEvidenceRecorder(evidenceStore);
      expect(await reopened.entries()).toEqual([
        {
          action: "ENGAGE",
          outcome: "APPLIED",
          reason: "freeze",
          actor: "operator-7",
          at: 1_700_000_000_000,
        },
      ]);
    });

    it("keeps the whole trail in a single record (no schema migration)", async () => {
      const evidenceStore = new MemoryEvidenceStore();
      const recorder = createDurableHaltEvidenceRecorder(evidenceStore);

      await recorder.append({
        action: "ENGAGE",
        outcome: "APPLIED",
        reason: "r",
        actor: "a",
        at: 1,
      });
      await recorder.append({
        action: "DISENGAGE",
        outcome: "NO_OP",
        reason: "r",
        actor: "a",
        at: 2,
      });

      expect(outcomes(await recorder.entries())).toEqual([
        "ENGAGE:APPLIED",
        "DISENGAGE:NO_OP",
      ]);
      // one record, rewritten in place — HALT_PERSISTENCE.storage "single-durable-record"
      expect(JSON.parse(evidenceStore.value!)).toHaveLength(2);
    });

    it("reads a missing record as an empty trail (a node never toggled)", async () => {
      const recorder = createDurableHaltEvidenceRecorder(new MemoryEvidenceStore(null));
      expect(await recorder.entries()).toEqual([]);
    });

    it("throws on an unparseable record rather than reading it as an empty trail", async () => {
      const recorder = createDurableHaltEvidenceRecorder(new MemoryEvidenceStore("{not json"));
      await expect(recorder.entries()).rejects.toBeInstanceOf(HaltEvidenceCorruptError);
    });

    it("throws on a well-formed JSON record that is not a trail of evidence rows", async () => {
      const wrongShape = new MemoryEvidenceStore(
        JSON.stringify([{ action: "ENGAGE", outcome: "MAYBE", reason: "r", actor: "a", at: 1 }]),
      );
      await expect(
        createDurableHaltEvidenceRecorder(wrongShape).entries(),
      ).rejects.toBeInstanceOf(HaltEvidenceCorruptError);
    });

    it("a corrupt trail cannot un-halt the node — the durable halt still stands", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createDurableHaltEvidenceRecorder(new MemoryEvidenceStore("garbage"));

      await expect(engageHalt(store, gate, recorder, OPERATOR)).rejects.toBeInstanceOf(
        HaltEvidenceCorruptError,
      );

      expect(store.writes).toEqual(["HALTED"]);
      expect(gate.isHalted()).toBe(true);
    });

    it("caps the single record at the newest HALT_EVIDENCE_MAX_RECORDS rows", async () => {
      const evidenceStore = new MemoryEvidenceStore();
      const recorder = createDurableHaltEvidenceRecorder(evidenceStore);
      const total = HALT_EVIDENCE_MAX_RECORDS + 3;

      for (let index = 0; index < total; index += 1) {
        await recorder.append({
          action: "ENGAGE",
          outcome: "NO_OP",
          reason: "r",
          actor: "a",
          at: index,
        });
      }

      const entries = await recorder.entries();
      expect(entries).toHaveLength(HALT_EVIDENCE_MAX_RECORDS);
      expect(entries[entries.length - 1]?.at).toBe(total - 1);
      expect(entries[0]?.at).toBe(total - HALT_EVIDENCE_MAX_RECORDS);
    });
  });

  describe("append-only trail integrity", () => {
    it("entries() returns a defensive copy that cannot mutate the trail", async () => {
      const recorder = createInMemoryHaltEvidenceRecorder();
      await recorder.append({
        action: "ENGAGE",
        outcome: "APPLIED",
        reason: "r",
        actor: "a",
        at: 1,
      });

      const first = await recorder.entries();
      (first as unknown as { action: string }[]).push({ action: "FORGED" });

      expect(await recorder.entries()).toEqual([
        { action: "ENGAGE", outcome: "APPLIED", reason: "r", actor: "a", at: 1 },
      ]);
    });
  });

  describe("toggleHalt is the only halt-state mutation path", () => {
    it("records the actual transition direction across toggles", async () => {
      const store = new MemoryHaltStore(null);
      const gate = createHaltGate();
      const recorder = createInMemoryHaltEvidenceRecorder();
      let clock = 0;
      const now = () => (clock += 1);

      // A null record reads as HALTED (MISSING_HALT_RECORD_DEFAULT), so the first
      // toggle on a fresh store is a real DISENGAGE that persists RUNNING, not a NO_OP.
      expect(await toggleHalt(store, gate, recorder, { actor: "a", now })).toBe("RUNNING");
      expect(await toggleHalt(store, gate, recorder, { actor: "a", now })).toBe("HALTED");
      expect(await toggleHalt(store, gate, recorder, { actor: "a", now })).toBe("RUNNING");

      expect(outcomes(await recorder.entries())).toEqual([
        "DISENGAGE:APPLIED",
        "ENGAGE:APPLIED",
        "DISENGAGE:APPLIED",
      ]);
    });

    it("a disengage on a fresh node with no durable record persists RUNNING (not a NO_OP)", async () => {
      const store = new MemoryHaltStore(null);
      const gate = createHaltGate();
      const recorder = createInMemoryHaltEvidenceRecorder();

      const result = await disengageHalt(store, gate, recorder, OPERATOR);

      expect(result).toBe("RUNNING");
      // the durable record itself must read RUNNING — the regression this ticket guards
      // against is a disengage that flips the live gate but never persists anything, so
      // the very next restart re-halts the node.
      expect(await store.read()).toBe("RUNNING");
      expect(store.writes).toEqual(["RUNNING"]);
      expect(gate.isHalted()).toBe(false);
      expect(outcomes(await recorder.entries())).toEqual(["DISENGAGE:APPLIED"]);
    });

    it("audits a rejected toggle without touching state", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      await expect(
        toggleHalt(store, gate, recorder, { ...OPERATOR, authorize: () => false }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError);

      expect(store.writes).toEqual([]);
      expect(gate.isHalted()).toBe(false);
      expect(outcomes(await recorder.entries())).toEqual(["ENGAGE:REJECTED"]);
    });

    it("the operator module exports no un-audited way to mutate halt state", async () => {
      // Every exported mutator must demand a recorder. `restoreHaltState` is excluded on
      // purpose: it converges the live gate to the durable record at boot, it does not
      // toggle, and audits toggles.
      const operatorModule: Record<string, unknown> = await import("../src/operator/index.js");
      const mutators = Object.keys(operatorModule).filter((name) =>
        /^(engage|disengage|toggle)/.test(name),
      );

      expect(mutators.sort()).toEqual(["disengageHalt", "engageHalt", "toggleHalt"]);
      for (const name of mutators) {
        // (store, gate, recorder, request) — the recorder is positional and mandatory
        expect((operatorModule[name] as (...args: unknown[]) => unknown).length).toBe(4);
      }
    });
  });

  describe("admission gating with evidence (no new work after halt; in-flight completes)", () => {
    it("engage refuses new signing/claims/admissions while in-flight work completes", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      const recorder = createInMemoryHaltEvidenceRecorder();

      const signer = createGatedSigner(gate, new RecordingSigner());
      const workerDelegate = new RecordingWorker([42]);
      const worker = createGatedWorker(gate, workerDelegate);
      const admission = createGatedAdmission(gate, new RecordingAdmission());

      // pre-halt: work is admitted, and a claim is taken (now in flight)
      await expect(signer.sign("a")).resolves.toBe("sig:a");
      const inflight = await worker.claim();
      expect(inflight).toBe(42);
      await expect(admission.admit("op-1")).resolves.toBe("op:op-1");

      await engageHalt(store, gate, recorder, { ...OPERATOR, reason: "freeze" });

      // no NEW work is accepted after halt — zero further delegate calls
      await expect(signer.sign("b")).rejects.toBeInstanceOf(OperatorHaltError);
      await expect(worker.claim()).resolves.toBeNull();
      await expect(admission.admit("op-2")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(workerDelegate.claimCalls).toBe(1);

      // the in-flight claim still completes safely (the one-in-flight-per-wallet rule: never abort mid-flight)
      await expect(worker.process(inflight as number)).resolves.toBe(84);
      expect(workerDelegate.processed).toEqual([42]);

      expect(outcomes(await recorder.entries())).toEqual(["ENGAGE:APPLIED"]);
    });

    it("disengage resumes admission and records the transition", async () => {
      const store = new MemoryHaltStore("HALTED");
      const gate = createHaltGate("HALTED");
      const recorder = createInMemoryHaltEvidenceRecorder();
      const admission = createGatedAdmission(gate, new RecordingAdmission());

      await expect(admission.admit("x")).rejects.toBeInstanceOf(OperatorHaltError);

      await disengageHalt(store, gate, recorder, OPERATOR);

      await expect(admission.admit("y")).resolves.toBe("op:y");
      expect(outcomes(await recorder.entries())).toEqual(["DISENGAGE:APPLIED"]);
    });

    it("a rejected disengage leaves the node halted and new work refused", async () => {
      const store = new MemoryHaltStore("HALTED");
      const gate = createHaltGate("HALTED");
      const recorder = createInMemoryHaltEvidenceRecorder();
      const admission = createGatedAdmission(gate, new RecordingAdmission());

      await expect(
        disengageHalt(store, gate, recorder, { ...OPERATOR, authorize: () => false }),
      ).rejects.toBeInstanceOf(HaltToggleRejectedError);

      await expect(admission.admit("x")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(outcomes(await recorder.entries())).toEqual(["DISENGAGE:REJECTED"]);
    });
  });

  describe("restart durability with evidence", () => {
    it("restart stays halted; the durable trail survives the restart", async () => {
      const evidenceStore = new MemoryEvidenceStore();
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate("RUNNING");
      await engageHalt(store, gate, createDurableHaltEvidenceRecorder(evidenceStore), OPERATOR);

      // simulate a process restart: a fresh gate AND a fresh recorder, both rebuilt from
      // durable records
      const restarted = createHaltGate();
      const reopened = createDurableHaltEvidenceRecorder(evidenceStore);
      const state = await restoreHaltState(store, restarted, { sleep: NO_SLEEP });

      expect(state).toBe("HALTED");
      expect(restarted.isHalted()).toBe(true);
      expect(outcomes(await reopened.entries())).toEqual(["ENGAGE:APPLIED"]);

      // a post-restart disengage appends to the same durable trail
      await disengageHalt(store, restarted, reopened, OPERATOR);
      expect(outcomes(await reopened.entries())).toEqual([
        "ENGAGE:APPLIED",
        "DISENGAGE:APPLIED",
      ]);
    });
  });
});
