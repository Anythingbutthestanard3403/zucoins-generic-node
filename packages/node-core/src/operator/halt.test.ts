import { describe, expect, it } from "vitest";

import {
  HALT_GATED_PHASES,
  HALT_PERMEABLE_PHASES,
  OperatorHaltError,
  assertNotHalted,
  assertPhaseAdmissible,
  createGatedAdmission,
  createGatedSigner,
  createGatedWorker,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  isHaltGatedPhase,
  restoreHaltState,
  toggleHalt,
  type Admission,
  type DurablePhase,
  type HaltGate,
  type HaltState,
  type HaltStore,
  type Signer,
  type Worker,
} from "./index.js";

const NO_SLEEP = async (): Promise<void> => {};
// Every toggle is audited (kind-scoped operator halt); these cases assert durable/gate behaviour, so they
// pass a throwaway recorder. The trail itself is asserted in test/halt-evidence.test.ts.
const AUDITED = () => createInMemoryHaltEvidenceRecorder();
const OPERATOR = { actor: "operator" };

class MemoryHaltStore implements HaltStore {
  private state: HaltState | null;
  readonly writes: HaltState[] = [];
  failReads = 0;
  failWrites = 0;
  corrupt = false;

  constructor(initial: HaltState | null = null) {
    this.state = initial;
  }

  async read(): Promise<HaltState | null> {
    if (this.failReads > 0) {
      this.failReads -= 1;
      throw new Error("transient store read failure");
    }
    if (this.corrupt) {
      return null;
    }
    return this.state;
  }

  async write(state: HaltState): Promise<void> {
    if (this.failWrites > 0) {
      this.failWrites -= 1;
      throw new Error("transient store write failure");
    }
    this.writes.push(state);
    this.state = state;
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

describe("operator halt", () => {
  describe("persistence across restart", () => {
    it("halt persists across restart", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate();
      await toggleHalt(store, gate, AUDITED(), OPERATOR);
      expect(gate.isHalted()).toBe(true);

      const restarted = createHaltGate();
      const state = await restoreHaltState(store, restarted, { sleep: NO_SLEEP });
      expect(state).toBe("HALTED");
      expect(restarted.isHalted()).toBe(true);
    });

    it("un-halt persists across restart", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate();
      const state = await restoreHaltState(store, gate, { sleep: NO_SLEEP });
      expect(state).toBe("RUNNING");
      expect(gate.isHalted()).toBe(false);
    });

    it("toggleHalt persists durably before flipping the live gate", async () => {
      const sequence: string[] = [];
      const store: HaltStore = {
        read: async () => null,
        write: async () => {
          sequence.push("write");
        },
      };
      const gate: HaltGate = {
        isHalted: () => false,
        engage: () => {
          sequence.push("engage");
        },
        release: () => {
          sequence.push("release");
        },
      };
      await toggleHalt(store, gate, AUDITED(), OPERATOR);
      expect(sequence).toEqual(["write", "release"]);
    });

    it("toggleHalt is idempotent for repeated engages", async () => {
      const store = new MemoryHaltStore(null);
      const gate = createHaltGate();
      // a null record now counts as HALTED (agreeing with restoreHaltState's
      // fail-closed default), so the first toggle on a fresh store is a real disengage.
      expect(await toggleHalt(store, gate, AUDITED(), OPERATOR)).toBe("RUNNING");
      expect(await toggleHalt(store, gate, AUDITED(), OPERATOR)).toBe("HALTED");
      expect(await toggleHalt(store, gate, AUDITED(), OPERATOR)).toBe("RUNNING");
      expect(store.writes).toEqual(["RUNNING", "HALTED", "RUNNING"]);
    });
  });

  describe("fail-closed boot restore", () => {
    it("fails closed on a read error that exhausts the retry budget", async () => {
      const store = new MemoryHaltStore("RUNNING");
      store.failReads = Number.POSITIVE_INFINITY;
      const gate = createHaltGate();
      const state = await restoreHaltState(store, gate, { maxAttempts: 3, sleep: NO_SLEEP });
      expect(state).toBe("HALTED");
      expect(gate.isHalted()).toBe(true);
    });

    it("fails closed on corrupt state", async () => {
      const store = new MemoryHaltStore("RUNNING");
      store.corrupt = true;
      const gate = createHaltGate();
      const state = await restoreHaltState(store, gate, { sleep: NO_SLEEP });
      expect(state).toBe("HALTED");
      expect(gate.isHalted()).toBe(true);
    });

    it("defaults to halted when no record exists", async () => {
      const store = new MemoryHaltStore(null);
      const gate = createHaltGate();
      const state = await restoreHaltState(store, gate, { sleep: NO_SLEEP });
      expect(state).toBe("HALTED");
      expect(gate.isHalted()).toBe(true);
    });

    it("recovers after a bounded number of transient read failures", async () => {
      const store = new MemoryHaltStore("RUNNING");
      store.failReads = 2;
      const gate = createHaltGate();
      const state = await restoreHaltState(store, gate, { maxAttempts: 4, sleep: NO_SLEEP });
      expect(state).toBe("RUNNING");
      expect(gate.isHalted()).toBe(false);
    });

    it("applies exponentially increasing backoff between retries", async () => {
      const store = new MemoryHaltStore("RUNNING");
      store.failReads = Number.POSITIVE_INFINITY;
      const delays: number[] = [];
      const gate = createHaltGate();
      await restoreHaltState(store, gate, {
        maxAttempts: 4,
        baseDelayMs: 10,
        backoffMultiplier: 2,
        sleep: async (ms) => {
          delays.push(ms);
        },
      });
      expect(delays).toEqual([10, 20, 40]);
    });

    it("never releases the gate on indeterminate state", async () => {
      const released: boolean[] = [];
      const gate: HaltGate = {
        isHalted: () => true,
        engage: () => {},
        release: () => {
          released.push(true);
        },
      };
      const store = new MemoryHaltStore(null);
      await restoreHaltState(store, gate, { sleep: NO_SLEEP });
      expect(released).toEqual([]);
    });

    it("createHaltGate defaults to a halted (fail-closed) construction", () => {
      expect(createHaltGate().isHalted()).toBe(true);
    });
  });

  describe("gated signer", () => {
    it("refuses when halted with zero delegate calls", async () => {
      const gate = createHaltGate("HALTED");
      const delegate = new RecordingSigner();
      const signer = createGatedSigner(gate, delegate);
      await expect(signer.sign("payload")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(delegate.calls).toBe(0);
    });

    it("delegates when not halted", async () => {
      const gate = createHaltGate("RUNNING");
      const delegate = new RecordingSigner();
      const signer = createGatedSigner(gate, delegate);
      await expect(signer.sign("payload")).resolves.toBe("sig:payload");
      expect(delegate.calls).toBe(1);
    });

    it("stops signing the moment the gate engages", async () => {
      const gate = createHaltGate("RUNNING");
      const delegate = new RecordingSigner();
      const signer = createGatedSigner(gate, delegate);
      await signer.sign("a");
      gate.engage();
      await expect(signer.sign("b")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(delegate.calls).toBe(1);
    });

    it("propagates a delegate signing error when not halted", async () => {
      const gate = createHaltGate("RUNNING");
      const failing: Signer<string, string> = {
        sign: async () => {
          throw new Error("downstream signing failure");
        },
      };
      const signer = createGatedSigner(gate, failing);
      await expect(signer.sign("payload")).rejects.toThrow("downstream signing failure");
    });
  });

  describe("gated worker", () => {
    it("refuses new claims when halted", async () => {
      const gate = createHaltGate("HALTED");
      const delegate = new RecordingWorker([1, 2]);
      const worker = createGatedWorker(gate, delegate);
      await expect(worker.claim()).resolves.toBeNull();
      expect(delegate.claimCalls).toBe(0);
    });

    it("completes in-flight work even while halted", async () => {
      const gate = createHaltGate("RUNNING");
      const delegate = new RecordingWorker([7]);
      const worker = createGatedWorker(gate, delegate);
      const claim = await worker.claim();
      expect(claim).toBe(7);
      gate.engage();
      await expect(worker.process(claim as number)).resolves.toBe(14);
      expect(delegate.processed).toEqual([7]);
    });

    it("admits claims again once the gate releases", async () => {
      const gate = createHaltGate("HALTED");
      const delegate = new RecordingWorker([5]);
      const worker = createGatedWorker(gate, delegate);
      await expect(worker.claim()).resolves.toBeNull();
      gate.release();
      await expect(worker.claim()).resolves.toBe(5);
    });
  });


  describe("gated admission", () => {
    it("refuses new operations when halted with zero delegate calls", async () => {
      const gate = createHaltGate("HALTED");
      const delegate = new RecordingAdmission();
      const admission = createGatedAdmission(gate, delegate);
      await expect(admission.admit("new-op")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(delegate.calls).toBe(0);
    });

    it("admits operations when not halted", async () => {
      const gate = createHaltGate("RUNNING");
      const delegate = new RecordingAdmission();
      const admission = createGatedAdmission(gate, delegate);
      await expect(admission.admit("new-op")).resolves.toBe("op:new-op");
      expect(delegate.calls).toBe(1);
    });

    it("stops admitting the moment the gate engages", async () => {
      const gate = createHaltGate("RUNNING");
      const delegate = new RecordingAdmission();
      const admission = createGatedAdmission(gate, delegate);
      await admission.admit("a");
      gate.engage();
      await expect(admission.admit("b")).rejects.toBeInstanceOf(OperatorHaltError);
      expect(delegate.calls).toBe(1);
    });

    it("resumes admitting once the gate releases", async () => {
      const gate = createHaltGate("HALTED");
      const delegate = new RecordingAdmission();
      const admission = createGatedAdmission(gate, delegate);
      await expect(admission.admit("x")).rejects.toBeInstanceOf(OperatorHaltError);
      gate.release();
      await expect(admission.admit("y")).resolves.toBe("op:y");
      expect(delegate.calls).toBe(1);
    });

    it("propagates a delegate admission error when not halted", async () => {
      const gate = createHaltGate("RUNNING");
      const failing: Admission<string, string> = {
        admit: async () => {
          throw new Error("downstream admission failure");
        },
      };
      const admission = createGatedAdmission(gate, failing);
      await expect(admission.admit("payload")).rejects.toThrow("downstream admission failure");
    });
  });

  describe("phase coverage", () => {
    it("pre_sign is gated", () => {
      expect(isHaltGatedPhase("pre_sign")).toBe(true);
      expect(HALT_GATED_PHASES).toEqual(["pre_sign"]);
    });

    it("post_sign, pre_submit, post_submit are permeable", () => {
      for (const phase of ["post_sign", "pre_submit", "post_submit"] as const) {
        expect(isHaltGatedPhase(phase)).toBe(false);
      }
      expect(HALT_PERMEABLE_PHASES).toEqual(["post_sign", "pre_submit", "post_submit"]);
    });

    it("assertPhaseAdmissible throws only on gated phases while halted", () => {
      const gate = createHaltGate("HALTED");
      expect(() => assertPhaseAdmissible(gate, "pre_sign")).toThrow(OperatorHaltError);
      for (const phase of ["post_sign", "pre_submit", "post_submit"] as const) {
        expect(() => assertPhaseAdmissible(gate, phase)).not.toThrow();
      }
    });

    it("assertPhaseAdmissible allows every phase when not halted", () => {
      const gate = createHaltGate("RUNNING");
      const phases: readonly DurablePhase[] = [
        "pre_sign",
        "post_sign",
        "pre_submit",
        "post_submit",
      ];
      for (const phase of phases) {
        expect(() => assertPhaseAdmissible(gate, phase)).not.toThrow();
      }
    });

    it("assertNotHalted throws when halted and passes when not", () => {
      const halted = createHaltGate("HALTED");
      const running = createHaltGate("RUNNING");
      expect(() => assertNotHalted(halted)).toThrow(OperatorHaltError);
      expect(() => assertNotHalted(running)).not.toThrow();
    });
  });

  describe("full lifecycle", () => {
    it("halt -> refuse -> in-flight completes -> restart stays halted -> un-halt -> resume", async () => {
      const store = new MemoryHaltStore("RUNNING");
      const gate = createHaltGate();
      await restoreHaltState(store, gate, { sleep: NO_SLEEP });
      expect(gate.isHalted()).toBe(false);

      const signer = createGatedSigner(gate, new RecordingSigner());
      const delegate = new RecordingWorker([11]);
      const worker = createGatedWorker(gate, delegate);

      const claim = await worker.claim();
      expect(claim).toBe(11);
      await expect(signer.sign("x")).resolves.toBe("sig:x");

      await toggleHalt(store, gate, AUDITED(), OPERATOR);
      expect(gate.isHalted()).toBe(true);
      await expect(signer.sign("y")).rejects.toBeInstanceOf(OperatorHaltError);
      await expect(worker.claim()).resolves.toBeNull();

      await expect(worker.process(claim as number)).resolves.toBe(22);

      const restarted = createHaltGate();
      await restoreHaltState(store, restarted, { sleep: NO_SLEEP });
      expect(restarted.isHalted()).toBe(true);

      await toggleHalt(store, restarted, AUDITED(), OPERATOR);
      expect(restarted.isHalted()).toBe(false);

      const resumedWorker = createGatedWorker(restarted, new RecordingWorker([12]));
      await expect(resumedWorker.claim()).resolves.toBe(12);
    });
  });
});
