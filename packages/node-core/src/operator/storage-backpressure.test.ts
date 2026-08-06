import { describe, expect, it } from "vitest";

import {
  BackpressureConfigurationError,
  DEFAULT_CRITICAL_THRESHOLD,
  DEFAULT_PRESSURE_THRESHOLD,
  EvidenceRejectedError,
  OperationsHaltedError,
  StorageBackpressureError,
  canAcceptEvidenceInState,
  canOperateInState,
  classifyPressure,
  createStorageBackpressure,
  nextPressureState,
  utilizationRatio,
  validateThresholds,
  type PressureBand,
  type PressureState,
  type StorageUtilizationSource,
} from "./index.js";

const THRESHOLDS = {
  pressure: DEFAULT_PRESSURE_THRESHOLD,
  critical: DEFAULT_CRITICAL_THRESHOLD,
};

class FakeSource implements StorageUtilizationSource {
  readings: number[];
  failNext = false;

  constructor(readings: number[] = []) {
    this.readings = readings;
  }

  async utilization(): Promise<number> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("transient storage read failure");
    }
    const next = this.readings.shift();
    return next === undefined ? 0 : next;
  }
}

describe("storage backpressure", () => {
  describe("classifyPressure", () => {
    it("classifies below the pressure threshold as NORMAL", () => {
      expect(classifyPressure(0, THRESHOLDS)).toBe("NORMAL");
      expect(classifyPressure(0.89, THRESHOLDS)).toBe("NORMAL");
    });

    it("classifies at and above the pressure threshold as PRESSURE", () => {
      expect(classifyPressure(0.9, THRESHOLDS)).toBe("PRESSURE");
      expect(classifyPressure(0.94, THRESHOLDS)).toBe("PRESSURE");
    });

    it("classifies at and above the critical threshold as CRITICAL", () => {
      expect(classifyPressure(0.95, THRESHOLDS)).toBe("CRITICAL");
      expect(classifyPressure(0.99, THRESHOLDS)).toBe("CRITICAL");
      expect(classifyPressure(1.5, THRESHOLDS)).toBe("CRITICAL");
    });

    it("fails closed on an indeterminate reading", () => {
      expect(classifyPressure(Number.NaN, THRESHOLDS)).toBe("CRITICAL");
      expect(classifyPressure(Number.POSITIVE_INFINITY, THRESHOLDS)).toBe("CRITICAL");
      expect(classifyPressure(-0.1, THRESHOLDS)).toBe("CRITICAL");
    });
  });

  describe("nextPressureState transition table", () => {
    const cases: Array<[PressureState, PressureBand, PressureState]> = [
      ["NORMAL", "NORMAL", "NORMAL"],
      ["NORMAL", "PRESSURE", "PRESSURE"],
      ["NORMAL", "CRITICAL", "CRITICAL"],
      ["PRESSURE", "NORMAL", "NORMAL"],
      ["PRESSURE", "PRESSURE", "PRESSURE"],
      ["PRESSURE", "CRITICAL", "CRITICAL"],
      ["CRITICAL", "CRITICAL", "CRITICAL"],
      ["CRITICAL", "PRESSURE", "HALTED"],
      ["CRITICAL", "NORMAL", "NORMAL"],
      ["HALTED", "NORMAL", "NORMAL"],
      ["HALTED", "PRESSURE", "HALTED"],
      ["HALTED", "CRITICAL", "HALTED"],
    ];

    it.each(cases)("from %s on band %s moves to %s", (current, band, expected) => {
      expect(nextPressureState(current, band)).toBe(expected);
    });
  });

  describe("state admission predicates", () => {
    it("admits new evidence only in NORMAL", () => {
      expect(canAcceptEvidenceInState("NORMAL")).toBe(true);
      expect(canAcceptEvidenceInState("PRESSURE")).toBe(false);
      expect(canAcceptEvidenceInState("CRITICAL")).toBe(false);
      expect(canAcceptEvidenceInState("HALTED")).toBe(false);
    });

    it("permits operations in NORMAL and PRESSURE only", () => {
      expect(canOperateInState("NORMAL")).toBe(true);
      expect(canOperateInState("PRESSURE")).toBe(true);
      expect(canOperateInState("CRITICAL")).toBe(false);
      expect(canOperateInState("HALTED")).toBe(false);
    });
  });

  describe("utilizationRatio", () => {
    it("computes used over capacity", () => {
      expect(utilizationRatio(90, 100)).toBe(0.9);
      expect(utilizationRatio(150, 100)).toBe(1.5);
    });

    it("returns NaN for indeterminate inputs so classification fails closed", () => {
      expect(Number.isNaN(utilizationRatio(10, 0))).toBe(true);
      expect(Number.isNaN(utilizationRatio(10, -5))).toBe(true);
      expect(Number.isNaN(utilizationRatio(Number.NaN, 10))).toBe(true);
      expect(Number.isNaN(utilizationRatio(Number.POSITIVE_INFINITY, 10))).toBe(true);
    });
  });

  describe("validateThresholds", () => {
    it("accepts a well-formed pair", () => {
      expect(validateThresholds({ pressure: 0.9, critical: 0.95 })).toEqual({
        pressure: 0.9,
        critical: 0.95,
      });
    });

    it("rejects non-finite, out-of-range, and inverted thresholds", () => {
      expect(() => validateThresholds({ pressure: 0, critical: 0.95 })).toThrow(
        BackpressureConfigurationError,
      );
      expect(() => validateThresholds({ pressure: 1, critical: 1 })).toThrow(
        BackpressureConfigurationError,
      );
      expect(() => validateThresholds({ pressure: 0.95, critical: 0.9 })).toThrow(
        BackpressureConfigurationError,
      );
      expect(() => validateThresholds({ pressure: 0.9, critical: 1.5 })).toThrow(
        BackpressureConfigurationError,
      );
      expect(() =>
        validateThresholds({ pressure: Number.NaN, critical: 0.95 }),
      ).toThrow(BackpressureConfigurationError);
    });
  });

  describe("global gate lifecycle", () => {
    it("starts NORMAL and admits everything", () => {
      const gate = createStorageBackpressure();
      expect(gate.globalState()).toBe("NORMAL");
      expect(gate.canAcceptEvidence()).toBe(true);
      expect(gate.canOperate()).toBe(true);
    });

    it("rejects new evidence but keeps operating under PRESSURE", () => {
      const gate = createStorageBackpressure();
      expect(gate.recordGlobalSample(0.92)).toBe("PRESSURE");
      expect(gate.canAcceptEvidence()).toBe(false);
      expect(gate.canOperate()).toBe(true);
    });

    it("halts all operations under CRITICAL", () => {
      const gate = createStorageBackpressure();
      expect(gate.recordGlobalSample(0.96)).toBe("CRITICAL");
      expect(gate.canAcceptEvidence()).toBe(false);
      expect(gate.canOperate()).toBe(false);
    });

    it("recovers from PRESSURE back to NORMAL when utilization drops", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.92);
      expect(gate.recordGlobalSample(0.5)).toBe("NORMAL");
      expect(gate.canAcceptEvidence()).toBe(true);
      expect(gate.canOperate()).toBe(true);
    });

    it("latches into HALTED below critical and auto-resumes below pressure", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.96); // CRITICAL
      // Drops into the recovery band [pressure, critical): halt latches, no flapping.
      expect(gate.recordGlobalSample(0.92)).toBe("HALTED");
      expect(gate.canAcceptEvidence()).toBe(false);
      expect(gate.canOperate()).toBe(false);
      // Still above pressure: stays halted.
      expect(gate.recordGlobalSample(0.91)).toBe("HALTED");
      // Below pressure: resumes automatically.
      expect(gate.recordGlobalSample(0.5)).toBe("NORMAL");
      expect(gate.canAcceptEvidence()).toBe(true);
      expect(gate.canOperate()).toBe(true);
    });

    it("stays CRITICAL while utilization remains at or above critical", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.96);
      expect(gate.recordGlobalSample(0.97)).toBe("CRITICAL");
      expect(gate.recordGlobalSample(0.95)).toBe("CRITICAL");
    });

    it("fails closed on an indeterminate sample", () => {
      const gate = createStorageBackpressure();
      expect(gate.recordGlobalSample(Number.NaN)).toBe("CRITICAL");
      expect(gate.canOperate()).toBe(false);
    });
  });

  describe("per-wallet gate", () => {
    it("gates a single full wallet while global stays healthy", () => {
      const gate = createStorageBackpressure();
      gate.recordWalletSample("wallet-a", 0.96);
      expect(gate.walletState("wallet-a")).toBe("CRITICAL");
      expect(gate.globalState()).toBe("NORMAL");
      expect(gate.canAcceptEvidence("wallet-a")).toBe(false);
      expect(gate.canOperate("wallet-a")).toBe(false);
      // Global and other wallets are unaffected.
      expect(gate.canAcceptEvidence()).toBe(true);
      expect(gate.canOperate()).toBe(true);
      expect(gate.canAcceptEvidence("wallet-b")).toBe(true);
      expect(gate.canOperate("wallet-b")).toBe(true);
    });

    it("rejects evidence but permits operations for a wallet under PRESSURE", () => {
      const gate = createStorageBackpressure();
      gate.recordWalletSample("wallet-a", 0.92);
      expect(gate.walletState("wallet-a")).toBe("PRESSURE");
      expect(gate.canAcceptEvidence("wallet-a")).toBe(false);
      expect(gate.canOperate("wallet-a")).toBe(true);
    });

    it("refuses globally even when the target wallet is healthy", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.96);
      gate.recordWalletSample("wallet-a", 0.1);
      expect(gate.canAcceptEvidence("wallet-a")).toBe(false);
      expect(gate.canOperate("wallet-a")).toBe(false);
    });

    it("reports NORMAL for an unknown wallet", () => {
      const gate = createStorageBackpressure();
      expect(gate.walletState("never-seen")).toBe("NORMAL");
    });

    it("forgets per-wallet state on demand", () => {
      const gate = createStorageBackpressure();
      gate.recordWalletSample("wallet-a", 0.96);
      gate.forgetWallet("wallet-a");
      expect(gate.walletState("wallet-a")).toBe("NORMAL");
      expect(gate.canOperate("wallet-a")).toBe(true);
    });
  });

  describe("assertion guards", () => {
    it("throws EvidenceRejectedError when evidence is refused", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.92);
      expect(() => gate.assertCanAcceptEvidence()).toThrow(EvidenceRejectedError);
      expect(() => gate.assertCanAcceptEvidence()).toThrow(StorageBackpressureError);
      // Operations still proceed under PRESSURE.
      expect(() => gate.assertCanOperate()).not.toThrow();
    });

    it("throws OperationsHaltedError when operations are halted", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.96);
      expect(() => gate.assertCanOperate()).toThrow(OperationsHaltedError);
      expect(() => gate.assertCanAcceptEvidence()).toThrow(EvidenceRejectedError);
    });

    it("does not throw while NORMAL", () => {
      const gate = createStorageBackpressure();
      expect(() => gate.assertCanAcceptEvidence()).not.toThrow();
      expect(() => gate.assertCanOperate()).not.toThrow();
    });
  });

  describe("monitoring source", () => {
    it("records a global sample from the configured source", async () => {
      const source = new FakeSource([0.92]);
      const gate = createStorageBackpressure({ source });
      expect(await gate.refresh()).toBe("PRESSURE");
      expect(gate.globalState()).toBe("PRESSURE");
    });

    it("fails closed when the source read throws", async () => {
      const source = new FakeSource([0.1]);
      source.failNext = true;
      const gate = createStorageBackpressure({ source });
      expect(await gate.refresh()).toBe("CRITICAL");
      expect(gate.canOperate()).toBe(false);
    });

    it("rejects refresh when no source is configured", async () => {
      const gate = createStorageBackpressure();
      await expect(gate.refresh()).rejects.toThrow(BackpressureConfigurationError);
    });
  });

  describe("configuration", () => {
    it("honors custom thresholds", () => {
      const gate = createStorageBackpressure({
        thresholds: { pressure: 0.5, critical: 0.6 },
      });
      expect(gate.recordGlobalSample(0.55)).toBe("PRESSURE");
      expect(gate.recordGlobalSample(0.65)).toBe("CRITICAL");
    });

    it("rejects invalid thresholds at construction", () => {
      expect(() => createStorageBackpressure({ thresholds: { pressure: 0.9, critical: 0.8 } })).toThrow(
        BackpressureConfigurationError,
      );
    });

    it("honors an explicit initial state and recovers from it", () => {
      const gate = createStorageBackpressure({ initial: "HALTED" });
      expect(gate.globalState()).toBe("HALTED");
      expect(gate.canOperate()).toBe(false);
      // A latched halt auto-resumes only on a below-pressure reading.
      expect(gate.recordGlobalSample(0.5)).toBe("NORMAL");
      expect(gate.canOperate()).toBe(true);
    });
  });

  describe("snapshot", () => {
    it("reports global and per-wallet readings", () => {
      const gate = createStorageBackpressure();
      gate.recordGlobalSample(0.92);
      gate.recordWalletSample("wallet-a", 0.96);
      const snapshot = gate.snapshot();
      expect(snapshot.global).toEqual({ state: "PRESSURE", utilization: 0.92 });
      expect(snapshot.wallets).toEqual([
        { walletId: "wallet-a", state: "CRITICAL", utilization: 0.96 },
      ]);
    });
  });
});
