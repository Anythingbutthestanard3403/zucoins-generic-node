// Pin node-core halt kind scope against contracts source.
// operator-halt is not a package export — census via relative contracts path
// (same posture as halt-durable-phases.test.ts).

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  HALT_EXEMPT_OPERATION_KINDS as CONTRACT_EXEMPT,
  HALT_GATED_OPERATION_KINDS as CONTRACT_GATED,
} from "../../generic-node-contracts/src/operator-halt/halt.contract.ts";
import {
  HALT_EXEMPT_OPERATION_KINDS,
  HALT_GATED_OPERATION_KINDS,
  OperatorHaltError,
  assertHaltAdmitsKind,
  createHaltGate,
  isHaltExemptOperationKind,
  isHaltGatedOperationKind,
  RUNNING,
} from "../src/operator/halt.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("halt kind scope", () => {
  it("mirrors contracts HALT_GATED / HALT_EXEMPT exactly", () => {
    expect([...HALT_GATED_OPERATION_KINDS]).toEqual([...CONTRACT_GATED]);
    expect([...HALT_EXEMPT_OPERATION_KINDS]).toEqual([...CONTRACT_EXEMPT]);
  });

  it("predicates match the closed sets", () => {
    expect(isHaltGatedOperationKind("MOVE_INTERNAL")).toBe(true);
    expect(isHaltGatedOperationKind("SEND_EXTERNAL")).toBe(true);
    expect(isHaltGatedOperationKind("RECEIVE_EXTERNAL")).toBe(false);
    expect(isHaltExemptOperationKind("RECEIVE_EXTERNAL")).toBe(true);
    expect(isHaltExemptOperationKind("MOVE_INTERNAL")).toBe(false);
  });

  it("assertHaltAdmitsKind: RECEIVE open while halted; MOVE/SEND refuse", () => {
    const gate = createHaltGate(RUNNING);
    gate.engage();
    expect(() => assertHaltAdmitsKind(gate, "RECEIVE_EXTERNAL")).not.toThrow();
    expect(() => assertHaltAdmitsKind(gate, "MOVE_INTERNAL")).toThrow(OperatorHaltError);
    expect(() => assertHaltAdmitsKind(gate, "SEND_EXTERNAL")).toThrow(OperatorHaltError);
    // Unknown fails closed (treat as gated).
    expect(() => assertHaltAdmitsKind(gate, "UNKNOWN_KIND")).toThrow(OperatorHaltError);
  });

  it("production formation paths call assertHaltAdmitsKind for MOVE and SEND (not RECEIVE)", () => {
    const moveSrc = readFileSync(resolve(here, "../src/core/move-form-and-sign.ts"), "utf8");
    expect(moveSrc).toMatch(/assertHaltAdmitsKind\s*\(\s*["']MOVE_INTERNAL["']\s*\)/);
    expect(moveSrc).toMatch(/signMoveStepsUnderLeases/);

    const workersSrc = readFileSync(
      resolve(here, "../../../apps/generic-node/src/money-workers/start-money-workers.ts"),
      "utf8",
    );
    expect(workersSrc).toMatch(/assertHaltAdmitsKind\s*\(\s*["']SEND_EXTERNAL["']\s*\)/);
    // Required gate — no optional-chain omit at production SEND first formation.
    expect(workersSrc).not.toMatch(/assertHaltAdmitsKind\?\./);
    // RECEIVE does not call kind gate (shared assertMoneyAdmitted only).
    expect(workersSrc).not.toMatch(/assertHaltAdmitsKind\s*\(\s*["']RECEIVE_EXTERNAL["']\s*\)/);
  });

  it("module comment cites and RECEIVE exemption", () => {
    const src = readFileSync(resolve(here, "../src/operator/halt.ts"), "utf8");
    expect(src).toContain("RECEIVE_EXTERNAL");
    expect(src).toMatch(/exempt/i);
  });
});
