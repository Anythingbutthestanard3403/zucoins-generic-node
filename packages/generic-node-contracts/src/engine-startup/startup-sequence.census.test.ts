import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  ENGINE_STARTUP_SEQUENCE,
  STARTUP_INVARIANTS,
  LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE,
  SHUTDOWN_INVARIANTS,
} from "./startup-sequence.contract.ts";
import { verifyStartupSequence, verifyShutdownSequence } from "./verifiers.ts";

describe("engine startup / shutdown sub-sequences are frozen (startup-sequence decision / boot-recovery rule)", () => {
  it("freezes the startup sub-sequence with the signer authority armed last", () => {
    assertFieldOrder(ENGINE_STARTUP_SEQUENCE, [
      "REBUILD_QUEUES",
      "START_RECONCILER",
      "START_MUTATION_WORKERS",
      "ARM_SIGNER_AUTHORITY",
    ]);
    expect(STARTUP_INVARIANTS.signer_authority_armed_last).toBe(true);
    expect(STARTUP_INVARIANTS.runs_only_on_leader).toBe(true);
  });

  it("freezes the leadership-loss shutdown sub-sequence", () => {
    assertFieldOrder(LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE, [
      "MARK_LEADERSHIP_LOST",
      "STOP_ADMITTING_NEW_WORK",
      "QUIESCE_IN_FLIGHT_UNDER_C02_LEASE",
      "GRACEFUL_EXIT_FOR_RESTART",
    ]);
    expect(SHUTDOWN_INVARIANTS.in_flight_completes_under_c02_lease).toBe(true);
    expect(SHUTDOWN_INVARIANTS.never_force_releases_lease).toBe(true);
    expect(SHUTDOWN_INVARIANTS.never_second_authority).toBe(true);
  });

  it("the frozen sequences pass their verifiers", () => {
    expect(verifyStartupSequence([...ENGINE_STARTUP_SEQUENCE])).toEqual([]);
    expect(verifyShutdownSequence([...LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE])).toEqual([]);
  });

  it("rejects a startup sequence that arms the signer before the engines run (negative path)", () => {
    const bad = ["REBUILD_QUEUES", "ARM_SIGNER_AUTHORITY", "START_MUTATION_WORKERS"];
    expect(verifyStartupSequence(bad)).toContain("SIGNER_AUTHORITY_NOT_LAST");
  });

  it("rejects a startup sequence with mutation workers before the queue rebuild (negative path)", () => {
    const bad = ["START_MUTATION_WORKERS", "REBUILD_QUEUES", "ARM_SIGNER_AUTHORITY"];
    expect(verifyStartupSequence(bad)).toContain("MUTATION_WORKERS_BEFORE_QUEUE_REBUILD");
  });

  it("rejects a shutdown sequence that does not mark leadership lost first (negative path)", () => {
    const bad = ["STOP_ADMITTING_NEW_WORK", "MARK_LEADERSHIP_LOST", "GRACEFUL_EXIT_FOR_RESTART"];
    expect(verifyShutdownSequence(bad)).toContain("MARK_LOST_NOT_FIRST");
  });
});
