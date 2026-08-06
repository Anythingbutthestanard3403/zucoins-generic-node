import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import {
  ENGINE_REGISTRY,
  LEADER_GATED_ENGINE_IDS,
  FOLLOWER_SAFE_ENGINE_IDS,
  type NodeEngine,
} from "./engines.contract.ts";
import { verifyEngineRegistry, FOLLOWER_ALLOWED_OPERATIONS } from "./verifiers.ts";

describe("engine registry is frozen and split-brain-consistent (runtime-component table / startup-sequence decision)", () => {
  it("the frozen registry conforms to its own verifier", () => {
    expect(verifyEngineRegistry(ENGINE_REGISTRY)).toEqual([]);
  });

  it("leader-gated iff economic-state writer; follower-safe iff not", () => {
    for (const engine of ENGINE_REGISTRY) {
      const leaderGated = engine.leadershipRequirement === "LEADER_REQUIRED";
      expect(leaderGated).toBe(engine.economicStateWriter);
    }
    expect(LEADER_GATED_ENGINE_IDS).toContain("SIGNER");
    expect(LEADER_GATED_ENGINE_IDS).toContain("SUBMITTER");
    expect(FOLLOWER_SAFE_ENGINE_IDS).toContain("OBSERVATION_SERVICE");
    expect(FOLLOWER_SAFE_ENGINE_IDS).toContain("HEALTH_REPORTER");
  });

  it("the registry is the exact closed set of 16 engines, not a superset or subset", () => {
    assertClosedSet(
      ENGINE_REGISTRY.map((engine) => engine.id),
      [
        "SIGNER",
        "SUBMITTER",
        "RECEIVE_EXECUTION_WORKER",
        "INTERNAL_MOVE_WORKER",
        "EXTERNAL_SEND_WORKER",
        "POOL_MINT_WORKER",
        "RECONCILER",
        "VAULT_ROTATION_WORKER",
        "SETTLEMENT_MONITOR",
        "BOOT_RECOVERY_CLASSIFIER",
        "OPERATOR_MUTATION_SERVICE",
        "API_INGRESS",
        "OBSERVATION_SERVICE",
        "REPORTING_SERVICE",
        "EXACT_PARTIAL_SERVER",
        "HEALTH_REPORTER",
      ],
    );
  });

  it("LEADER_GATED_ENGINE_IDS is the exact closed set of the 11 leader-gated money engines", () => {
    assertClosedSet(LEADER_GATED_ENGINE_IDS, [
      "SIGNER",
      "SUBMITTER",
      "RECEIVE_EXECUTION_WORKER",
      "INTERNAL_MOVE_WORKER",
      "EXTERNAL_SEND_WORKER",
      "POOL_MINT_WORKER",
      "RECONCILER",
      "VAULT_ROTATION_WORKER",
      "SETTLEMENT_MONITOR",
      "BOOT_RECOVERY_CLASSIFIER",
      "OPERATOR_MUTATION_SERVICE",
    ]);
  });

  it("FOLLOWER_SAFE_ENGINE_IDS is the exact closed set of the 5 follower-safe engines", () => {
    assertClosedSet(FOLLOWER_SAFE_ENGINE_IDS, [
      "API_INGRESS",
      "OBSERVATION_SERVICE",
      "REPORTING_SERVICE",
      "EXACT_PARTIAL_SERVER",
      "HEALTH_REPORTER",
    ]);
  });

  it("every follower engine claims only operations the follower mode permits", () => {
    const allowed = new Set<string>(FOLLOWER_ALLOWED_OPERATIONS);
    for (const engine of ENGINE_REGISTRY) {
      if (engine.leadershipRequirement !== "FOLLOWER_SAFE") continue;
      expect(engine.followerAllowedOperations.length).toBeGreaterThan(0);
      for (const op of engine.followerAllowedOperations) {
        expect(allowed.has(op)).toBe(true);
      }
    }
  });

  it("no leader-gated engine exposes any follower operation", () => {
    for (const engine of ENGINE_REGISTRY) {
      if (engine.leadershipRequirement !== "LEADER_REQUIRED") continue;
      expect(engine.followerAllowedOperations).toEqual([]);
    }
  });

  it("rejects a follower-safe engine marked as an economic writer (negative path)", () => {
    const bad: NodeEngine = {
      id: "ROGUE_FOLLOWER",
      leadershipRequirement: "FOLLOWER_SAFE",
      economicStateWriter: true,
      followerAllowedOperations: ["SERVE_READS"],
    };
    expect(verifyEngineRegistry([bad])).toContain("FOLLOWER_ENGINE_MARKED_ECONOMIC_WRITER");
  });

  it("rejects a leader-gated engine that exposes follower operations (negative path)", () => {
    const bad: NodeEngine = {
      id: "LEAKY_LEADER",
      leadershipRequirement: "LEADER_REQUIRED",
      economicStateWriter: true,
      followerAllowedOperations: ["SERVE_READS"],
    };
    expect(verifyEngineRegistry([bad])).toContain("LEADER_ENGINE_HAS_FOLLOWER_OPERATIONS");
  });

  it("rejects a follower engine claiming an operation outside the allowed set (negative path)", () => {
    const bad: NodeEngine = {
      id: "OVERREACH_FOLLOWER",
      leadershipRequirement: "FOLLOWER_SAFE",
      economicStateWriter: false,
      followerAllowedOperations: ["SIGN"],
    };
    expect(verifyEngineRegistry([bad])).toContain("FOLLOWER_OPERATION_OUTSIDE_ALLOWED_SET");
  });
});
