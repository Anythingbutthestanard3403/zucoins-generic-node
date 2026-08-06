/**
 * SOURCE: the node-core runtime component table ("all money engines run under one
 * process-wide signer leadership lock in addition to wallet leases") + the startup-sequence decision
 * (startMoneyEngines runs only on the lock holder; request-driven signers refuse on a non-holder)
 * + the operations-recovery leadership rule (no alternate instance signs unless it holds process
 * leadership). Consumes the named concern operation vocabulary.
 *
 * the named concern freezes the engine registry: every node engine/worker classified as leader-gated or
 * follower-safe, as data. `economicStateWriter` means it writes custody/economic state — leases,
 * wallet state, signatures, submissions, minted keys — the class the leadership lock serialises.
 * Queue admission, observation appends, and event/report reads are NOT economic-state writes.
 */

import { type NodeOperationClass } from "../readiness/index.ts";

export type LeadershipRequirement = "LEADER_REQUIRED" | "FOLLOWER_SAFE";

export interface NodeEngine {
  readonly id: string;
  readonly leadershipRequirement: LeadershipRequirement;
  readonly economicStateWriter: boolean;
  readonly followerAllowedOperations: readonly NodeOperationClass[];
}

/**
 * Every leader-gated engine is an economic-state writer with no follower operations: on a
 * non-leader it does not run at all. Every follower-safe engine is not an economic-state writer
 * and names the non-economic operation classes it may run without leadership.
 */
export const ENGINE_REGISTRY = [
  {
    id: "SIGNER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "SUBMITTER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "RECEIVE_EXECUTION_WORKER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "INTERNAL_MOVE_WORKER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "EXTERNAL_SEND_WORKER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "POOL_MINT_WORKER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "RECONCILER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "VAULT_ROTATION_WORKER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "SETTLEMENT_MONITOR",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "BOOT_RECOVERY_CLASSIFIER",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "OPERATOR_MUTATION_SERVICE",
    leadershipRequirement: "LEADER_REQUIRED",
    economicStateWriter: true,
    followerAllowedOperations: [],
  },
  {
    id: "API_INGRESS",
    leadershipRequirement: "FOLLOWER_SAFE",
    economicStateWriter: false,
    followerAllowedOperations: ["ADMIT_BOUNDED_QUEUE", "SERVE_ADMIN_QUERIES"],
  },
  {
    id: "OBSERVATION_SERVICE",
    leadershipRequirement: "FOLLOWER_SAFE",
    economicStateWriter: false,
    followerAllowedOperations: ["SERVE_READS"],
  },
  {
    id: "REPORTING_SERVICE",
    leadershipRequirement: "FOLLOWER_SAFE",
    economicStateWriter: false,
    followerAllowedOperations: ["SERVE_READS", "SERVE_ADMIN_QUERIES"],
  },
  {
    id: "EXACT_PARTIAL_SERVER",
    leadershipRequirement: "FOLLOWER_SAFE",
    economicStateWriter: false,
    followerAllowedOperations: ["SERVE_EXACT_PARTIAL"],
  },
  {
    id: "HEALTH_REPORTER",
    leadershipRequirement: "FOLLOWER_SAFE",
    economicStateWriter: false,
    followerAllowedOperations: ["REPORT_HEALTH"],
  },
] as const satisfies readonly NodeEngine[];

export type NodeEngineId = (typeof ENGINE_REGISTRY)[number]["id"];

export const LEADER_GATED_ENGINE_IDS = ENGINE_REGISTRY.filter(
  (engine) => engine.leadershipRequirement === "LEADER_REQUIRED",
).map((engine) => engine.id) as readonly NodeEngineId[];

export const FOLLOWER_SAFE_ENGINE_IDS = ENGINE_REGISTRY.filter(
  (engine) => engine.leadershipRequirement === "FOLLOWER_SAFE",
).map((engine) => engine.id) as readonly NodeEngineId[];
