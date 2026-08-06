/**
 * SOURCE: derived from this concern's frozen contracts (engines, startup-sequence, split-brain)
 * + the startup-sequence decision. Pure conformance verifiers returning the frozen violation ids a
 * candidate commits. The follower operation universe is consumed from the named concern's READY_NOT_LEADER
 * mode, so a follower engine may only claim operations that mode already permits.
 */

import { NODE_MODES, type NodeMode } from "../readiness/index.ts";
import { type NodeEngine } from "./engines.contract.ts";

const readyNotLeader: NodeMode | undefined = (NODE_MODES as readonly NodeMode[]).find(
  (mode) => mode.id === "READY_NOT_LEADER",
);

/** The operation classes a non-leader instance may run, from the named concern degraded-mode contract.*/
export const FOLLOWER_ALLOWED_OPERATIONS: readonly string[] = readyNotLeader?.allowed ?? [];

/**
 * The registry conforms only when every leader-gated engine is an economic-state writer with no
 * follower operations, and every follower-safe engine is not an economic-state writer, names at
 * least one follower operation, and claims only operations the follower mode permits.
 */
export const verifyEngineRegistry = (engines: readonly NodeEngine[]): readonly string[] => {
  const violations = new Set<string>();
  const allowed = new Set<string>(FOLLOWER_ALLOWED_OPERATIONS);
  for (const engine of engines) {
    if (engine.leadershipRequirement === "LEADER_REQUIRED") {
      if (!engine.economicStateWriter) violations.add("LEADER_ENGINE_NOT_ECONOMIC_WRITER");
      if (engine.followerAllowedOperations.length > 0) {
        violations.add("LEADER_ENGINE_HAS_FOLLOWER_OPERATIONS");
      }
    } else {
      if (engine.economicStateWriter) violations.add("FOLLOWER_ENGINE_MARKED_ECONOMIC_WRITER");
      if (engine.followerAllowedOperations.length === 0) {
        violations.add("FOLLOWER_ENGINE_HAS_NO_OPERATIONS");
      }
      for (const op of engine.followerAllowedOperations) {
        if (!allowed.has(op)) violations.add("FOLLOWER_OPERATION_OUTSIDE_ALLOWED_SET");
      }
    }
  }
  return [...violations];
};

/**
 * The startup sub-sequence conforms only when the queues are rebuilt before the mutation workers
 * start and ARM_SIGNER_AUTHORITY is the final stage. Arming the signer before the engines run is
 * the exact regression this must catch (the frozen rule flips authority last).
 */
export const verifyStartupSequence = (sequence: readonly string[]): readonly string[] => {
  const violations: string[] = [];
  const arm = sequence.indexOf("ARM_SIGNER_AUTHORITY");
  const rebuild = sequence.indexOf("REBUILD_QUEUES");
  const workers = sequence.indexOf("START_MUTATION_WORKERS");
  if (arm < 0) return ["MISSING_ARM_SIGNER_AUTHORITY"];
  if (arm !== sequence.length - 1) violations.push("SIGNER_AUTHORITY_NOT_LAST");
  if (rebuild < 0 || workers < 0 || !(rebuild < workers)) {
    violations.push("MUTATION_WORKERS_BEFORE_QUEUE_REBUILD");
  }
  return violations;
};

/**
 * The shutdown sub-sequence conforms only when leadership loss is marked first and the graceful
 * exit is last. Anything that acts before marking loss keeps a lost leader writing.
 */
export const verifyShutdownSequence = (sequence: readonly string[]): readonly string[] => {
  const violations: string[] = [];
  if (sequence[0] !== "MARK_LEADERSHIP_LOST") violations.push("MARK_LOST_NOT_FIRST");
  if (sequence[sequence.length - 1] !== "GRACEFUL_EXIT_FOR_RESTART") {
    violations.push("GRACEFUL_EXIT_NOT_LAST");
  }
  return violations;
};

/**
 * The takeover boundary conforms only when the new leader has not armed its authority while the
 * old leader has not yet quiesced. A new leader armed before the old quiesced is the split-brain
 * window this must reject.
 */
export const verifyTakeover = (oldQuiesced: boolean, newArmed: boolean): readonly string[] =>
  newArmed && !oldQuiesced ? ["NEW_LEADER_ARMED_BEFORE_OLD_QUIESCED"] : [];
