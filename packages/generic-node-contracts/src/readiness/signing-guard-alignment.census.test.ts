import { describe, expect, it } from "vitest";

import { NODE_MODES } from "./degraded-modes.contract.ts";
import { classifyMode } from "./verifiers.ts";
import {
  type NodeReadinessState,
  evaluateReadiness,
  hasSignerLeadership,
  maySign,
} from "./predicates.ts";

/** Every state field a gating readiness check reads; `vault_available` contributes two. */
const READINESS_GATING_LEVERS = [
  "schemaMigrated",
  "databaseReachable",
  "vaultKeyRingLoaded",
  "vaultCensusVerified",
  "observationReadCapable",
] as const satisfies readonly (keyof NodeReadinessState)[];

type ReadinessGatingLever = (typeof READINESS_GATING_LEVERS)[number];

/**
 * The subset of gating levers that feed only `evaluateReadiness`, not `hasSignerLeadership` too.
 * The vault fields are excluded here: `hasSignerLeadership` also requires
 * `vaultKeyRingLoaded && vaultCensusVerified` (predicates.ts), so forcing either one false
 * necessarily collapses actual leadership to false regardless of `leadershipLockHeld` — that's
 * correct product behavior (leadership genuinely requires the vault), but it means `stateFor`
 * cannot produce a (ready: false, leader: true) pair for a vault lever, so those two levers are
 * verified only via the maySign alignment below, not via this exact-pair invariant.
 */
const READINESS_ONLY_GATING_LEVERS = [
  "schemaMigrated",
  "databaseReachable",
  "observationReadCapable",
] as const satisfies readonly ReadinessGatingLever[];

const ALL_GATING_TRUE: NodeReadinessState = {
  schemaMigrated: true,
  databaseReachable: true,
  vaultKeyRingLoaded: true,
  vaultCensusVerified: true,
  observationReadCapable: true,
  leadershipLockHeld: true,
};

/**
 * Builds a state producing exactly (evaluateReadiness().ready === ready, hasSignerLeadership() ===
 * leader) by toggling exactly one gating field (`lever`, defaulting to `databaseReachable`); every
 * other gating field stays healthy so it confounds neither axis. `leadershipLockHeld` is the sole
 * leadership lever. Parametrizing over every lever proves the SIGN alignment holds no matter which
 * gating dependency is the one that failed, not only the database.
 */
const stateFor = (
  ready: boolean,
  leader: boolean,
  lever: ReadinessGatingLever = "databaseReachable",
): NodeReadinessState => ({
  ...ALL_GATING_TRUE,
  [lever]: ready,
  leadershipLockHeld: leader,
});

const READINESS_LEADERSHIP_PAIRS: readonly (readonly [boolean, boolean])[] = [
  [true, true],
  [true, false],
  [false, true],
  [false, false],
];

describe("signing guard is aligned with the frozen degraded-modes table (the readiness concern)", () => {
  it.each(READINESS_ONLY_GATING_LEVERS)(
    "stateFor produces exactly the requested readiness and leadership verdicts via %s",
    (lever) => {
      for (const [ready, leader] of READINESS_LEADERSHIP_PAIRS) {
        const state = stateFor(ready, leader, lever);
        expect(evaluateReadiness(state).ready).toBe(ready);
        expect(hasSignerLeadership(state)).toBe(leader);
      }
    },
  );

  it.each(READINESS_GATING_LEVERS)(
    "maySign matches each mode's frozen SIGN allowance for every readiness x leadership pair via %s",
    (lever) => {
      for (const [ready, leader] of READINESS_LEADERSHIP_PAIRS) {
        const mode = NODE_MODES.find((candidate) => candidate.id === classifyMode(ready, leader));
        expect(mode).toBeDefined();
        const allowed: readonly string[] = mode?.allowed ?? [];
        expect(allowed.includes("SIGN")).toBe(maySign(stateFor(ready, leader, lever)));
      }
    },
  );

  it("a leader whose gating readiness dependency failed may not sign (the LEADER_NOT_READY hole)", () => {
    const leaderNotReady = stateFor(false, true);
    expect(classifyMode(false, true)).toBe("LEADER_NOT_READY");
    expect(hasSignerLeadership(leaderNotReady)).toBe(true);
    expect(maySign(leaderNotReady)).toBe(false);
  });
});
