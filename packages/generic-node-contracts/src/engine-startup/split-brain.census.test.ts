import { describe, expect, it } from "vitest";

import { WALLET_SEQUENCING_AUTHORITY } from "../readiness/index.ts";
import { NO_SPLIT_BRAIN_INVARIANT, TAKEOVER_BOUNDARY } from "./split-brain.contract.ts";
import { verifyTakeover } from "./verifiers.ts";

describe("no-split-brain invariant and takeover boundary (the named concern; the frozen rule / the vault-storage rule)", () => {
  it("binds the wallet sequencing authority to the named concern / vault C-02 value, not a new one", () => {
    expect(NO_SPLIT_BRAIN_INVARIANT.wallet_sequencing_authority).toBe(WALLET_SEQUENCING_AUTHORITY);
    expect(NO_SPLIT_BRAIN_INVARIANT.wallet_sequencing_authority).toBe("C-02_UNIVERSAL_LEASE");
  });

  it("freezes the two safety layers: the leadership gate and the DB backstop", () => {
    expect(NO_SPLIT_BRAIN_INVARIANT.at_most_one_leader_holds_lock).toBe(true);
    expect(NO_SPLIT_BRAIN_INVARIANT.follower_leader_gated_engines_cannot_economic_write).toBe(true);
    expect(NO_SPLIT_BRAIN_INVARIANT.db_single_in_flight_per_wallet_backstop).toBe(true);
  });

  it("freezes the takeover boundary: old quiesces before new arms; authority armed last", () => {
    expect(TAKEOVER_BOUNDARY.old_leader_quiesces_before_new_acquires_lock).toBe(true);
    expect(TAKEOVER_BOUNDARY.lock_is_the_single_serialisation_point).toBe(true);
    expect(TAKEOVER_BOUNDARY.new_leader_runs_boot_recovery_before_engines).toBe(true);
    expect(TAKEOVER_BOUNDARY.new_leader_arms_authority_last).toBe(true);
  });

  it("a clean handoff (old quiesced, new arms) passes the takeover verifier", () => {
    expect(verifyTakeover(true, true)).toEqual([]);
    expect(verifyTakeover(true, false)).toEqual([]);
    expect(verifyTakeover(false, false)).toEqual([]);
  });

  it("a new leader arming before the old quiesced is rejected (negative path)", () => {
    expect(verifyTakeover(false, true)).toContain("NEW_LEADER_ARMED_BEFORE_OLD_QUIESCED");
  });
});
