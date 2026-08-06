import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import { LEADERSHIP_RULES, SIGNING_CONCURRENCY } from "../vault/index.ts";
import {
  WALLET_SEQUENCING_AUTHORITY,
  CONSUMED_VAULT_LEADERSHIP,
  FAIL_CLOSED_RULES,
  LEADERSHIP_LOSS_HANDLING,
  LEADERSHIP_LOCK_EXIT,
} from "./fail-closed.contract.ts";
import { verifyWalletSequencingAuthority } from "./verifiers.ts";

describe("fail-closed rules and the single wallet sequencing authority (the readiness concern)", () => {
  it("the wallet sequencing authority is the vault's frozen C-02 lease, not a new one", () => {
    expect(WALLET_SEQUENCING_AUTHORITY).toBe("C-02_UNIVERSAL_LEASE");
    expect(WALLET_SEQUENCING_AUTHORITY).toBe(LEADERSHIP_RULES.wallet_ordering_authority);
  });

  it("consumes the vault leadership facts rather than restating them", () => {
    expect(CONSUMED_VAULT_LEADERSHIP.mutations_single_writer).toBe(
      LEADERSHIP_RULES.mutations_single_writer,
    );
    expect(CONSUMED_VAULT_LEADERSHIP.rotation_is_sole_all_envelope_writer).toBe(
      LEADERSHIP_RULES.rotation_is_sole_all_envelope_writer,
    );
    expect(CONSUMED_VAULT_LEADERSHIP.no_hybrid_fallback).toBe(LEADERSHIP_RULES.no_hybrid_fallback);
    expect(CONSUMED_VAULT_LEADERSHIP.vault_row_lock_held_across_signing).toBe(
      SIGNING_CONCURRENCY.vault_row_lock_held_across_signing,
    );
    expect(CONSUMED_VAULT_LEADERSHIP.vault_row_lock_held_across_signing).toBe(false);
  });

  it("freezes the fail-closed rule set including the node-level separation and lock-exit rules", () => {
    const ids = FAIL_CLOSED_RULES.map((entry) => entry.id);
    assertClosedSet(ids, [
      "NO_SIGNING_WITHOUT_LEADERSHIP",
      "NO_LEADERSHIP_WITHOUT_VAULT_CENSUS",
      "LEADERSHIP_LOSS_QUIESCES_SIGNING",
      "LEADERSHIP_IS_NODE_LEVEL_NOT_WALLET_SEQUENCING",
      "LEADERSHIP_LOCK_RELEASED_ON_GRACEFUL_SHUTDOWN",
      "INVOLUNTARY_LEADERSHIP_LOSS_FAILS_CLOSED",
    ]);
  });

  it("leadership loss quiesces signing but never releases or re-sequences leases", () => {
    expect(LEADERSHIP_LOSS_HANDLING.quiesces_signing).toBe(true);
    expect(LEADERSHIP_LOSS_HANDLING.releases_wallet_leases).toBe(false);
    expect(LEADERSHIP_LOSS_HANDLING.re_sequences_wallet_leases).toBe(false);
    expect(LEADERSHIP_LOSS_HANDLING.db_single_in_flight_is_backstop).toBe(true);
  });

  it("releases the leadership lock last on graceful shutdown and never continues signing after loss", () => {
    expect(LEADERSHIP_LOCK_EXIT.released_on_graceful_shutdown).toBe(true);
    expect(LEADERSHIP_LOCK_EXIT.released_after_signing_quiesced).toBe(true);
    expect(LEADERSHIP_LOCK_EXIT.continues_signing_after_loss).toBe(false);
    expect(LEADERSHIP_LOCK_EXIT.restarts_to_reacquire_after_loss).toBe(true);
  });

  it("leadership lock exit never releases or re-sequences wallet leases; the DB backstops the loss window", () => {
    expect(LEADERSHIP_LOCK_EXIT.releases_or_resequences_wallet_leases_on_exit).toBe(false);
    expect(LEADERSHIP_LOCK_EXIT.db_single_in_flight_backstops_loss_window).toBe(true);
  });

  it("the frozen C-02 authority passes its verifier", () => {
    expect(verifyWalletSequencingAuthority(WALLET_SEQUENCING_AUTHORITY)).toEqual([]);
  });

  it("a second wallet sequencing authority is rejected (negative path)", () => {
    expect(verifyWalletSequencingAuthority("SIGNER_LEADERSHIP")).toContain(
      "SECOND_WALLET_SEQUENCING_AUTHORITY",
    );
    expect(verifyWalletSequencingAuthority("READINESS_GATE")).toContain(
      "SECOND_WALLET_SEQUENCING_AUTHORITY",
    );
  });
});
