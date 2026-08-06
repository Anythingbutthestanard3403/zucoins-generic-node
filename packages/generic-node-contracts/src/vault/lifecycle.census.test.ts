import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  ROTATION_STATES,
  ROTATION_TRANSITIONS,
  ROTATION_INVARIANTS,
  SIGNING_CONCURRENCY,
  RECOVERY,
} from "./lifecycle.contract.ts";

describe("rotation, concurrency, and recovery are frozen (the vault model freeze; the vault-storage rule guards 3-4)", () => {
  it("rotation states and transition edges in sequence", () => {
    assertFieldOrder(ROTATION_STATES, ["STABLE", "ROTATING", "ROTATION_COMPLETE"]);
    assertFieldOrder(
      ROTATION_TRANSITIONS.map((transition) => [transition.from, transition.to]),
      [
        ["STABLE", "ROTATING"],
        ["ROTATING", "ROTATING"],
        ["ROTATING", "ROTATION_COMPLETE"],
        ["ROTATION_COMPLETE", "STABLE"],
      ],
    );
  });

  it("crash-safe resumable rotation invariants", () => {
    expect(ROTATION_INVARIANTS).toEqual({
      crash_safe_resumable: true,
      old_key_retained_until_committed_marker: true,
      boot_reads_mixed_version_via_key_ring: true,
      unreadable_or_failed_pubkey_row_aborts_without_advancing_writer_version: true,
      old_ciphertext_gc_only_post_complete: true,
    });
  });

  it("signing holds no vault row lock; the lease is the sole wallet-sequencing authority", () => {
    expect(SIGNING_CONCURRENCY.vault_row_lock_held_across_signing).toBe(false);
    expect(SIGNING_CONCURRENCY.vault_read_access).toBe("READ_ONLY_BY_PRIMARY_KEY");
    expect(SIGNING_CONCURRENCY.wallet_ordering_authority).toBe("C-02_UNIVERSAL_LEASE");
  });

  it("recovery is per-wallet, monotonic, never cleared by rotation; no in-place replacement", () => {
    expect(RECOVERY.recovery_verified_at_scope).toBe("PER_WALLET");
    expect(RECOVERY.monotonic).toBe(true);
    expect(RECOVERY.cleared_by_rotation).toBe(false);
    expect(RECOVERY.key_replacement_in_place).toBe(false);
  });

  it("no rotation edge advances the writer version on a failed row (negative)", () => {
    expect(
      ROTATION_INVARIANTS.unreadable_or_failed_pubkey_row_aborts_without_advancing_writer_version,
    ).toBe(true);
    expect(ROTATION_INVARIANTS.old_ciphertext_gc_only_post_complete).toBe(true);
  });
});
