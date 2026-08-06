import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  BOOT_SEQUENCE,
  LEADERSHIP_PREREQUISITE_SEQUENCE,
  BOOT_SEQUENCE_INVARIANTS,
  SHUTDOWN_SEQUENCE,
  SHUTDOWN_SEQUENCE_INVARIANTS,
} from "./boot-sequence.contract.ts";
import { verifyBootSequence, verifyShutdownSequence } from "./verifiers.ts";

describe("boot sequence is frozen; leadership follows the vault census (the readiness concern)", () => {
  it("freezes the stage sequence", () => {
    assertFieldOrder(BOOT_SEQUENCE, [
      "SCHEMA_VALIDATE",
      "VAULT_KEY_RING_LOAD",
      "VAULT_CENSUS_VERIFY",
      "LEADERSHIP_ACQUIRE",
      "BOOT_RECOVERY_CLASSIFY",
      "ENGINE_ACTIVATION",
    ]);
  });

  it("freezes the key-ring -> census -> leadership prerequisite chain", () => {
    assertFieldOrder(LEADERSHIP_PREREQUISITE_SEQUENCE, [
      "VAULT_KEY_RING_LOAD",
      "VAULT_CENSUS_VERIFY",
      "LEADERSHIP_ACQUIRE",
    ]);
  });

  it("readiness is reachable before leadership and signer authority flips last (the readiness-leadership decoupling rule)", () => {
    expect(BOOT_SEQUENCE_INVARIANTS.readiness_reachable_before_leadership).toBe(true);
    expect(BOOT_SEQUENCE_INVARIANTS.signer_authority_active_last).toBe(true);
    expect(BOOT_SEQUENCE_INVARIANTS.leadership_acquire_after_vault_census).toBe(true);
    expect(BOOT_SEQUENCE_INVARIANTS.vault_census_after_key_ring_load).toBe(true);
    expect(BOOT_SEQUENCE_INVARIANTS.engine_activation_after_leadership).toBe(true);
  });

  it("the frozen sequence passes its own verifier", () => {
    expect(verifyBootSequence([...BOOT_SEQUENCE])).toEqual([]);
  });

  it("rejects a sequence that claims leadership before the vault census (negative path)", () => {
    const bad = [
      "SCHEMA_VALIDATE",
      "VAULT_KEY_RING_LOAD",
      "LEADERSHIP_ACQUIRE",
      "VAULT_CENSUS_VERIFY",
      "ENGINE_ACTIVATION",
    ];
    expect(verifyBootSequence(bad)).toContain("LEADERSHIP_BEFORE_VAULT_CENSUS");
  });

  it("rejects a sequence missing a prerequisite stage (negative path)", () => {
    expect(verifyBootSequence(["SCHEMA_VALIDATE", "LEADERSHIP_ACQUIRE"])).toContain(
      "MISSING_PREREQUISITE_STAGE",
    );
  });

  it("rejects a vault stage running before schema validation (negative path)", () => {
    const bad = [
      "VAULT_KEY_RING_LOAD",
      "SCHEMA_VALIDATE",
      "VAULT_CENSUS_VERIFY",
      "LEADERSHIP_ACQUIRE",
    ];
    expect(verifyBootSequence(bad)).toContain("VAULT_BEFORE_SCHEMA_VALIDATE");
  });

  it("rejects a duplicated boot stage instead of matching only its first copy (negative path)", () => {
    const bad = [
      "SCHEMA_VALIDATE",
      "VAULT_KEY_RING_LOAD",
      "VAULT_CENSUS_VERIFY",
      "VAULT_CENSUS_VERIFY",
      "LEADERSHIP_ACQUIRE",
    ];
    expect(verifyBootSequence(bad)).toContain("DUPLICATE_LIFECYCLE_STAGE");
  });
});

describe("shutdown sequence releases the leadership lock last (the readiness concern)", () => {
  it("freezes the shutdown stage sequence", () => {
    assertFieldOrder(SHUTDOWN_SEQUENCE, [
      "SIGNER_AUTHORITY_WITHDRAW",
      "ENGINE_QUIESCE",
      "INFLIGHT_SIGNING_COMPLETE",
      "LEADERSHIP_RELEASE",
    ]);
  });

  it("withdraws signer authority first and releases the leadership lock last", () => {
    expect(SHUTDOWN_SEQUENCE_INVARIANTS.signer_authority_withdrawn_first).toBe(true);
    expect(SHUTDOWN_SEQUENCE_INVARIANTS.leadership_release_is_last).toBe(true);
    expect(SHUTDOWN_SEQUENCE_INVARIANTS.engines_quiesce_before_inflight_signing_completes).toBe(
      true,
    );
    expect(SHUTDOWN_SEQUENCE_INVARIANTS.inflight_signing_completes_before_leadership_release).toBe(
      true,
    );
  });

  it("the frozen shutdown sequence passes its own verifier", () => {
    expect(verifyShutdownSequence([...SHUTDOWN_SEQUENCE])).toEqual([]);
  });

  it("rejects releasing the leadership lock before in-flight signing completes (negative path)", () => {
    const bad = [
      "SIGNER_AUTHORITY_WITHDRAW",
      "ENGINE_QUIESCE",
      "LEADERSHIP_RELEASE",
      "INFLIGHT_SIGNING_COMPLETE",
    ];
    expect(verifyShutdownSequence(bad)).toContain(
      "LEADERSHIP_RELEASE_BEFORE_INFLIGHT_SIGNING_COMPLETE",
    );
  });

  it("rejects releasing the leadership lock while signer authority is still held (negative path)", () => {
    const bad = [
      "LEADERSHIP_RELEASE",
      "SIGNER_AUTHORITY_WITHDRAW",
      "ENGINE_QUIESCE",
      "INFLIGHT_SIGNING_COMPLETE",
    ];
    expect(verifyShutdownSequence(bad)).toContain("LEADERSHIP_RELEASE_BEFORE_AUTHORITY_WITHDRAW");
  });

  it("rejects a shutdown sequence missing a stage (negative path)", () => {
    expect(verifyShutdownSequence(["SIGNER_AUTHORITY_WITHDRAW", "LEADERSHIP_RELEASE"])).toContain(
      "MISSING_PREREQUISITE_STAGE",
    );
  });
});
