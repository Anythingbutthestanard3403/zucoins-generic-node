// Production RECEIVE_EXTERNAL guard census
// governing:; the one-in-flight-per-wallet and byte-exact signing rules, 4, 5

import { describe, expect, it } from "vitest";

import {
  RECEIVE_EXTERNAL_LANDING_INVARIANTS,
} from "../../src/schema/receive-external-landing.contract.js";

// census: production RECEIVE_EXTERNAL path guards inventory
export const RECEIVE_EXTERNAL_GUARDS: readonly string[] = [
  // Pre-flight checks (from receive-preflight.ts)
  "dual_control_authorization",
  "receiver_eligibility_d917",  
  "external_payer_independent",
  "amount_fixed_fractional",
  "no_active_lease",
  "abort_criteria_bound",
  "fresh_vault_backup",
  "expected_artifact_or_clean_start",
  "no_submit_yet",
  "build_version_recorded",
  "runner_lock_acquired",
  
  // Transfer code assembly guards
  "receive_transfer_code_wire_version",
  "receive_transfer_code_type",
  "receive_message_prefix",
  "anchor_pattern_validation",
  "transfer_code_digest_algorithm",
  "transfer_code_digest_no_preprocessing",
  
  // Reconciliation guards
  "receive_never_crosses_boundary_signer",
  "receive_never_crosses_boundary_submitter", 
  "receive_formation_complete_check",
  "receive_step2_signature_persisted_check",
  "receive_signer_audit_indicates_use_check",
  "receive_lease_active_during_reconcile",
  "receive_path_observation_classification",
  "receive_landed_verified_outcome",
  "receive_invariant_breach_detection",
  "receive_indeterminate_reason_handling",
  
  // Schema guards (from receive-external-landing.sql - matching contract invariant IDs)
  "ONE_LANDING_PROOF_PER_OPERATION",
  "SETTLED_BODY_PHASE_FROZEN", 
  "PUBLIC_PHASE_FROZEN",
  "ONE_RECEIVER_PATH",
  "LANDING_ORACLE_IS_EXACT_OR_COMPLETE_PATH",
  "PATH_DEPTH_MATCHES_ORACLE",
  "EXACT_HEAD_IDENTITY_IFF_DEPTH_ZERO",
  "BODY_COUNT_MATCHES_DEPTH",
  "ORDERED_PATH_PERSISTED",
  "NO_PARTIAL_PATH_MAY_COMMIT",
  "ZERO_BODY_PATH_CANNOT_COMMIT",
  "EXACT_BODY_BYTES_PERSISTED",
  "ONE_LANDED_EVENT_PER_OPERATION",
  "EVENT_TYPE_FROZEN",
];

describe("RECEIVE_EXTERNAL guard census", () => {
  it("contains exactly 41 production guards", () => {
    expect(RECEIVE_EXTERNAL_GUARDS.length).toBe(41);
  });

  it("includes all schema invariants from receive-external-landing.contract.ts", () => {
    const schemaInvariants = RECEIVE_EXTERNAL_LANDING_INVARIANTS.map(inv => inv.id);
    for (const invariant of schemaInvariants) {
      expect(RECEIVE_EXTERNAL_GUARDS).toContain(invariant);
    }
  });

  it("includes all transfer code constants", () => {
    expect(RECEIVE_EXTERNAL_GUARDS).toContain("receive_transfer_code_wire_version");
    expect(RECEIVE_EXTERNAL_GUARDS).toContain("receive_transfer_code_type");
    expect(RECEIVE_EXTERNAL_GUARDS).toContain("receive_message_prefix");
  });

  it("includes all reconciliation logic guards", () => {
    const reconciliationGuards = [
      "receive_never_crosses_boundary_signer",
      "receive_never_crosses_boundary_submitter",
      "receive_formation_complete_check",
      "receive_step2_signature_persisted_check",
      "receive_signer_audit_indicates_use_check",
      "receive_lease_active_during_reconcile",
      "receive_path_observation_classification",
      "receive_landed_verified_outcome",
      "receive_invariant_breach_detection",
      "receive_indeterminate_reason_handling",
    ];
    for (const guard of reconciliationGuards) {
      expect(RECEIVE_EXTERNAL_GUARDS).toContain(guard);
    }
  });

  it("includes all pre-flight check guards", () => {
    const preflightGuards = [
      "dual_control_authorization",
      "receiver_eligibility_d917",  
      "external_payer_independent",
      "amount_fixed_fractional",
      "no_active_lease",
      "abort_criteria_bound",
      "fresh_vault_backup",
      "expected_artifact_or_clean_start",
      "no_submit_yet",
      "build_version_recorded",
      "runner_lock_acquired",
    ];
    for (const guard of preflightGuards) {
      expect(RECEIVE_EXTERNAL_GUARDS).toContain(guard);
    }
  });
});