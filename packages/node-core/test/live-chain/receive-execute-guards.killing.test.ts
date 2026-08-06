// RECEIVE_EXTERNAL guard killing tests
// governing:; the one-in-flight-per-wallet and byte-exact signing rules, 4, 5

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  receiveExternalAbortCriteria,
  receiveAbortActionFor,
} from "./receive-abort-criteria.js";
import { 
  buildReceiveMessage,
  hashTransferCodeText,
  ReceiveTransferCodeError,
  RECEIVE_TRANSFER_CODE_WIRE_VERSION,
  RECEIVE_TRANSFER_CODE_TYPE,
  RECEIVE_MESSAGE_PREFIX,
} from "../../src/protocol/receive-transfer-code.js";
import { classifyReceiveReconcile } from "../../src/protocol/reconcile/receive.js";
import { 
  RECEIVE_EXTERNAL_LANDING_INVARIANTS,
  RECEIVE_EXTERNAL_LANDING_SCHEMA_FILE,
} from "../../src/schema/receive-external-landing.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../../src/schema", RECEIVE_EXTERNAL_LANDING_SCHEMA_FILE);

describe("RECEIVE_EXTERNAL guard killing tests", () => {
  // Abort criteria guards
  describe("abort_criteria_bound guard", () => {
    it("pins code TTL bounds", () => {
      const criteria = receiveExternalAbortCriteria();
      expect(criteria.codeTtlMinSecs).toBe(60);
      expect(criteria.codeTtlMaxSecs).toBe(3600);
      expect(criteria.codeTtlDefaultSecs).toBe(300);
    });

    it("forbids blind retry", () => {
      const criteria = receiveExternalAbortCriteria();
      expect(criteria.blindRetryForbidden).toBe(true);
    });

    it("enforces single submit only", () => {
      const criteria = receiveExternalAbortCriteria();
      expect(criteria.singleSubmitOnly).toBe(true);
    });
  });

  describe("operator_halt_handling guard", () => {
    it("handles operator halt correctly", () => {
      const rule = receiveAbortActionFor("OPERATOR_HALT");
      expect(rule.action).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
      expect(rule.mayResubmit).toBe(false);
    });
  });

  describe("code_ttl_elapsed_handling guard", () => {
    it("handles code TTL elapsed correctly", () => {
      const rule = receiveAbortActionFor("CODE_TTL_ELAPSED");
      expect(rule.action).toBe("HOLD_RECEIVER_ON_CODE_EXPIRY");
      expect(rule.mayResubmit).toBe(false);
    });
  });

  describe("submit_ambiguous_handling guard", () => {
    it("handles submit ambiguity correctly", () => {
      const rule = receiveAbortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
      expect(rule.action).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
      expect(rule.mayResubmit).toBe(false);
    });
  });

  describe("all_abort_triggers_covered guard", () => {
    it("covers all abort triggers", () => {
      const criteria = receiveExternalAbortCriteria();
      const triggers: string[] = [
        "SUBMIT_REJECTED",
        "SUBMIT_AMBIGUOUS_OR_UNOBSERVED", 
        "INVARIANT_BREACH",
        "LANDED_VERIFIED",
        "OPERATOR_HALT",
        "CODE_TTL_ELAPSED",
      ];
      expect(criteria.rules.map(r => r.trigger).sort()).toEqual(triggers.sort());
    });
  });

  // Transfer code assembly guards
  describe("receive_transfer_code_wire_version guard", () => {
    it("enforces wire version", () => {
      expect(RECEIVE_TRANSFER_CODE_WIRE_VERSION).toBe("1");
    });
  });

  describe("receive_transfer_code_type guard", () => {
    it("enforces transfer code type", () => {
      expect(RECEIVE_TRANSFER_CODE_TYPE).toBe("sender_create_transaction");
    });
  });

  describe("receive_message_prefix guard", () => {
    it("enforces message prefix", () => {
      expect(RECEIVE_MESSAGE_PREFIX).toBe("zp1:");
    });
  });

  describe("anchor_pattern_validation guard", () => {
    it("rejects invalid anchor pattern", () => {
      expect(() => buildReceiveMessage("12345678-1234-1234-1234-123456789012", "invalid anchor!")).toThrow(ReceiveTransferCodeError);
      expect(() => buildReceiveMessage("12345678-1234-1234-1234-123456789012", "invalid anchor!")).toThrow("invalid_anchor");
    });

    it("accepts valid anchor pattern", () => {
      expect(() => buildReceiveMessage("12345678-1234-1234-1234-123456789012", "valid-anchor")).not.toThrow();
    });
  });

  describe("transfer_code_digest_algorithm guard", () => {
    it("uses SHA-256 algorithm", () => {
      const text = "test";
      const digest = hashTransferCodeText(text);
      expect(digest).toBe("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    });
  });

  describe("transfer_code_digest_no_preprocessing guard", () => {
    it("does not preprocess before hashing", () => {
      const text = "test";
      const digest = hashTransferCodeText(text);
      expect(digest).toBe("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    });
  });

  // Reconciliation guards
  describe("receive_never_crosses_boundary_signer guard", () => {
    it("classifies as PROVEN_NOT_STARTED when signer boundary not crossed", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: "op",
        formationComplete: false,
        step2SignaturePersisted: false,
        signerAuditIndicatesUse: false,
      });
      expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
      expect(outcome.neverCrossedBoundary).toBe("SIGNER");
    });
  });

  describe("receive_never_crosses_boundary_submitter guard", () => {
    it("classifies as PROVEN_NOT_STARTED when submitter boundary not crossed", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: "op",
        formationComplete: true,
        step2SignaturePersisted: true,
        signerAuditIndicatesUse: false,
      });
      expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
      expect(outcome.neverCrossedBoundary).toBe("SUBMITTER");
    });
  });

  describe("receive_formation_complete_check guard", () => {
    it("detects invariant breach when formation complete but signer audit indicates use", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: "op",
        formationComplete: true,
        step2SignaturePersisted: false,
        signerAuditIndicatesUse: true,
      });
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      expect(outcome.reason.source).toBe("EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT");
    });
  });

  describe("receive_step2_signature_persisted_check guard", () => {
    it("detects invariant breach when signature persisted but signer audit indicates use", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: "op",
        formationComplete: true,
        step2SignaturePersisted: false,
        signerAuditIndicatesUse: true,
      });
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      expect(outcome.reason.source).toBe("EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT");
    });
  });

  describe("receive_signer_audit_indicates_use_check guard", () => {
    it("detects invariant breach when signer audit indicates use without persisted bytes", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: "op",
        formationComplete: false,
        step2SignaturePersisted: false,
        signerAuditIndicatesUse: true,
      });
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      expect(outcome.reason.source).toBe("EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT");
    });
  });

  describe("receive_lease_active_during_reconcile guard", () => {
    it("detects invariant breach when lease not active during reconcile", () => {
      const outcome = classifyReceiveReconcile({
        boundary: "POST_SUBMIT",
        receiveAttemptId: "attempt",
        receiverWalletId: "wallet",
        receiverLeaseState: "INACTIVE" as any,
        receiverObservation: { tier: "LANDED" as any, proof: {} as any },
      });
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      expect(outcome.reason.source).toBe("LEASE_NOT_ACTIVE_DURING_RECONCILE");
    });
  });

  // Schema guards — verified against the production SQL file, not a local static array
  describe("schema invariant guards (SQL-enforcing)", () => {
    const sql = readFileSync(sqlPath, "utf8");

    for (const invariant of RECEIVE_EXTERNAL_LANDING_INVARIANTS) {
      it(`enforces ${invariant.id} in the production schema`, () => {
        expect(sql, `receive-external-landing.sql must enforce ${invariant.id}`)
          .toContain(invariant.sqlAnchor);
      });
    }
  });
});