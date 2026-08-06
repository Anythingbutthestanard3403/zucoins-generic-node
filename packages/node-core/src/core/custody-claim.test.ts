// service-boundary unit proofs for the claim precheck layer.
// Real-Postgres adversarial inputs live in custody-claim-boundary.pg.test.ts.
import { describe, expect, it, vi } from "vitest";
import {
  buildLeaseClaimInsertSql,
  claimWalletLease,
  precheckAutomaticSink,
  precheckDestinationCreate,
  precheckInternalCustody,
  precheckLeaseClaim,
} from "./custody-claim.js";

const eligible = {
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
  walletState: "AVAILABLE",
} as const;

const CLAIM = {
  walletId: "a0000000-0000-4000-8000-000000000001",
  membershipId: "d0000000-0000-4000-8000-000000000001",
  leaseGroupId: "d0000000-0000-4000-8000-000000000002",
  rootOperationId: "d0000000-0000-4000-8000-000000000003",
  operationId: "d0000000-0000-4000-8000-000000000004",
  leaseEpoch: 1,
  ownerInstanceId: "d0000000-0000-4000-8000-000000000005",
} as const;

describe("custody claim service (generic core neutrality; custody claim boundary)", () => {
  describe("precheckDestinationCreate (golden test 5 — service boundary)", () => {
    it("accepts node_generated", () => {
      expect(precheckDestinationCreate({ keyOrigin: "node_generated" })).toEqual({
        ok: true,
        denialReason: null,
      });
    });

    it("rejects imported purely on origin", () => {
      expect(precheckDestinationCreate({ keyOrigin: "imported" })).toEqual({
        ok: false,
        denialReason: "DESTINATION_ORIGIN_NOT_NODE_GENERATED",
      });
    });
  });

  describe("precheckInternalCustody / precheckAutomaticSink", () => {
    it("internal custody does not require recovery", () => {
      expect(precheckInternalCustody({ ...eligible, recoveryVerifiedAt: null })).toEqual({
        eligible: true,
        denialReason: null,
      });
    });

    it("automatic sink requires recovery (golden test 6)", () => {
      expect(precheckAutomaticSink({ ...eligible, recoveryVerifiedAt: null })).toEqual({
        eligible: false,
        denialReason: "INVALID_RECOVERY_VERIFIED_AT",
      });
    });

    it("imported never becomes internal even when recovery-verified", () => {
      expect(
        precheckAutomaticSink({
          ...eligible,
          keyOrigin: "imported",
        }),
      ).toEqual({
        eligible: false,
        denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
      });
    });
  });

  describe("precheckLeaseClaim", () => {
    it("origin conjunct alone rejects imported for non-sink roles", () => {
      expect(precheckLeaseClaim({ ...eligible, keyOrigin: "imported" }, "SEND_SOURCE")).toEqual({
        ok: false,
        denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
      });
    });

    it("MOVE_DESTINATION requires full automatic-sink eligibility", () => {
      expect(precheckLeaseClaim(eligible, "MOVE_DESTINATION")).toEqual({
        ok: true,
        denialReason: null,
      });
      expect(
        precheckLeaseClaim({ ...eligible, walletState: "QUARANTINED" }, "MOVE_DESTINATION"),
      ).toEqual({
        ok: false,
        denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
      });
    });

    it.each(["RECEIVE_WINDOW", "MOVE_SOURCE", "SEND_SOURCE"] as const)(
      "%s rejects QUARANTINED/RETIRED under the lease-state allowlist",
      (role) => {
        expect(
          precheckLeaseClaim({ ...eligible, walletState: "QUARANTINED" }, role),
        ).toEqual({
          ok: false,
          denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
        });
        expect(precheckLeaseClaim({ ...eligible, walletState: "RETIRED" }, role)).toEqual({
          ok: false,
          denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
        });
        expect(precheckLeaseClaim(eligible, role)).toEqual({ ok: true, denialReason: null });
      },
    );

    it("RECONCILIATION is exempt from lease-state rejection (recovery lane)", () => {
      expect(
        precheckLeaseClaim({ ...eligible, walletState: "QUARANTINED" }, "RECONCILIATION"),
      ).toEqual({ ok: true, denialReason: null });
      expect(
        precheckLeaseClaim({ ...eligible, walletState: "RETIRED" }, "RECONCILIATION"),
      ).toEqual({ ok: true, denialReason: null });
    });
  });

  describe("claimWalletLease", () => {
    it("never calls the executor when precheck fails", async () => {
      const execute = vi.fn(async () => undefined);
      const decision = await claimWalletLease(
        { ...eligible, keyOrigin: "imported" },
        "MOVE_DESTINATION",
        execute,
        CLAIM,
      );
      expect(decision.ok).toBe(false);
      expect(execute).not.toHaveBeenCalled();
    });

    it("maps claim-boundary origin rejection from the insert executor", async () => {
      const execute = vi.fn(async () => {
        throw new Error("ERROR:  P0001: CUSTODY_LEASE_ORIGIN_REJECTED");
      });
      const decision = await claimWalletLease(eligible, "MOVE_DESTINATION", execute, CLAIM);
      expect(decision).toEqual({
        ok: false,
        denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
      });
      expect(execute).toHaveBeenCalledOnce();
    });

    it("maps claim-boundary quarantine rejection (TOCTOU class)", async () => {
      const execute = vi.fn(async () => {
        throw new Error("ERROR:  P0001: CUSTODY_LEASE_WALLET_STATE_REJECTED");
      });
      const decision = await claimWalletLease(eligible, "MOVE_DESTINATION", execute, CLAIM);
      expect(decision).toEqual({
        ok: false,
        denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
      });
    });

    it("buildLeaseClaimInsertSql carries the full fencing column set (custody schema PK spelling)", () => {
      const sql = buildLeaseClaimInsertSql({
        ...CLAIM,
        leaseRole: "MOVE_DESTINATION",
      });
      expect(sql).toContain("INSERT INTO wallet_active_leases");
      expect(sql).toContain("MOVE_DESTINATION");
      expect(sql).toContain("membership_id");
      expect(sql).toContain("lease_group_id");
      expect(sql).toContain("root_operation_id");
      expect(sql).toContain("operation_id");
      expect(sql).toContain("lease_epoch");
      expect(sql).toContain("heartbeat_at");
      expect(sql).toContain("owner_instance_id");
      // Retired three-column shape must not reappear (BREAK F1).
      expect(sql).not.toMatch(
        /INSERT INTO wallet_active_leases\s*\(\s*wallet_id\s*,\s*lease_role\s*,\s*acquired_at\s*\)/,
      );
      expect(sql).not.toContain("SELECT"); // no precheck fused into the claim statement
    });
  });
});
