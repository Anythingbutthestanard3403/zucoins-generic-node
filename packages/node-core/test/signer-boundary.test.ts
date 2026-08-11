import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  LeaseSignerBoundary,
  NotSignerLeaderError,
  SignerBoundaryError,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SignerLeadershipLatch,
  type VaultSigner,
  type WalletSigningCapability,
  MoneyPathGatesMissingError,
  signUnderLease,
} from "../src/core/signer-boundary.js";
import { SignerLeadership } from "../src/workers/leadership.js";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const FIXED_TIME = "2026-01-15T00:00:00.000Z";

function makeCapability(overrides: Partial<WalletSigningCapability> = {}): WalletSigningCapability {
  const preimageText = overrides.preimageText ?? '{"amount":"1000","sender":"wallet-1"}';
  return { walletId: "wallet-1", operationId: "op-1", leaseEpoch: 1n, purpose: "SPLITCHAIN_STEP_1", preimageText, expectedPreimageSha256: sha256Hex(preimageText), ...overrides };
}

function makeLease(overrides: Partial<ActiveLeaseRecord> = {}): ActiveLeaseRecord {
  return { walletId: "wallet-1", operationId: "op-1", epoch: 1n, role: "SEND_SOURCE", lifecycle: "ACTIVE", ...overrides };
}

function makeBoundary(lease: ActiveLeaseRecord | null, leadership: SignerLeadershipLatch = { held: true }) {
  const auditEntries: SignerAuditEntry[] = [];
  const vaultSigner: VaultSigner = { sign: vi.fn().mockResolvedValue("c2lnbmF0dXJlLWJ5dGVz") };
  const leaseReader = { readActiveLease: vi.fn().mockResolvedValue(lease) };
  const boundary = new LeaseSignerBoundary({
    leadership,
    leaseReader,
    vaultSigner,
    auditLog: { append: vi.fn().mockImplementation(async (e: SignerAuditEntry) => { auditEntries.push(e); }) },
    now: () => FIXED_TIME,
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
  });
  return { boundary, auditEntries, vaultSigner, leaseReader };
}

describe("LeaseSignerBoundary", () => {
  // The process-exclusivity half of the one-in-flight-per-wallet rule: a wallet lease says nobody else holds THIS
  // wallet; leadership says no other instance is signing at all. A valid lease must not be
  // enough — otherwise a deposed instance whose lock the database already freed keeps signing.
  describe("signer leadership (AC3)", () => {
    it("refuses a fully valid capability while the latch is not held, and never reaches the vault", async () => {
      const { boundary, auditEntries, vaultSigner, leaseReader } = makeBoundary(makeLease(), {
        held: false,
        reason: "signer leadership lock connection end",
      });
      await expect(boundary.sign(makeCapability())).rejects.toThrow(NotSignerLeaderError);
      // The proof is the negative: no vault call, and the refusal lands before the lease read.
      expect(vaultSigner.sign).not.toHaveBeenCalled();
      expect(leaseReader.readActiveLease).not.toHaveBeenCalled();
      expect(auditEntries).toHaveLength(0);
    });

    it("carries the non-secret loss reason and no key material", async () => {
      const { boundary } = makeBoundary(makeLease(), { held: false, reason: "connection error: ECONNRESET" });
      await expect(boundary.sign(makeCapability())).rejects.toThrow(
        "node does not hold signer leadership: connection error: ECONNRESET",
      );
    });

    it("tracks the real latch through acquire and loss", async () => {
      const latch = new SignerLeadership();
      const { boundary, vaultSigner } = makeBoundary(makeLease(), latch);

      await expect(boundary.sign(makeCapability())).rejects.toThrow(NotSignerLeaderError);
      latch.markAcquired();
      expect((await boundary.sign(makeCapability())).signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
      expect(vaultSigner.sign).toHaveBeenCalledTimes(1);

      // The dedicated lock connection died: the lock is already free server-side, so signing
      // must stop within the same tick — before the standby could plausibly acquire.
      latch.markLost("signer leadership lock connection end");
      await expect(boundary.sign(makeCapability())).rejects.toThrow(NotSignerLeaderError);
      expect(vaultSigner.sign).toHaveBeenCalledTimes(1);
    });
  });

  describe("valid lease", () => {
    it("signs and records audit entry when lease is valid", async () => {
      const { boundary, auditEntries, vaultSigner } = makeBoundary(makeLease());
      const cap = makeCapability();
      const result = await boundary.sign(cap);
      expect(result.signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
      expect(result.preimageSha256).toBe(cap.expectedPreimageSha256);
      expect(vaultSigner.sign).toHaveBeenCalledWith("wallet-1", new TextEncoder().encode(cap.preimageText));
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0].outcome).toBe("SIGNED");
      expect(auditEntries[0].walletId).toBe("wallet-1");
      expect(auditEntries[0].leaseEpoch).toBe(1n);
      expect(auditEntries[0].timestamp).toBe(FIXED_TIME);
    });
    it("accepts RECEIVE_WINDOW role for step-2 co-signing", async () => {
      const { boundary } = makeBoundary(makeLease({ role: "RECEIVE_WINDOW" }));
      expect((await boundary.sign(makeCapability({ purpose: "SPLITCHAIN_STEP_2" }))).signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
    });
    it("accepts MOVE_SOURCE role", async () => {
      const { boundary } = makeBoundary(makeLease({ role: "MOVE_SOURCE" }));
      expect((await boundary.sign(makeCapability())).signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
    });
    it("accepts RECONCILIATION role (recovery lane)", async () => {
      const { boundary } = makeBoundary(makeLease({ role: "RECONCILIATION" }));
      expect((await boundary.sign(makeCapability())).signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
    });
  });
  describe("no lease (fail-closed)", () => {
    it("rejects when no lease exists for the wallet", async () => {
      const { boundary, auditEntries } = makeBoundary(null);
      await expect(boundary.sign(makeCapability())).rejects.toThrow(SignerBoundaryError);
      expect(auditEntries[0].outcome).toBe("REJECTED");
      expect(auditEntries[0].rejectionReason).toBe("no active lease for wallet");
    });
  });
  describe("released lease", () => {
    it("rejects when lease lifecycle is RELEASED", async () => {
      const { boundary, auditEntries } = makeBoundary(makeLease({ lifecycle: "RELEASED" }));
      await expect(boundary.sign(makeCapability())).rejects.toThrow("lease is released");
      expect(auditEntries[0].outcome).toBe("REJECTED");
    });
  });
  describe("operation mismatch", () => {
    it("rejects when lease holds a different operation", async () => {
      const { boundary, auditEntries } = makeBoundary(makeLease({ operationId: "op-other" }));
      await expect(boundary.sign(makeCapability())).rejects.toThrow("operation mismatch");
      expect(auditEntries[0].outcome).toBe("REJECTED");
    });
  });
  describe("epoch mismatch (stale lease)", () => {
    it("rejects when capability epoch does not match lease epoch", async () => {
      const { boundary, auditEntries } = makeBoundary(makeLease({ epoch: 2n }));
      await expect(boundary.sign(makeCapability({ leaseEpoch: 1n }))).rejects.toThrow("lease epoch mismatch");
      expect(auditEntries[0].outcome).toBe("REJECTED");
    });
  });
  describe("role not permitted", () => {
    it("rejects MOVE_DESTINATION role (not a signing role)", async () => {
      const { boundary, auditEntries } = makeBoundary(makeLease({ role: "MOVE_DESTINATION" }));
      await expect(boundary.sign(makeCapability())).rejects.toThrow("lease role not permitted for signing");
      expect(auditEntries[0].outcome).toBe("REJECTED");
    });
  });
  describe("preimage digest mismatch", () => {
    it("rejects when expectedPreimageSha256 does not match preimageText", async () => {
      const { boundary, auditEntries, vaultSigner } = makeBoundary(makeLease());
      await expect(boundary.sign(makeCapability({ expectedPreimageSha256: "0".repeat(64) }))).rejects.toThrow("preimage digest mismatch");
      expect(vaultSigner.sign).not.toHaveBeenCalled();
      expect(auditEntries[0].outcome).toBe("REJECTED");
    });
  });
  describe("error codes", () => {
    it("carries the correct code for each rejection class", async () => {
      const cases: Array<{ lease: ActiveLeaseRecord | null; cap?: Partial<WalletSigningCapability>; code: string }> = [
        { lease: null, code: "NO_LEASE" },
        { lease: makeLease({ lifecycle: "RELEASED" }), code: "LEASE_RELEASED" },
        { lease: makeLease({ operationId: "x" }), code: "OPERATION_MISMATCH" },
        { lease: makeLease({ epoch: 99n }), code: "EPOCH_MISMATCH" },
        { lease: makeLease({ role: "MOVE_DESTINATION" }), code: "ROLE_NOT_PERMITTED" },
      ];
      for (const { lease, cap, code } of cases) {
        const { boundary } = makeBoundary(lease);
        try { await boundary.sign(makeCapability(cap)); expect.unreachable("should have thrown"); }
        catch (e) { expect((e as SignerBoundaryError).code).toBe(code); }
      }
    });
  });
  describe("audit completeness", () => {
    it("records rejection audit before throwing (no silent failures)", async () => {
      const { boundary, auditEntries } = makeBoundary(null);
      await expect(boundary.sign(makeCapability())).rejects.toThrow();
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0].outcome).toBe("REJECTED");
      expect(auditEntries[0].purpose).toBe("SPLITCHAIN_STEP_1");
    });
    it("never returns private key material in the result", async () => {
      const { boundary } = makeBoundary(makeLease());
      const result = await boundary.sign(makeCapability());
      expect(Object.keys(result)).toEqual(["signature", "preimageSha256"]);
    });
  });
});


describe("audit write fails closed", () => {
  // A swallowed audit-write failure would let signUnderLease resolve with a signature the
  // durable signer_audit table never recorded — exactly the operation-kind-dependent gap this
  // ticket closes for MOVE/SEND. signUnderLeaseBody awaits auditLog.append with no surrounding
  // try/catch, so a throwing append must propagate and the caller must never see a signature.
  it("propagates a SIGNED-path audit-write failure instead of returning a signature", async () => {
    const vaultSigner: VaultSigner = { sign: vi.fn().mockResolvedValue("c2lnbmF0dXJlLWJ5dGVz") };
    const auditLog = { append: vi.fn().mockRejectedValue(new Error("insert failed: connection lost")) };
    const boundary = new LeaseSignerBoundary({
      leadership: { held: true },
      leaseReader: { readActiveLease: async () => makeLease() },
      vaultSigner,
      auditLog,
      now: () => FIXED_TIME,
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    });
    // The vault already produced a signature (the private key acted), but the durable audit
    // write failed — the call must still reject, so no caller ever treats this as a completed,
    // durably-audited sign.
    await expect(boundary.sign(makeCapability())).rejects.toThrow("insert failed: connection lost");
    expect(vaultSigner.sign).toHaveBeenCalledTimes(1);
    expect(auditLog.append).toHaveBeenCalledTimes(1);
  });

  it("propagates a REJECTED-path audit-write failure instead of surfacing the lease rejection", async () => {
    const vaultSigner: VaultSigner = { sign: vi.fn() };
    const auditLog = { append: vi.fn().mockRejectedValue(new Error("insert failed: connection lost")) };
    const boundary = new LeaseSignerBoundary({
      leadership: { held: true },
      leaseReader: { readActiveLease: async () => null },
      vaultSigner,
      auditLog,
      now: () => FIXED_TIME,
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    });
    // Even the REJECTED branch must not swallow an audit-write failure: the original
    // SignerBoundaryError ("no active lease") must not surface as if it were durably recorded.
    await expect(boundary.sign(makeCapability())).rejects.toThrow("insert failed: connection lost");
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(auditLog.append).toHaveBeenCalledTimes(1);
  });
});

describe("signUnderLease drain bridge", () => {
  it("calls trackSigningInflight with the in-flight body before vault resolves", async () => {
    const tracked: Promise<unknown>[] = [];
    let resolveVault!: (sig: string) => void;
    const vaultPending = new Promise<string>((resolve) => {
      resolveVault = resolve;
    });
    const leadership: SignerLeadershipLatch = {
      held: true,
      trackSigningInflight(work) {
        tracked.push(work);
      },
    };
    const { signUnderLease } = await import("../src/core/signer-boundary.js");
    const preimageText = '{"amount":"1000","sender":"wallet-1"}';
    const expected = sha256Hex(preimageText);
    const signPromise = signUnderLease(
      {
        leadership,
        leaseReader: { readActiveLease: async () => makeLease() },
        vaultSigner: { sign: async () => vaultPending },
        auditLog: { append: async () => undefined },
        now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      },
      makeCapability({ preimageText, expectedPreimageSha256: expected }),
    );
    // Bridge is synchronous on entry — body is tracked before first await settles.
    expect(tracked).toHaveLength(1);
    resolveVault("c2lnbmF0dXJlLWJ5dGVz");
    const result = await signPromise;
    expect(result.signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
    await expect(tracked[0]).resolves.toBeDefined();
  });

  it("SignerLeadership.trackSigningInflight forwards to the installed tracker", async () => {
    const latch = new SignerLeadership();
    latch.markAcquired();
    const seen: Promise<unknown>[] = [];
    latch.setSigningInflightTracker((work) => {
      seen.push(work);
    });
    const p = Promise.resolve("ok");
    latch.trackSigningInflight(p);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBe(p);
  });

  it("setSigningInflightTracker freezes after first install (Defect D2)", () => {
    const latch = new SignerLeadership();
    const first: Promise<unknown>[] = [];
    latch.setSigningInflightTracker((work) => {
      first.push(work);
    });
    expect(() =>
      latch.setSigningInflightTracker(() => {
        /* wipe */
      }),
    ).toThrow(/already installed/);
    const p = Promise.resolve("still-first");
    latch.trackSigningInflight(p);
    expect(first).toHaveLength(1);
    expect(first[0]).toBe(p);
  });
});

describe("withSignTransaction (ZTR-1160)", () => {
  it("runs lease read, vault, and SIGNED audit inside the supplied transaction body", async () => {
    const order: string[] = [];
    const lease = makeLease();
    const vaultSigner: VaultSigner = {
      sign: vi.fn().mockImplementation(async () => {
        order.push("vault");
        return "c2lnbmF0dXJlLWJ5dGVz";
      }),
    };
    const txLeaseReader = {
      readActiveLease: vi.fn().mockImplementation(async () => {
        order.push("lease");
        return lease;
      }),
    };
    const txAudit = {
      append: vi.fn().mockImplementation(async () => {
        order.push("audit");
      }),
    };
    const fallbackLease = { readActiveLease: vi.fn().mockResolvedValue(lease) };
    const fallbackAudit = { append: vi.fn() };

    const result = await signUnderLease(
      {
        leadership: { held: true },
        leaseReader: fallbackLease,
        vaultSigner,
        auditLog: fallbackAudit,
        now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
        withSignTransaction: async (body) => {
          order.push("begin");
          const out = await body({ leaseReader: txLeaseReader, auditLog: txAudit });
          order.push("commit");
          return out;
        },
      },
      makeCapability(),
    );

    expect(result.signature).toBe("c2lnbmF0dXJlLWJ5dGVz");
    expect(order).toEqual(["begin", "lease", "vault", "audit", "commit"]);
    expect(fallbackLease.readActiveLease).not.toHaveBeenCalled();
    expect(fallbackAudit.append).not.toHaveBeenCalled();
    expect(txAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "SIGNED" }),
    );
  });

  it("commits REJECTED audit before surfacing SignerBoundaryError (no rollback of audit)", async () => {
    const order: string[] = [];
    const txAudit = {
      append: vi.fn().mockImplementation(async () => {
        order.push("audit");
      }),
    };
    await expect(
      signUnderLease(
        {
          leadership: { held: true },
          leaseReader: { readActiveLease: async () => null },
          vaultSigner: { sign: vi.fn() },
          auditLog: { append: vi.fn() },
          now: () => FIXED_TIME,
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
          withSignTransaction: async (body) => {
            order.push("begin");
            const out = await body({
              leaseReader: { readActiveLease: async () => null },
              auditLog: txAudit,
            });
            order.push("commit");
            return out;
          },
        },
        makeCapability(),
      ),
    ).rejects.toThrow(SignerBoundaryError);
    // Rejection is thrown AFTER commit so the FAILED audit row is not rolled back.
    expect(order).toEqual(["begin", "audit", "commit"]);
    expect(txAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "REJECTED", rejectionReason: "no active lease for wallet" }),
    );
  });
});

describe("money-path gates fail-closed", () => {
  it("signUnderLease without money gates throws MoneyPathGatesMissingError (never admits)", () => {
    const lease = makeLease();
    expect(() =>
      signUnderLease(
        {
          leadership: { held: true },
          leaseReader: { readActiveLease: async () => lease },
          vaultSigner: { sign: async () => "x" },
          auditLog: { append: async () => undefined },
          now: () => FIXED_TIME,
        },
        makeCapability(),
      ),
    ).toThrow(MoneyPathGatesMissingError);
  });

  // AC8: skipMoneyAdmission was a public bypass; it no longer exists in the interface.
  // Passing it as an extra runtime property is ignored — missing gates still fail-closed.
  it("rejects signUnderLease even when skipMoneyAdmission is present as an extra property", () => {
    const lease = makeLease();
    expect(() =>
      signUnderLease(
        {
          leadership: { held: true },
          leaseReader: { readActiveLease: async () => lease },
          vaultSigner: { sign: async () => "x" },
          auditLog: { append: async () => undefined },
          now: () => FIXED_TIME,
          skipMoneyAdmission: true,
        } as never,
        makeCapability(),
      ),
    ).toThrow(MoneyPathGatesMissingError);
  });
});

describe("wallet state recheck inside lease transaction (ZTR-1171)", () => {
  it("refuses when assertWalletMaySign on tx ports rejects after lease is valid", async () => {
    const { WalletSigningHaltedError } = await import("../src/core/signer-boundary.js");
    const auditEntries: SignerAuditEntry[] = [];
    const vaultSigner: VaultSigner = { sign: vi.fn().mockResolvedValue("c2lnbmF0dXJlLWJ5dGVz") };
    const lease = makeLease();
    await expect(
      signUnderLease(
        {
          leadership: { held: true },
          leaseReader: { readActiveLease: vi.fn().mockResolvedValue(lease) },
          vaultSigner,
          auditLog: {
            append: vi.fn().mockImplementation(async (e: SignerAuditEntry) => {
              auditEntries.push(e);
            }),
          },
          now: () => FIXED_TIME,
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          // Outer gate admits — quarantine happens after lease was taken.
          assertWalletMaySign: async () => {},
          withSignTransaction: async (body) =>
            body({
              leaseReader: { readActiveLease: vi.fn().mockResolvedValue(lease) },
              auditLog: {
                append: vi.fn().mockImplementation(async (e: SignerAuditEntry) => {
                  auditEntries.push(e);
                }),
              },
              assertWalletMaySign: async (walletId: string) => {
                throw new WalletSigningHaltedError(walletId);
              },
            }),
        },
        makeCapability(),
      ),
    ).rejects.toThrow(/wallet signing halted/);
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(auditEntries.some((e) => e.outcome === "REJECTED")).toBe(true);
  });
});

