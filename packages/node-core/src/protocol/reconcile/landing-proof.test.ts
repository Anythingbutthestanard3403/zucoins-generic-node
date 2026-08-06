// opaque landing-path oracle landing-path proof capability.

import { describe, expect, it } from "vitest";

import * as reconcileBarrel from "./index.js";
import {
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  type LandingPathProof,
} from "./landing-proof.js";
import {
  isLandingOracleSeal,
  issueLandingOracleSeal,
  mintLandingPathProof,
  mintLandingPathProofFromOracle,
  type LandingOracleSeal,
} from "./landing-oracle-mint.fixture.js";

describe("landing path proof capability", () => {
  it("issue + mint yields LANDED_EXACT with matching exact-head digests", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-a",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs-head-1",
      depth: 0,
    });
    expect(proof.kind).toBe("LANDED_EXACT");
    expect(proof.depth).toBe(0);
    expect(isLandingPathProof(proof)).toBe(true);
    expect(Object.isFrozen(proof)).toBe(true);
  });

  it("issue + mint yields LANDED_COMPLETE_PATH only when head digest differs", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-a",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "bb".repeat(32),
      freshHeadObservationId: "obs-head-2",
      depth: 3,
    });
    expect(proof.kind).toBe("LANDED_COMPLETE_PATH");
    expect(proof.depth).toBe(3);
    expect(proof.freshHeadBodySha256).toBe("bb".repeat(32));
  });

  it("refuses LANDED_EXACT forge where expected ≠ fresh head body", () => {
    expect(() =>
      issueLandingOracleSeal({
        walletPubkeyBase64Urlsafe: "w",
        expectedBodySha256: "aa".repeat(32),
        freshHeadBodySha256: "bb".repeat(32),
        freshHeadObservationId: "obs",
        depth: 0,
      }),
    ).toThrow(/exact-head anchor/);
  });

  it("refuses buried path where expected === fresh head body", () => {
    expect(() =>
      issueLandingOracleSeal({
        walletPubkeyBase64Urlsafe: "w",
        expectedBodySha256: "aa".repeat(32),
        freshHeadBodySha256: "aa".repeat(32),
        freshHeadObservationId: "obs",
        depth: 2,
      }),
    ).toThrow(/buried head/);
  });

  it("mintLandingPathProof refuses a seal that was never issued (structural forgery)", () => {
    const fakeSeal = {
      kind: "LANDED_EXACT",
      walletPubkeyBase64Urlsafe: "w",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs",
      depth: 0,
    } as unknown as LandingOracleSeal;
    expect(isLandingOracleSeal(fakeSeal)).toBe(false);
    expect(() => mintLandingPathProof(fakeSeal)).toThrow(/issued oracle seal/);
  });

  it("a hand-written object literal is not a LandingPathProof (compile + runtime)", () => {
    // @ts-expect-error — module-private brand symbol is not nameable outside landing-proof.ts
    const impostor: LandingPathProof = {
      kind: "LANDED_EXACT",
      walletPubkeyBase64Urlsafe: "w",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs",
      depth: 0,
    };
    expect(isLandingPathProof(impostor)).toBe(false);
  });

  it("spread-copy of an issued proof is not in the WeakSet (identity, not shape)", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "w",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs",
      depth: 0,
    });
    const copy = { ...proof };
    expect(isLandingPathProof(proof)).toBe(true);
    expect(isLandingPathProof(copy)).toBe(false);
  });

  it("seal is frozen and single-use — second mint refuses; field mutation fails", () => {
    const seal = issueLandingOracleSeal({
      walletPubkeyBase64Urlsafe: "w",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs-A",
      depth: 0,
    });
    expect(Object.isFrozen(seal)).toBe(true);
    expect(isLandingOracleSeal(seal)).toBe(true);
    expect(() => {
      (seal as { expectedBodySha256: string }).expectedBodySha256 = "evil";
    }).toThrow();
    const p1 = mintLandingPathProof(seal);
    expect(isLandingPathProof(p1)).toBe(true);
    expect(isLandingOracleSeal(seal)).toBe(false);
    expect(() => mintLandingPathProof(seal)).toThrow(/issued oracle seal/);
  });

  it("revalidateLandingPathProofBindings enforces independent external evidence only", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-a",
      expectedBodySha256: "aa".repeat(32),
      freshHeadBodySha256: "aa".repeat(32),
      freshHeadObservationId: "obs-1",
      depth: 0,
    });
    expect(
      revalidateLandingPathProofBindings(proof, {
        walletPubkeyBase64Urlsafe: "wallet-a",
        expectedBodySha256: "aa".repeat(32),
      }),
    ).toBe(true);
    expect(
      revalidateLandingPathProofBindings(proof, {
        walletPubkeyBase64Urlsafe: "wallet-a",
        expectedBodySha256: "aa".repeat(32),
        freshHeadObservationId: "obs-1",
        freshHeadBodySha256: "aa".repeat(32),
      }),
    ).toBe(true);
    expect(
      revalidateLandingPathProofBindings(proof, {
        walletPubkeyBase64Urlsafe: "wallet-a",
        expectedBodySha256: "aa".repeat(32),
        freshHeadObservationId: "obs-OTHER",
      }),
    ).toBe(false);
    expect(
      revalidateLandingPathProofBindings(proof, {
        walletPubkeyBase64Urlsafe: "wallet-a",
        expectedBodySha256: "bb".repeat(32),
      }),
    ).toBe(false);
    expect(
      revalidateLandingPathProofBindings(
        {
          kind: "LANDED_EXACT",
          walletPubkeyBase64Urlsafe: "wallet-a",
          expectedBodySha256: "aa".repeat(32),
          freshHeadBodySha256: "aa".repeat(32),
          freshHeadObservationId: "obs-1",
          depth: 0,
        },
        {
          walletPubkeyBase64Urlsafe: "wallet-a",
          expectedBodySha256: "aa".repeat(32),
        },
      ),
    ).toBe(false);
  });

  it("mintLandingPathProof cannot be called with bare kind/wallet/hash/depth strings", () => {
    // @ts-expect-error — old 5-arg forge surface is gone; seal required
    expect(() => mintLandingPathProof("LANDED_EXACT", "w", "h", "obs", 0)).toThrow();
  });

  it("reconcile barrel does not export string mint / seal issue", () => {
    const barrel = reconcileBarrel as Record<string, unknown>;
    expect(barrel.mintLandingPathProofFromOracle).toBeUndefined();
    expect(barrel.mintLandingPathProof).toBeUndefined();
    expect(barrel.issueLandingOracleSeal).toBeUndefined();
    expect(barrel.isLandingOracleSeal).toBeUndefined();
    expect(typeof barrel.isLandingPathProof).toBe("function");
    expect(typeof barrel.revalidateLandingPathProofBindings).toBe("function");
  });

  it("landing-proof.ts Stage-2 surface does not export string mint (deep-import forge closed)", async () => {
    const surface = (await import("./landing-proof.js")) as Record<string, unknown>;
    expect(surface.mintLandingPathProofFromOracle).toBeUndefined();
    expect(surface.mintLandingPathProof).toBeUndefined();
    expect(surface.issueLandingOracleSeal).toBeUndefined();
    expect(typeof surface.isLandingPathProof).toBe("function");
  });
});
