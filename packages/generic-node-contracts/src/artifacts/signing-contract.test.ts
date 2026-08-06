import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  ARTIFACT_KEY_ROLE,
  NODE_IDENTITY_KEY_STATUSES,
  KEY_REJECT_REASONS,
  KEY_VALIDITY_RULES,
  isKeyAcceptedForVerification,
  isKeyAcceptedForNewSigning,
  type NodeIdentityKeyRecord,
  type NodeIdentityKeyStatus,
} from "./signing-contract.ts";

const key = (
  status: NodeIdentityKeyStatus,
  validFromUnixMs: number,
  validUntilUnixMs: number | null,
  role: string = ARTIFACT_KEY_ROLE,
): NodeIdentityKeyRecord => ({
  keyId: "k1",
  role,
  publicKeyB64: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
  status,
  validFromUnixMs,
  validUntilUnixMs,
});

const T1 = 2_000;
const T2 = 3_000;
const T3 = 4_000;

describe("node-identity signing contract (A.3.4, the artifacts freeze)", () => {
  it("freezes the key statuses, validity rules, and reject-reason set", () => {
    assertFieldOrder(NODE_IDENTITY_KEY_STATUSES, ["ACTIVE", "RETIRED", "REVOKED"]);
    expect(ARTIFACT_KEY_ROLE).toBe("node_identity");
    expect(KEY_VALIDITY_RULES.authorizesNewSigning).toEqual({ ACTIVE: true, RETIRED: false, REVOKED: false });
    expect(KEY_VALIDITY_RULES.verifiesHistorical).toEqual({ ACTIVE: true, RETIRED: true, REVOKED: false });
    expect(KEY_VALIDITY_RULES.revocationOverridesInterval).toBe(true);
    assertFieldOrder(KEY_REJECT_REASONS, [
      "wrong_key_role",
      "revoked",
      "retired_cannot_sign_new",
      "not_active_cannot_sign_new",
      "before_valid_from",
      "after_valid_until",
    ]);
  });

  it("ACTIVE key inside its window verifies and may sign new activity", () => {
    const k = key("ACTIVE", T1, T3);
    expect(isKeyAcceptedForVerification(k, T2)).toEqual({ accepted: true });
    expect(isKeyAcceptedForNewSigning(k, T2)).toEqual({ accepted: true });
  });

  it("RETIRED key still verifies historical signatures but cannot sign new (frozen history)", () => {
    const k = key("RETIRED", T1, T2);
    expect(isKeyAcceptedForVerification(k, T1 + 1)).toEqual({ accepted: true });
    expect(isKeyAcceptedForNewSigning(k, T1 + 1)).toEqual({ accepted: false, reason: "retired_cannot_sign_new" });
  });

  it("REVOKED key is refused for verification AND new signing, even inside its old window", () => {
    const k = key("REVOKED", T1, T3);
    expect(isKeyAcceptedForVerification(k, T2)).toEqual({ accepted: false, reason: "revoked" });
    expect(isKeyAcceptedForNewSigning(k, T2)).toEqual({ accepted: false, reason: "revoked" });
  });

  it("cross-purpose: a non-identity key role never verifies an artifact", () => {
    const walletRoleKey = key("ACTIVE", T1, T3, "wallet");
    expect(isKeyAcceptedForVerification(walletRoleKey, T2)).toEqual({ accepted: false, reason: "wrong_key_role" });
    expect(isKeyAcceptedForNewSigning(walletRoleKey, T2)).toEqual({ accepted: false, reason: "wrong_key_role" });
  });

  it("enforces the validity window bounds", () => {
    const k = key("ACTIVE", T1, T2);
    expect(isKeyAcceptedForVerification(k, T1 - 1)).toEqual({ accepted: false, reason: "before_valid_from" });
    expect(isKeyAcceptedForVerification(k, T2 + 1)).toEqual({ accepted: false, reason: "after_valid_until" });
  });

  it("open-ended (validUntil = null) key covers any instant at or after validFrom", () => {
    const k = key("ACTIVE", T1, null);
    expect(isKeyAcceptedForVerification(k, T1)).toEqual({ accepted: true });
    expect(isKeyAcceptedForVerification(k, T3 * 1000)).toEqual({ accepted: true });
    expect(isKeyAcceptedForVerification(k, T1 - 1)).toEqual({ accepted: false, reason: "before_valid_from" });
  });

  it("rotation overlap: an artifact signed in the overlap verifies against both keys; new signing only the incoming ACTIVE one", () => {
    // Outgoing key rotated out at T2; incoming key active from T1 (< T2) — windows overlap [T1,T2].
    const outgoing = key("RETIRED", 1_000, T2);
    const incoming = key("ACTIVE", T1, null);
    const signedInOverlap = T1 + 100;
    expect(isKeyAcceptedForVerification(outgoing, signedInOverlap)).toEqual({ accepted: true });
    expect(isKeyAcceptedForVerification(incoming, signedInOverlap)).toEqual({ accepted: true });
    const now = T3; // after the outgoing window closed
    expect(isKeyAcceptedForNewSigning(outgoing, now)).toEqual({ accepted: false, reason: "retired_cannot_sign_new" });
    expect(isKeyAcceptedForNewSigning(incoming, now)).toEqual({ accepted: true });
  });

  it("rejects a reordered key-status list (negative path)", () => {
    expectRejects(
      () => [...NODE_IDENTITY_KEY_STATUSES].reverse(),
      (mutated) => assertFieldOrder(mutated, NODE_IDENTITY_KEY_STATUSES),
    );
  });
});
