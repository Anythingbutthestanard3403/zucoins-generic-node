import { describe, expect, it } from "vitest";

import {
  createOperatorPushAuthSealer,
  createProcessLocalOperatorPushSealKey,
  openOperatorPushAuth,
  resolveOperatorPushSealKeyFromEnv,
  sealOperatorPushAuth,
} from "./operator-push-seal.js";

describe("operator push auth seal", () => {
  it("round-trips auth secret under process-local key", () => {
    const key = createProcessLocalOperatorPushSealKey();
    const sealed = sealOperatorPushAuth("auth-secret-not-returned", key);
    expect(sealed.startsWith("zp-op-push-auth-v1.")).toBe(true);
    expect(sealed).not.toContain("auth-secret-not-returned");
    expect(openOperatorPushAuth(sealed, key)).toBe("auth-secret-not-returned");
  });

  it("resolves 64-hex OPERATOR_PUSH_SEAL_KEY", () => {
    const hex = "ab".repeat(32);
    const key = resolveOperatorPushSealKeyFromEnv({ OPERATOR_PUSH_SEAL_KEY: hex });
    expect(key?.length).toBe(32);
    const sealer = createOperatorPushAuthSealer(key!);
    const s = sealer.seal("xyz-auth-value");
    expect(sealer.open(s)).toBe("xyz-auth-value");
  });

  it("discards length-only placeholder format", () => {
    const key = createProcessLocalOperatorPushSealKey();
    expect(() => openOperatorPushAuth("sealed:22", key)).toThrow(/unrecognised/i);
  });
});
