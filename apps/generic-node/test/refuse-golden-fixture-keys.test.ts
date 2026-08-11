// Boot-lane A.8 golden fixture key refusal (ZTR-1174 / r2 arm-before-refuse fix).
import { describe, expect, it, vi } from "vitest";

import {
  A8_GOLDEN_NODE_ID,
  A8_GOLDEN_PUBLIC_KEYS,
  assertNoGoldenFixtureKeysAtBoot,
  GoldenFixtureKeyBootError,
  refuseGoldenEventSigningKey,
  refuseGoldenThenProbeIdentity,
} from "../src/boot/refuse-golden-fixture-keys.js";

// A key clearly not in the A.8 golden set.
const NON_GOLDEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes — not an A.8 seed pubkey

describe("assertNoGoldenFixtureKeysAtBoot", () => {
  it("admits non-golden keys", () => {
    expect(() =>
      assertNoGoldenFixtureKeysAtBoot([{ publicKey: NON_GOLDEN, role: "NODE_IDENTITY" }]),
    ).not.toThrow();
  });

  it("refuses every A.8 golden public key as node identity", () => {
    for (const publicKey of A8_GOLDEN_PUBLIC_KEYS) {
      expect(() =>
        assertNoGoldenFixtureKeysAtBoot([{ publicKey, role: "NODE_IDENTITY" }]),
      ).toThrow(GoldenFixtureKeyBootError);
    }
  });

  it("refuses golden keys in wallet custody", () => {
    const [golden] = A8_GOLDEN_PUBLIC_KEYS;
    expect(() =>
      assertNoGoldenFixtureKeysAtBoot([
        { publicKey: NON_GOLDEN, role: "NODE_IDENTITY" },
        { publicKey: golden, role: "wallet custody" },
      ]),
    ).toThrow(/wallet custody/);
  });

  it("refuses the A.8 golden node id", () => {
    expect(() =>
      assertNoGoldenFixtureKeysAtBoot([
        { keyId: A8_GOLDEN_NODE_ID, publicKey: NON_GOLDEN, role: "NODE_IDENTITY" },
      ]),
    ).toThrow(/golden fixture node id/);
  });

  it("refuses unpadded forms of golden keys", () => {
    const padded = [...A8_GOLDEN_PUBLIC_KEYS][0]!;
    const unpadded = padded.replace(/=+$/, "");
    expect(() =>
      assertNoGoldenFixtureKeysAtBoot([{ publicKey: unpadded, role: "NODE_IDENTITY_SEED" }]),
    ).toThrow(GoldenFixtureKeyBootError);
  });
});

describe("refuseGoldenThenProbeIdentity — ensure-then-refuse ordering", () => {
  it("probes only after a non-golden ensure result and returns the armable signer", () => {
    const sign = vi.fn(() => new Uint8Array([1, 2, 3]));
    const armed = refuseGoldenThenProbeIdentity({
      signingKeyId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      publicKey: NON_GOLDEN,
      sign,
    });
    expect(sign).toHaveBeenCalledTimes(1);
    expect(sign).toHaveBeenCalledWith(new Uint8Array());
    expect(armed.signingKeyId).toBe("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    expect(armed.publicKey).toBe(NON_GOLDEN);
    expect(armed.sign(new Uint8Array([9]))).toEqual(new Uint8Array([1, 2, 3]));
    expect(sign).toHaveBeenCalledTimes(2);
  });

  it("refuses a sealed golden NODE_IDENTITY before sign/probe runs (no arm side-effects)", () => {
    const [golden] = A8_GOLDEN_PUBLIC_KEYS;
    const sign = vi.fn(() => new Uint8Array([9]));
    expect(() =>
      refuseGoldenThenProbeIdentity({
        signingKeyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        publicKey: golden!,
        sign,
      }),
    ).toThrow(GoldenFixtureKeyBootError);
    expect(sign).not.toHaveBeenCalled();
  });

  it("refuses A.8 golden node id on ensure result before probe", () => {
    const sign = vi.fn(() => new Uint8Array());
    expect(() =>
      refuseGoldenThenProbeIdentity({
        signingKeyId: A8_GOLDEN_NODE_ID,
        publicKey: NON_GOLDEN,
        sign,
      }),
    ).toThrow(/golden fixture node id/);
    expect(sign).not.toHaveBeenCalled();
  });
});

describe("refuseGoldenEventSigningKey — EVENT_SIGNING golden at boot", () => {
  it("admits a non-golden EVENT_SIGNING public key", () => {
    expect(() =>
      refuseGoldenEventSigningKey({
        signingKeyId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        publicKey: NON_GOLDEN,
      }),
    ).not.toThrow();
  });

  it("refuses every A.8 golden public key as EVENT_SIGNING before arm", () => {
    for (const publicKey of A8_GOLDEN_PUBLIC_KEYS) {
      expect(() =>
        refuseGoldenEventSigningKey({
          signingKeyId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
          publicKey,
        }),
      ).toThrow(/EVENT_SIGNING/);
    }
  });

  it("refuses unpadded golden EVENT_SIGNING keys", () => {
    const padded = [...A8_GOLDEN_PUBLIC_KEYS][0]!;
    const unpadded = padded.replace(/=+$/, "");
    expect(() =>
      refuseGoldenEventSigningKey({
        signingKeyId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        publicKey: unpadded,
      }),
    ).toThrow(GoldenFixtureKeyBootError);
  });
});

// Source-order pin: main.ts must call refuse helpers before arming holders.
describe("main.ts boot order pin (refuse before arm)", () => {
  it("calls refuseGoldenThenProbeIdentity before sendSignerHolder / identityEnsured", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(here, "../src/main.ts"), "utf8");
    const refuseIdx = src.indexOf("refuseGoldenThenProbeIdentity(identity)");
    const holderIdx = src.indexOf("sendSignerHolder.current = {\n        signingKeyId: armedIdentity");
    const ensuredIdx = src.indexOf("identityEnsured = true");
    const eventRefuseIdx = src.indexOf("refuseGoldenEventSigningKey(eventKey)");
    const installIdx = src.indexOf("installEventSigner({");
    expect(refuseIdx).toBeGreaterThan(0);
    expect(holderIdx).toBeGreaterThan(refuseIdx);
    expect(ensuredIdx).toBeGreaterThan(holderIdx);
    expect(eventRefuseIdx).toBeGreaterThan(0);
    // EVENT_SIGNING refuse is inside openSigner, which is the arg to installEventSigner —
    // both must appear; refuse must precede the return that arms.
    const openReturnAfterRefuse = src.indexOf(
      "return {\n            signingKeyId: eventKey.signingKeyId",
      eventRefuseIdx,
    );
    expect(openReturnAfterRefuse).toBeGreaterThan(eventRefuseIdx);
    expect(installIdx).toBeGreaterThan(0);
  });
});
