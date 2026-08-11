// Boot-lane A.8 golden fixture key refusal (ZTR-1174).
import { describe, expect, it } from "vitest";

import {
  A8_GOLDEN_NODE_ID,
  A8_GOLDEN_PUBLIC_KEYS,
  assertNoGoldenFixtureKeysAtBoot,
  GoldenFixtureKeyBootError,
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
    const padded = [...A8_GOLDEN_PUBLIC_KEYS][0];
    const unpadded = padded.replace(/=+$/, "");
    expect(() =>
      assertNoGoldenFixtureKeysAtBoot([{ publicKey: unpadded, role: "NODE_IDENTITY_SEED" }]),
    ).toThrow(GoldenFixtureKeyBootError);
  });
});
