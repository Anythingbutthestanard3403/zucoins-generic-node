// Channel-oracle audit correction (defect 1 — runtime-mutable channel oracle). Regression proving:
//  (a) AUTHORITATIVE_CHANNELS is deep-frozen, so a runtime mutation (the injection vector) throws
//      rather than silently poisoning the exported channel set; and
//  (b) the sole-channel verifiers no longer trust a poisoned channel list — a disguised extra
//      channel that fools the structural predicates (soleChannelIsAuthoritativePull /
//      pullIsSoleCursorAuthority) is rejected by authoritativeChannelsAreCanonical, whose expected
//      oracle is a verifier-internal frozen copy decoupled from the mutable export.
//
// CONTRACT_FREEZE.
import { describe, expect, it } from "vitest";

import {
  AUTHORITATIVE_CHANNELS,
  authoritativeChannelsAreCanonical,
  pullIsSoleCursorAuthority,
  soleChannelIsAuthoritativePull,
} from "./index.js";

// A disguised extra channel: it lies `egress: "none_node_serves_pull"` and takes the accelerator
// role, so both structural predicates admit it — but it is not part of the canonical set.
const DISGUISED_INJECTED_CHANNEL = {
  channel: "unexpected_injected_channel",
  route: "GET /v1/unexpected",
  egress: "none_node_serves_pull",
  role: "low_latency_wake_accelerator",
} as const;

describe("channel-oracle defect 1: AUTHORITATIVE_CHANNELS is immutable at runtime", () => {
  it("rejects appending an injected channel (frozen array)", () => {
    expect(() => {
      (AUTHORITATIVE_CHANNELS as readonly unknown[] as unknown[]).push({ ...DISGUISED_INJECTED_CHANNEL });
    }).toThrow();
  });

  it("rejects mutating a row's egress (frozen rows)", () => {
    expect(() => {
      (AUTHORITATIVE_CHANNELS[0] as unknown as { egress: string }).egress = "node_egress_poison";
    }).toThrow();
  });
});

describe("channel-oracle defect 1: canonical verifier is decoupled from the mutable reference", () => {
  it("accepts exactly the canonical exported channel set", () => {
    expect(authoritativeChannelsAreCanonical(AUTHORITATIVE_CHANNELS)).toBe(true);
  });

  it("rejects a disguised extra channel that fools both structural predicates", () => {
    const poisoned = [...AUTHORITATIVE_CHANNELS, { ...DISGUISED_INJECTED_CHANNEL }];
    // The old structural predicates are fooled by the disguised zero-egress accelerator channel...
    expect(soleChannelIsAuthoritativePull(poisoned)).toBe(true);
    expect(pullIsSoleCursorAuthority(poisoned)).toBe(true);
    // ...but the canonical verifier, pinned to its own frozen oracle, rejects it.
    expect(authoritativeChannelsAreCanonical(poisoned)).toBe(false);
  });

  it("rejects a mutated-role copy", () => {
    const poisoned = AUTHORITATIVE_CHANNELS.map((c, i) =>
      i === 0 ? { ...c, role: "low_latency_wake_accelerator" } : { ...c },
    );
    expect(authoritativeChannelsAreCanonical(poisoned)).toBe(false);
  });
});
