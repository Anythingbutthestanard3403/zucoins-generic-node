/**
 * Gate: every purpose served by a tenant-reachable route has a consumer verifier.
 * Prevents the ZTR-1145 failure mode — a green suite pinning zp-node-event-v1
 * (never served on GET /v1/events) while the real purpose goes unverified.
 */
import { describe, expect, it } from "vitest";

import {
  CONSUMER_VERIFIER_BY_PURPOSE,
  ROUTE_SERVED_PURPOSES,
} from "./route-purpose-verifiers.js";
import { authenticateImplementerEvent } from "@zucoins/node-core/verifier/consumer";
import {
  CHECKPOINT_DELIVERY_CHANNEL,
  IMPLEMENTER_CHECKPOINT_PURPOSE,
  IMPLEMENTER_EVENT_PURPOSE,
} from "@zucoins/generic-node-contracts/implementer-events";

describe("route-purpose-verifier gate", () => {
  it("lists exactly the purposes GET /v1/events serves", () => {
    expect([...ROUTE_SERVED_PURPOSES]).toEqual([
      IMPLEMENTER_EVENT_PURPOSE,
      IMPLEMENTER_CHECKPOINT_PURPOSE,
    ]);
    // Cross-check the frozen checkpoint delivery channel.
    expect(CHECKPOINT_DELIVERY_CHANNEL.path).toBe("/v1/events");
    expect(CHECKPOINT_DELIVERY_CHANNEL.proofPurpose).toBe(IMPLEMENTER_CHECKPOINT_PURPOSE);
    expect(CHECKPOINT_DELIVERY_CHANNEL.responseField).toBe("checkpoints");
  });

  it("registers a consumer verifier for every served purpose", () => {
    for (const purpose of ROUTE_SERVED_PURPOSES) {
      const verifier = CONSUMER_VERIFIER_BY_PURPOSE[purpose];
      expect(typeof verifier, purpose).toBe("function");
      expect(verifier).toBe(authenticateImplementerEvent);
    }
  });

  it("does not list the operator-only zp-node-event-v1 as a served purpose", () => {
    expect(ROUTE_SERVED_PURPOSES).not.toContain("zp-node-event-v1");
  });

  it("does not list zp-implementer-keyrotation-v1 until a route serves it", () => {
    // Assessed under ZTR-1145: byte-frozen + verifier exists, no tenant route yet.
    expect(ROUTE_SERVED_PURPOSES).not.toContain("zp-implementer-keyrotation-v1");
  });
});
