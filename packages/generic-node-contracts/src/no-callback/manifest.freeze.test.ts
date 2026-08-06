// Freeze + census gate for the no-callback contract (generic callbacks removed).
//
// Consumes reporting-tuples' node-event purpose and event-sequencing's gapless-cursor fact. Proves: (a) the manifest
// matches the golden; (b) every node-initiated callback surface is rejected; (c) the node makes zero
// non-gateway egress across all three operations and an operator callback URL host is forbidden;
// (d) the sole authoritative channel is the pull cursor carrying zp-node-event-v1;
// (e) the residual guardrail is inert; and (f) a negative per fact class.
import { describe, expect, it } from "vitest";

import golden from "./gen/no-callback.json" with { type: "json" };
import { NODE_EVENT_PURPOSE } from "../reporting-tuples/index.js";
import { GAP_DETECTION } from "../event-sequencing/index.js";
import {
  AUTHORITATIVE_CHANNELS,
  AUTHORITATIVE_EVENT_PURPOSE,
  OPERATIONS,
  RESIDUAL_GUARDRAIL,
  callbackHostForbidden,
  isEgressAllowed,
  isRejectedSurface,
  operationMakesNoNonGatewayEgress,
  residualGuardrailInactive,
  soleChannelIsAuthoritativePull,
} from "./index.js";
import { buildNoCallbackManifest } from "./manifest.js";

const GATEWAY_HOSTS = ["gateway.splitchain.test"] as const;

describe("no-callback manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildNoCallbackManifest()).toEqual(golden);
  });
});

describe("no-callback census: every node-initiated callback surface is rejected", () => {
  it("the callback_url field and all node-initiated surfaces are rejected", () => {
    expect(isRejectedSurface("callback_url_request_field")).toBe(true);
    expect(isRejectedSurface("callback_registration")).toBe(true);
    expect(isRejectedSurface("node_initiated_delivery_worker")).toBe(true);
    expect(isRejectedSurface("callback_retry_queue")).toBe(true);
    // Not over-struck: the kept pull channel (subscription handle) is NOT a rejected surface.
    expect(isRejectedSurface("subscription_handle")).toBe(false);
  });
});

describe("egress-absence (the removal safety proof; feeds the runtime network-containment gate)", () => {
  it("every operation makes zero non-gateway egress", () => {
    for (const op of OPERATIONS) {
      expect(operationMakesNoNonGatewayEgress(op)).toBe(true);
    }
  });

  it("only the configured gateway host is permitted egress; a callback URL host is forbidden", () => {
    expect(isEgressAllowed("gateway.splitchain.test", GATEWAY_HOSTS)).toBe(true);
    expect(callbackHostForbidden("attacker.example.com", GATEWAY_HOSTS)).toBe(true);
  });
});

describe("sole authoritative channel (consumes reporting-tuples / event-sequencing)", () => {
  it("all authoritative channels are node-served pull with zero egress", () => {
    expect(soleChannelIsAuthoritativePull(AUTHORITATIVE_CHANNELS)).toBe(true);
  });

  it("the authoritative channel carries zp-node-event-v1 over the gapless cursor", () => {
    expect(AUTHORITATIVE_EVENT_PURPOSE).toBe(NODE_EVENT_PURPOSE);
    // The pull cursor is provably complete (gapless + hash-chained), so a push is redundant and
    // non-authoritative — the grounds for removal.
    expect(GAP_DETECTION.authoritativeGapDetector).toBe("previous_event_hash_chain");
    expect(GAP_DETECTION.seqContiguityIsGapDetector).toBe(false);
  });
});

describe("residual guardrail is inert (conditional on operator re-admitting push)", () => {
  it("the guardrail is inactive and gated on an operator override", () => {
    expect(residualGuardrailInactive(RESIDUAL_GUARDRAIL)).toBe(true);
    expect(RESIDUAL_GUARDRAIL.appliesOnlyIf).toBe("operator_overrides_no_callback_removal_to_re_admit_push");
  });
});

describe("no-callback negative path (one per fact class)", () => {
  it("rejected surfaces: a kept pull channel is not falsely rejected", () => {
    expect(isRejectedSurface("sse_stream")).toBe(false);
  });

  it("egress: an operator-supplied host is not allowed egress", () => {
    expect(isEgressAllowed("attacker.example.com", GATEWAY_HOSTS)).toBe(false);
  });

  it("sole channel: a node-egress push channel is rejected", () => {
    expect(soleChannelIsAuthoritativePull([{ channel: "node_push", egress: "node_egress_to_operator_url" }])).toBe(false);
  });

  it("residual guardrail: activating it without an operator override is rejected", () => {
    expect(residualGuardrailInactive({ active: true })).toBe(false);
  });
});
