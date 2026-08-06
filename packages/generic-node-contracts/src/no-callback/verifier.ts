// Pure verifiers over the no-callback contract. The attack census (egress-absence + cursor-authority
// tests) and the network-containment concern's runtime network-containment gate consume these. All checks are structural.
//

import { REJECTED_SURFACES } from "./rejected-surfaces.js";
import { isEgressAllowed } from "./egress.js";
import { deepFreeze } from "./deep-freeze.js";

export interface ChannelShape {
  readonly channel: string;
  readonly egress: string;
}
export interface CanonicalChannelShape {
  readonly channel: string;
  readonly egress: string;
  readonly role: string;
}
export interface GuardrailShape {
  readonly active: boolean;
}

// Defect-1 correction: a verifier-internal, structurally independent frozen copy of the sole
// authoritative channel set. It is declared here — NOT imported from channels.ts's exported
// AUTHORITATIVE_CHANNELS — so a runtime mutation of that export, or a swapped channels module,
// cannot poison the verifier's own expectation. A freeze test asserts the two declarations agree,
// so honest drift is caught while a malicious mutation is not trusted.
const CANONICAL_AUTHORITATIVE_CHANNELS = deepFreeze([
  { channel: "pull_events", egress: "none_node_serves_pull", role: "authoritative_cursor" },
  { channel: "sse_stream", egress: "none_node_serves_pull", role: "low_latency_wake_accelerator" },
  { channel: "snapshot", egress: "none_node_serves_pull", role: "bootstrap_reconciliation" },
] as const);

// True iff a surface is one of the rejected node-initiated callback surfaces.
export function isRejectedSurface(surface: string): boolean {
  return REJECTED_SURFACES.some((s) => s.surface === surface);
}

// True iff an operator-supplied callback URL host is forbidden egress — it is never a configured
// gateway host, so a node-initiated request to it can never be made (the egress-absence proof).
export function callbackHostForbidden(host: string, configuredGatewayHosts: readonly string[]): boolean {
  return !isEgressAllowed(host, configuredGatewayHosts);
}

// True iff every authoritative channel is served by the node in the pull direction with zero node
// egress — so the sole delivery channel is the authoritative pull cursor, not a push.
export function soleChannelIsAuthoritativePull(channels: readonly ChannelShape[]): boolean {
  return channels.length > 0 && channels.every((c) => c.egress === "none_node_serves_pull");
}

// True iff `channels` is EXACTLY the canonical authoritative channel set — same channels, same
// egress, same role, same sequence, with no extra, missing, or mutated row. Unlike
// soleChannelIsAuthoritativePull (a structural predicate that admits ANY zero-egress set), this
// pins the verifier-internal frozen oracle, so an injected disguised channel — even one lying
// `egress: "none_node_serves_pull"` under an accelerator role — is rejected. the network-containment concern's runtime
// network-containment gate should assert this, not merely the structural predicates.
export function authoritativeChannelsAreCanonical(channels: readonly CanonicalChannelShape[]): boolean {
  if (channels.length !== CANONICAL_AUTHORITATIVE_CHANNELS.length) return false;
  return CANONICAL_AUTHORITATIVE_CHANNELS.every((expected, i) => {
    const actual = channels[i];
    return (
      actual !== undefined &&
      actual.channel === expected.channel &&
      actual.egress === expected.egress &&
      actual.role === expected.role
    );
  });
}

// True iff the residual push guardrail is inert — it is not active unless operator re-admits push.
export function residualGuardrailInactive(guardrail: GuardrailShape): boolean {
  return guardrail.active === false;
}
