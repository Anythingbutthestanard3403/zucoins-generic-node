// The original attack checklist (SSRF, DNS rebinding, redirects, private ranges,
// TLS failure, duplicate delivery, restart, stale events, permanent failure), each mapped to the
// mechanism that neutralizes it. With callbacks removed there is nothing left to attack:
// every transport attack is impossible by construction because the node issues no request to any
// operator-supplied URL, and every replay / stale / duplicate / permanent-failure attack is inert
// because a delivery is never operation truth — the consumer reconciles against the authoritative
// pull cursor (invariant #6). The SSRF URL guard is moot with zero egress. CONTRACT_FREEZE.

import { OPERATION_EGRESS } from "./egress.js";

// The two structural removal facts every attack collapses onto.
export const NEUTRALIZED_BY_EGRESS_ABSENCE = "egress_absence_no_operator_url_request" as const;
export const NEUTRALIZED_BY_PULL_CURSOR = "pull_cursor_authoritative_delivery_is_not_truth" as const;

// Transport-layer attacks — the classic callback-URL surface. Neutralized by construction: the node
// never issues a send-side request to an operator-supplied URL, so there is no request to rebind,
// redirect, TLS-downgrade, or point at a private range.
export const NEUTRALIZED_TRANSPORT_ATTACKS = [
  { attack: "ssrf", classicVector: "node_fetches_operator_callback_url", neutralizedBy: NEUTRALIZED_BY_EGRESS_ABSENCE },
  { attack: "dns_rebinding", classicVector: "callback_host_reresolves_to_internal_ip_after_validation", neutralizedBy: NEUTRALIZED_BY_EGRESS_ABSENCE },
  { attack: "redirect_follow", classicVector: "callback_302_redirects_node_to_internal_target", neutralizedBy: NEUTRALIZED_BY_EGRESS_ABSENCE },
  { attack: "private_range", classicVector: "callback_url_targets_loopback_link_local_or_rfc1918", neutralizedBy: NEUTRALIZED_BY_EGRESS_ABSENCE },
  { attack: "tls_failure", classicVector: "callback_tls_downgrade_or_cert_bypass", neutralizedBy: NEUTRALIZED_BY_EGRESS_ABSENCE },
] as const;

// Replay / delivery-integrity attacks. Neutralized because a delivery is never operation truth: the
// consumer reconciles against the authoritative, gapless, hash-chained pull cursor, so a duplicated,
// reordered, stale, or never-delivered event cannot alter operation state.
export const NEUTRALIZED_REPLAY_ATTACKS = [
  { attack: "duplicate_delivery", classicVector: "same_event_delivered_twice", neutralizedBy: NEUTRALIZED_BY_PULL_CURSOR },
  { attack: "restart_regap", classicVector: "delivery_worker_restart_reorders_or_skips", neutralizedBy: NEUTRALIZED_BY_PULL_CURSOR },
  { attack: "stale_event", classicVector: "late_event_arrives_after_cursor_advanced", neutralizedBy: NEUTRALIZED_BY_PULL_CURSOR },
  { attack: "permanent_failure", classicVector: "delivery_never_succeeds", neutralizedBy: NEUTRALIZED_BY_PULL_CURSOR },
] as const;

// The non-gateway destination classes isEgressAllowed must reject — the shapes an operator callback
// URL would have taken. The freeze test asserts isEgressAllowed(exampleHost, gatewayHosts) === false
// for every class, since none is a configured gateway host.
export const NON_GATEWAY_DESTINATION_CLASSES = [
  { class: "operator_http_url", exampleHost: "operator.example.com" },
  { class: "operator_https_url", exampleHost: "hooks.merchant.example" }, // contract-allow:frozen-attack-surface-example-host
  { class: "dns_rebinding_resolved_ip", exampleHost: "10.0.0.5" },
  { class: "redirect_target_host", exampleHost: "internal.svc.cluster.local" },
  { class: "loopback", exampleHost: "127.0.0.1" },
  { class: "link_local", exampleHost: "169.254.0.1" },
  { class: "cloud_metadata", exampleHost: "169.254.169.254" },
  { class: "rfc1918_private", exampleHost: "192.168.1.1" },
] as const;

export type TransportAttack = (typeof NEUTRALIZED_TRANSPORT_ATTACKS)[number]["attack"];
export type ReplayAttack = (typeof NEUTRALIZED_REPLAY_ATTACKS)[number]["attack"];
export type NonGatewayDestinationClass = (typeof NON_GATEWAY_DESTINATION_CLASSES)[number]["class"];

export interface EgressCensusRow {
  readonly operation: string;
  readonly nonGatewayEgress: string;
}

// True iff an egress census row grants zero non-gateway egress. The egress-dimension negative control:
// a row asserting egress to an operator URL is rejected (returns false).
export function egressRowIsClean(row: EgressCensusRow): boolean {
  return row.nonGatewayEgress === "none";
}

// True iff the frozen per-operation egress census grants zero non-gateway egress across every
// operation — the whole-lifecycle egress-absence proof consumed from the frozen OPERATION_EGRESS.
export function egressCensusIsClean(): boolean {
  return OPERATION_EGRESS.every(egressRowIsClean);
}

// True iff an attack entry is neutralized by one of the two frozen removal mechanisms.
export function attackIsNeutralized(entry: { readonly neutralizedBy: string }): boolean {
  return entry.neutralizedBy === NEUTRALIZED_BY_EGRESS_ABSENCE || entry.neutralizedBy === NEUTRALIZED_BY_PULL_CURSOR;
}
