// The egress-absence contract. With no callback in existence, the node makes ZERO
// send-side HTTP to any non-gateway, non-configured host across the full lifecycle of all three
// operations — so SSRF, DNS-rebinding, and redirect-follow are impossible by construction (the
// load-bearing safety proof of callback removal). This census is a pure verifier consumable by
// the runtime network-containment gate. CONTRACT_FREEZE.

import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.js";

// The only permitted send-side-HTTP destination class for the node. Every other host is forbidden
// egress; there is no operator-supplied-URL egress of any kind.
export const ALLOWED_EGRESS_KIND = "configured_splitchain_gateway_only" as const;

// Every generic operation makes zero non-gateway send-side HTTP over its full lifecycle. Sourced from
// the canonical OPERATION_KINDS/OperationKind (operations.contract.ts) rather than redeclared
// so this concern can never drift from the frozen three-operation set (the scan/dependency-boundary anti-self-reference
// gate: a second declaration of the same literal triple anywhere outside operations.contract.ts is a
// build-time drift risk, not merely a style preference).
export const OPERATIONS = OPERATION_KINDS;
export type OperationName = OperationKind;

export const OPERATION_EGRESS = OPERATIONS.map((operation) => ({
  operation,
  nonGatewayEgress: "none",
})) as ReadonlyArray<{ readonly operation: OperationName; readonly nonGatewayEgress: "none" }>;

// True iff a host is a permitted egress destination — i.e. one of the configured SplitChain gateway
// hosts. An operator-supplied callback URL host is never in this set. the network-containment concern's runtime gate consumes
// this predicate.
export function isEgressAllowed(host: string, configuredGatewayHosts: readonly string[]): boolean {
  return configuredGatewayHosts.includes(host);
}

// True iff an operation makes no non-gateway egress over its lifecycle.
export function operationMakesNoNonGatewayEgress(operation: OperationName): boolean {
  const row = OPERATION_EGRESS.find((r) => r.operation === operation);
  return row?.nonGatewayEgress === "none";
}
