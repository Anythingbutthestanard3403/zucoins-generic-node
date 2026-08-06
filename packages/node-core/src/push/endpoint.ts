// Opaque per-wallet push `endpoint_id` and the node's own receive URL (inbound push receivers).
//
// The token, never the wallet pubkey, appears in the URL: the endpoint is handed to a
// third-party push service, so putting the pubkey there would leak the wallet set to
// anyone who observes a subscription. 20 random bytes = 160 bits, over the >=128-bit floor.

import { randomBytes } from "node:crypto";

const ENDPOINT_ID_RANDOM_BYTES = 20;

/** `wp_` + 160 bits of base64url randomness. */
export function generateEndpointId(): string {
  return `wp_${randomBytes(ENDPOINT_ID_RANDOM_BYTES).toString("base64url")}`;
}

/**
 * Shape of the endpoint id, used to reject a malformed path segment before it reaches
 * the store. Anchored so a traversal or injection attempt cannot match.
 */
export const ENDPOINT_ID_PATTERN = /^wp_[A-Za-z0-9_-]{20,64}$/u;

export function isValidEndpointId(candidate: string): boolean {
  return ENDPOINT_ID_PATTERN.test(candidate);
}

/** The node's own per-wallet Web Push receive URL. */
export function buildPushEndpointUrl(nodePublicUrl: string, endpointId: string): string {
  return `${nodePublicUrl.replace(/\/+$/u, "")}${PUSH_RECEIVER_PATH_PREFIX}/${endpointId}`;
}

/** Path prefix the receiver route mounts on; shared so URL build and route match cannot drift. */
export const PUSH_RECEIVER_PATH_PREFIX = "/v1/receivers/push";
