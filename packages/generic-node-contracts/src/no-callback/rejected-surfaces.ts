// The removed callback surfaces. REMOVE means actively striking `callback_url`
// and every node-initiated callback surface, not merely declining to add: a node-initiated send-side
// HTTP request to an operator-supplied URL is a live SSRF / DNS-rebinding / redirect primitive on
// exactly the self-custody key-holding machine that must never reach outward.
// The signed pull cursor + SSE + snapshot is the sole channel. CONTRACT_FREEZE.

// Each rejected surface with its removal ground. Kept as data so a future edit cannot silently
// reintroduce a node-initiated push surface; the census test asserts each is rejected.
export const REJECTED_SURFACES = [
  {
    surface: "callback_url_request_field",
    location: "api contract: POST /v1/receives",
    ground: "scope violation — present only on RECEIVE_EXTERNAL, a checkout-notification leak; the field pointed at no backend", // contract-allow:frozen-rejected-surface-ground-text
  },
  {
    surface: "callback_registration",
    location: "operation-flow: callback registration step",
    ground: "node-initiated push has no endpoint auth contract (PULL-only, no HMAC/bearer); redundant with the authoritative pull cursor",
  },
  {
    surface: "node_initiated_delivery_worker",
    location: "(never added)",
    ground: "outbound HTTP to an operator-supplied URL is a live SSRF/DNS-rebinding/redirect primitive on the key-holding node", // contract-allow:frozen-rejected-surface-ground-text
  },
  {
    surface: "callback_retry_queue",
    location: "(never added)",
    ground: "push is at-least-once and gap-silent; invariant #6 forbids trusting a node push, so a callback can never be load-bearing",
  },
] as const;

export type RejectedSurface = (typeof REJECTED_SURFACES)[number]["surface"];
