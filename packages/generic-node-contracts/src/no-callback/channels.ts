// The sole authoritative delivery channel. The signed pull
// event stream + SSE + snapshot is the only delivery surface; a webhook/push is a named
// implementer-layer feature (the implementer-webhook projection), built on the platform's
// own infrastructure from the pull stream it already consumes for invariant-#6 verification.
// CONTRACT_FREEZE.

import { deepFreeze } from "./deep-freeze.js";

// The authoritative channels. All are PULL/served by the node with zero node egress; SSE is the
// low-latency wake accelerator over the same durable event row. Deep-frozen at module init so the
// exported set is immutable at runtime (defect-1 correction): a `readonly` tuple is mutable at
// runtime, and both the manifest and the runtime-gate verifiers read this same reference, so an
// injected node-push channel could otherwise poison actual and expected alike.
export const AUTHORITATIVE_CHANNELS = deepFreeze([
  { channel: "pull_events", route: "GET /v1/events", egress: "none_node_serves_pull", role: "authoritative_cursor" },
  { channel: "sse_stream", route: "GET /v1/events/stream", egress: "none_node_serves_pull", role: "low_latency_wake_accelerator" },
  { channel: "snapshot", route: "GET /v1/state/snapshot", egress: "none_node_serves_pull", role: "bootstrap_reconciliation" },
] as const);

// The event tuple the authoritative channel carries — must equal reporting-tuples' frozen node-event purpose.
export const AUTHORITATIVE_EVENT_PURPOSE = "zp-node-event-v1" as const;

// The webhook relocation: a named implementer/platform-layer feature, NOT a generic-node surface.
// Deep-frozen for the same defect-1 reason (its `grounds` array is otherwise runtime-mutable).
export const WEBHOOK_RELOCATION = deepFreeze({
  owner: "implementer_platform_layer",
  name: "zupayments_merchant_webhook_projection",
  builtFrom: "the_authoritative_pull_stream",
  grounds: [
    "platform_layer_owns_webhooks",
    "pull_stream_is_sole_authority",
    "zero_node_egress",
    "ssrf_url_guard",
  ],
} as const);
