/**
 * @zucoins/consumer-example — product-neutral generic-node consumer.
 *
 * Demonstrates the six-step independent verification procedure using only
 * public API surfaces plus the independent verifier pipeline and the
 * node-key pinning workflow.
 *
 * Composition: deposit (RECEIVE_EXTERNAL) → internal_allocation (MOVE_INTERNAL) →
 * external_distribution (SEND_EXTERNAL). No product-layer business states.
 *
 * The verification pipeline and the HTTP wrapping this example wires together now
 * ship as the installable `@zucoins/generic-node-consumer` SDK. This package re-exports that
 * SDK's surface so existing imports of `@zucoins/consumer-example` keep working, and its own
 * source is now purely the worked example (see `worked-example.test.ts`) that shows a merchant
 * implementer how to compose the SDK's HTTP client with its verification pipeline end to end.
 */

export * from "@zucoins/generic-node-consumer";
