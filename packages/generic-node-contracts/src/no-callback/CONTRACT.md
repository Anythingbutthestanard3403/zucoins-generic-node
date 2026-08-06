# no-callback — CONTRACT

Freeze slice: **resolve callback inclusion and contract** (depends on the reporting concern).
Gate: `CONTRACT_FREEZE`.

Governing sources: the API contract's callback section; operation flows. Decision:
**`no-callback-removal`** — REMOVE `callback_url` and every node-initiated callback; the
signed pull event stream + SSE + snapshot frozen by `reporting-channel` is the sole
authoritative channel.

## The resolution (remove callbacks)

`no-callback-removal` removes callbacks on every lens (product-neutral, minimum-surface,
build-once, self-custody): a node-initiated send-side HTTP request to an operator-supplied URL is
a live SSRF / DNS-rebinding / redirect primitive on exactly the key-holding self-custody node; it
violates the three-generic-operations scope (a webhook is an implementer projection, and
`callback_url` appeared only on `RECEIVE_EXTERNAL`); and it is redundant + non-authoritative next
to the gapless, hash-chained pull cursor.

## What is frozen (`src/no-callback/`)

- **`rejected-surfaces.ts` — `REJECTED_SURFACES`.** The `callback_url` field, callback registration,
  node-initiated delivery worker, and callback retry queue, each with its removal ground, kept as
  data so no push surface can be silently reintroduced.
- **`egress.ts` — the egress-absence contract.** The node's only permitted egress is the configured
  SplitChain gateway; every operation (RECEIVE/MOVE/SEND) makes zero non-gateway egress over its
  lifecycle, so SSRF/DNS-rebinding/redirect-follow are impossible by construction. `isEgressAllowed`
  is a pure predicate the runtime network-containment gate consumes.
- **`channels.ts` — the sole authoritative channel.** The `reporting-channel` pull events + SSE +
  snapshot, all node-served in the pull direction with zero egress, carrying the reporting
  concern's `zp-node-event-v1`. A webhook/push is the relocated implementer-layer webhook
  projection.
- **`residual-guardrail.ts` — inert conditional data.** The residual push guardrail (the
  `ssrf-url-guard` guard, no-cursor-advance, event_id dedup, non-authority statement) applies ONLY
  if a future decision re-admits push; it is frozen `active: false` so a re-admission would have a
  frozen contract to land on.

## Surfaces struck from the API and flow contract

The removal is applied, not merely declared: the request body carries no `callback_url` field and
no field note for one; the receive-creation flow registers no callback (the subscription-handle
hash stays); the event-serving flow states that no push/callback channel exists; and the
event-serving section is titled "Event ordering" — the callback bullets do not exist, while the <!-- contract-allow:frozen-spec-section-title -->
cursor-authoritative and SSE-accelerator bullets stand. The separate statement that "an
application callback is not landing proof" is deliberately KEPT: it describes a recipient-relayed
claim the node ignores, unrelated to the removed field.

## Consuming the reporting and event concerns

The freeze test asserts `AUTHORITATIVE_EVENT_PURPOSE` equals the reporting concern's
`NODE_EVENT_PURPOSE` and that the cursor's authoritative gap detector is the events concern's hash
chain — the pull cursor is provably complete, which is exactly why a push is redundant and
non-authoritative (the removal grounds).

## Scope handoff + negatives

CONTRACT_FREEZE only. There is no "define callback contract" follow-on slice: the removal
decision cancels it. One negative per fact class (kept-channel-not-over-struck, forbidden egress,
push-channel rejection, guardrail activation) is present and demonstrated to fire.

---

# no-callback — CONTRACT (attack callback transport and replay)

Freeze slice: **attack callback transport and replay**. Scope follows `no-callback-removal`: with
callbacks removed there is no transport to attack, so this slice freezes tests proving the removal
holds by construction rather than testing a live callback worker. Kept separate from the first
slice's `gen/no-callback.json` — earlier slices win — via its own frozen artifact
`gen/attack-surface.json`.

## What is frozen (`src/no-callback/`)

- **`attack-surface.ts`.** The attack checklist mapped to its neutralization:
  `NEUTRALIZED_TRANSPORT_ATTACKS` (SSRF, DNS-rebinding, redirect-follow, private-range, TLS-failure) all
  neutralized by egress-absence — the node issues no request to any operator URL; `NEUTRALIZED_REPLAY_ATTACKS`
  (duplicate delivery, restart re-gap, stale event, permanent failure) all neutralized because a delivery
  is never operation truth (invariant #6); and `NON_GATEWAY_DESTINATION_CLASSES` — the exact host classes
  `isEgressAllowed` must reject (operator http/https URLs, DNS-rebinding IPs, redirect targets, loopback,
  link-local, cloud-metadata `169.254.169.254`, RFC1918).
- **`cursor-authority.ts`.** The pull cursor + node-global hash chain is the sole authority;
  `pullIsSoleCursorAuthority` (SSE never holds the authoritative role), `sseModelKeepsCursorAuthority`
  (SSE never advances a cursor), `sparseTenantViewIsComplete` (consumes the reporting concern's
  `evaluateTenantSeq` + the events concern's `GAP_DETECTION`), and `gapDetectorIsChainNotContiguity`
  (consumes the events concern's `gapDetectorIsHashChain`).
- **`attack-manifest.ts` / `gen/attack-surface.json`.** The serialized census the freeze gate snapshots.

## The package census (no callback identifier outside REJECTED_SURFACES)

`attack-transport.freeze.test.ts` walks every `.ts`/`.json` under `src/` and asserts no callback
FIELD/ROUTE/WORKER identifier (`callback_url`, `callback_registration`, `callback_retry`, a node
delivery worker, or a `/callbacks` route) exists in any concern other than `no-callback`, and that in
the live no-callback contract the identifiers appear ONLY inside `REJECTED_SURFACES`. Both censuses
carry a positive control (the detector is proven to fire on the rejected data) so neither is vacuously
green.

## Negatives (one per dimension)

Egress dimension: an egress-allowing model (`nonGatewayEgress: "operator_url"`, and an operator host
passed to `isEgressAllowed`) is rejected. Cursor dimension: an SSE-advances-cursor model, and a model
promoting SSE to the authoritative-cursor role, are rejected. Demonstrated to fire.
