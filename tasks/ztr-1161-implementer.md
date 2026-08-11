# ZTR-1161 implementer

## Decision
**Option 1 — wire VAPID** (default `PUSH_VAPID_MODE=observe`).

## Live Authorization header
No byte-level capture of a production `POST /v1/receivers/push/:id` was available this session (wallet API Cloudflare 1010 from this host; no prod node `push.receiver_inbound` logs). Protocol/spec evidence that deliveries are designed to carry `Authorization: vapid t=…, k=…`:
- Merchant Wallets `docs/04-PAYMENT-FLOW-SPEC.md` §4.3
- Merchant Wallets production receiver verifies VAPID on that header
- SplitChain `push_notification__get_app_server_public_key__v1__*` trust root is fetched/stored for this check

**Rollout proof path:** ship observe → `gn_push_vapid_total{outcome=…}` + `push.receive_vapid` audits on live traffic → flip `PUSH_VAPID_MODE=enforce` when ACTIVE rows have keys and verified dominates.

## Changes
- `PushSubscriptionRow.appServerPublicKey` + SQL `SELECT_COLS`
- `createPushReceiver` VAPID gate (observe/enforce); outcome counter hook
- Route reads single `Authorization`; uniform 204 unchanged
- `gn_push_vapid_total` / `MetricsHooks.onPushVapid`
- `PUSH_VAPID_MODE` env (first-boot, default observe)

## Verify
- `tsc -b` green
- push-* + config + transport tests green
- `boundaries` app-shell allowlist miss for `generic-node-contracts/observation` is pre-existing on origin/main (unrelated)

## Head SHA
`e922e94609d4895131330d4a978919cf24617a7a`
