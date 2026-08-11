# ZTR-1154 implementer r2 (Review B rework)

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/58
- **Branch:** ztr-1154-push-envelope-golden
- **Worktree:** /Volumes/Ai Building/.zup-scratch/ztr-1154-impl/
- **Claim:** run=112a8315-6c78-4736-94dc-a0613d523e40

## Review B defects addressed

1. **Golden authenticity** — Replaced reconstructed mini-nest with full D8.92 / wallet-SW delivered cleartext (`title`/`body`/`data.{id,type_name,type_data}`). `originKind` corrected to **`canonical-constructor`** (honest supersession: no live post-decrypt FCM/APNs capture available). meta.json + fixture provenance document AC supersession with merchant `notificationBody()` + SW §505-543 citations. Digest `5528e5a1…0df02f42`.
2. **Pageable alert** — Added `SAFETY_ALERT_SIGNALS` / rule / `DEFAULT_ALERT_THRESHOLDS` entry `push_no_transfer_code_streak` (P1, ≥20). `composePush` dispatches via `safetyAlertEvaluator.evaluateAndDispatch` (main wires `custodyAlertEvaluator`). Prom rule `GenericNodePushNoTransferCodeStreak` on `gn_push_no_transfer_code_streak >= 20`. incidents + generated alert-reference + SIGNAL_WIRING bound.
3. **Gauge order** — `createPushReceiveMetricsPort` observes streak **before** sink; threshold event publishes **20** not 19. Unit + compose-mirror integration tests.

## Verify

- tsc -b node-core, contracts, generic-node: pass
- safety-alerts 44; push-payload-and-seal 39; provenance 29; streak.alert 2; operator-docs.census 35; custody-alerts 12 — pass

## Head (post-push)
