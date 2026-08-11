# ZTR-1144 implementer

**HEAD:** `64b146f7be93b1a89b317b31e480bdc12d193214`
**Branch:** `ztr-1144-alert-bindings`
**Base:** `origin/main` @ `db3f5f0`

## Governing spec
- Doc 09 §9.1 / §11 (alert catalogue + P0 posture) via ticket + `docs/operations/*`
- In-process rules: `packages/node-core/src/operator/safety-alerts.ts`
- Prometheus rules: `docs/operations/alerts/generic-node.rules.yml`

## Acceptance
- [x] `gn_invariant_breach_total` emitted (`applyMoveInvariantBreachQuarantine.onQuarantineApplied` + receive-expiry INVARIANT_BREACH) and bound to P0
- [x] `duplicateSubmitRejectionCount` from submit_decisions mint loser (move + receive)
- [x] `regression` / `path_gap` / `endpoint_disagreement` / `receiveQueueFull503Rate` / `signerInFlightAmbiguous` bound to real counters/stamps
- [x] `gn_operations_attention_required` gauge + `attention_backlog` signal
- [x] `gn_t0_read_failures_total` → `gateway_read_failure`; `gn_receive_queue_oldest_age_seconds` → `queue_oldest_age`
- [x] Webhook channel + `OPERATOR_ALERT_WEBHOOK_URL` (https, no credentials); P0/P1 escalate log+webhook
- [x] Fallback guard preserved (DB-truth signals omitted when `databaseTruthAvailable=false`)
- [x] E2E test: inject breach → P0 webhook POST (`metrics-custody-alerts-bindings.test.ts`)
- [x] Alert rules committed + operator docs regenerated

## Verify @ 64b146f7be93b1a89b317b31e480bdc12d193214
- `tsc -b`: clean
- `@zucoins/node-core` vitest safety-alerts + metrics: **61 passed**
- `apps/generic-node` vitest custody bindings + custody alerts + operator docs census + snapshot-source: **71 passed**
- lint: eslint packages clean (pre-existing warnings only)

## Files
Core metrics/alerts, custody composition, producers (breach/duplicate/503/endpoint), env webhook, Prom rules, gen docs, tests.
