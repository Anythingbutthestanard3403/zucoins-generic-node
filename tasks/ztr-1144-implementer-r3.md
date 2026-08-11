# ZTR-1144 implementer r3 (Review A D3 residual)

**Branch:** `ztr-1144-alert-bindings` (PR #79)  
**Prior head (A FAIL / B PASS):** `8f9add2610f751e8e11d0b65349fdb7414462f85`  
**Claim run:** `6ca599e6-8620-4c9f-9773-68f64eb50f35`

## Blocking residual (Review A)

In-process `queue_caps` lived entirely in `DB_TRUTH_ONLY_SIGNALS`, so during
`databaseTruthAvailable=false` the process `receiveQueueFull503Rate` arm was
dropped with the DB gauges. Prom already split (`GenericNodeReceiveQueueFull503`
without `gn_database_truth_available`); in-process webhook/log stayed silent on
503 during DB outage.

## Fix

`apps/generic-node/src/metrics/custody-alerts.ts`:

- Remove `queue_caps` from fully-gated `DB_TRUTH_ONLY_SIGNALS` (lease /
  attention_backlog / queue_oldest_age stay).
- Hybrid evaluate: when DB-truth is down, zero DB arms
  (`receiveQueueUtilization` / `poolCapUtilization` / `pinnedPoolRatio`) before
  `deriveSafetyAlertReadings`, keep `receiveQueueFull503Rate`, and only include
  `queue_caps` when the 503 arm is live (`> 0`). No 503 + DB down → signal
  omitted (does not clear a prior depth/pool/pinned page with fallback zeros).

D1–D2 r2 wiring untouched.

## Tests

- `metrics-custody-alerts.test.ts`: DB depth alone silent on blip; 503 alone
  pages `queue_caps:P1` on blip.
- `metrics-custody-alerts-bindings.test.ts`: metrics counter → P1 on
  `databaseTruthAvailable=false`; depth/pool/pinned alone still suppressed.

## Docs

Already accurate at r2 (`incidents.md`, `alert-reference.md`,
`generic-node.rules.yml` “mirrors in-process”, `gen-operator-alert-docs.mjs`).
No regen required once in-process matches the claimed split.

## Verification

| Command | Result |
|---|---|
| `tsc -b packages/node-core apps/generic-node` | clean |
| vitest: safety-alerts, metrics, invariant-breach, custody-alerts, custody-alerts-bindings, snapshot-source, graceful-stop, money-workers | **180 passed / 8 files** |
| vitest: operator-docs.census | **38 passed** |
| eslint touched custody-alerts + tests | 0 errors |

## HEAD

`bee5b9fd81accc1f890eca90ba0341225ee504d7`
