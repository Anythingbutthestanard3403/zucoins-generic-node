# ZTR-1144 implementer r2 (dual-FAIL clearance)

**Branch:** `ztr-1144-alert-bindings` (PR #79)
**Base:** rebased onto `origin/main` @ `b66163e`
**Prior failed head:** `ea568d828c4e1312cbf7ede239a631be7ce85491`

## Dual-FAIL defects cleared

| ID | Defect | Fix |
|---|---|---|
| D1 | `onQuarantineApplied` dead / MOVE park silent / sibling silence | (1) `applyMoveBreachOperatorAction` forwards `onQuarantineApplied`; (2) MOVE park + re-raise commit paths call `metricsHooks.onInvariantBreach()` when `outcome.kind === "INVARIANT_BREACH"`; (3) boot-recovery `onInvariantBreach` when `invariantBreach` true, wired from `main` → `metricsHooks`; (4) receive-expiry producer retained; (5) non-tautology tests on apply + operator action + composition source ratchet |
| D2 | `signerInFlightAmbiguous` used full `inflightCount` | `ShutdownRegistry.signingInflightCount` only via `setSigningInflightTracker` / `signUnderLease`; main stamp uses it; money-tick drain rebound to `trackInflight` (not authority signing tracker) |
| D3 | Prom `queue_caps` DB-gated the 503 arm | Split `GenericNodeReceiveQueueFull503` without DB-truth conjunct; depth/pool/pinned stay DB-gated |

## SIGNAL_WIRING / docs
Regenerated `alert-reference.md` + `escalation-matrix.md`; incidents `queue_caps` notes 503 not DB-gated.

## Verification (pre-push)
- `tsc -b`: clean
- node-core vitest safety-alerts + metrics + invariant-breach: **95 passed**
- generic-node vitest custody bindings/alerts/snapshot + operator-docs + money-workers + graceful-stop: **120 passed** (psql teardown ETIMEDOUT env flake after green)
- lint node-core + generic-node: 0 errors (pre-existing warnings only)

## HEAD


