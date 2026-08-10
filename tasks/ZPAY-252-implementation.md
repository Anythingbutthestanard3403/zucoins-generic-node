# ZPAY-252 — generic-node signer-leadership handover (implementer)

## Problem
Railway zero-downtime keeps OLD until NEW `/health/ready` 200. NEW blocked on
signer leadership (and EVENT_SIGNING ensure after leadership) → never ready →
OLD never SIGTERM'd → deadlock. Staging: three FAILED deploys.

## Design (D8.102 class; contracts already said READY without leadership)
1. **Deploy-ready without leadership:** boot lane runs gateway-read **before**
   signer-leadership so schema ∧ vault ∧ observation can pass while waiting.
2. **EVENT_SIGNING off `/health/ready`:** ZTR-1179 made `eventSignerAvailable`
   verdict-forcing on ready, but ensure runs only after leadership — that
   re-coupled ready to the lock. Money admission still refuses without it.
3. **Wait-for-handover (no short hard timeout):** leadership acquire waits until
   prior holder releases or SIGTERM aborts. `SIGNER_LEADERSHIP_RETRY_MAX_MS` is
   now a prolonged-wait **warn** threshold only (default 30s).
4. **Logs (AC3):** `waiting-for-handover` vs `prolonged wait` (wedged prior).

## AC
| AC | Status |
|----|--------|
| AC1 new instance ready while previous holds lock | **satisfied** — gateway before leadership; eventSigner non-gating on ready |
| AC2 exactly one signer | **satisfied** — session advisory lock + money workers only after acquire |
| AC3 boot log handover vs deadlocked | **satisfied** — waiting-for-handover / prolonged wait |
| AC4 treasury node boot lane shape | **confirmed shared** — apps/node D8.102 already: bind + markBootComplete before background NODE_ALIVE; money engines post-lock. Generic-node now matches. |

## Governing
- Decision: D8.102 (treasury precedent); readiness contracts
  `readiness_reachable_before_leadership`
- Spec: docs/proposals/generic-node-redesign-v2/03-node-core.md § leadership;
  packages/generic-node-contracts readiness predicates

## Verification (exact head recorded at PR open)
```
pnpm --filter @zucoins/node-core exec tsc -b
pnpm --filter @zucoins/generic-node exec tsc -b
pnpm --filter @zucoins/node-core exec vitest run test/health-probes.test.ts test/deployment-health.test.ts
  → 2 files, 53 passed
pnpm --filter @zucoins/generic-node exec vitest run \
  test/boot-lane.test.ts test/readiness.test.ts test/health-routes.test.ts \
  test/event-signer-authority.test.ts test/config-schema.test.ts \
  test/deployment-scenarios.test.ts test/reference-deployment.test.ts \
  test/health-route-order.test.ts test/money-admission-db-latch.test.ts
  → 9 files, 211 passed
pnpm --filter @zucoins/node-core lint  → 0 errors
pnpm --filter @zucoins/generic-node lint → 0 errors
```

## Files
- `packages/node-core/src/api/health.ts` — eventSigner off ready verdict
- `packages/node-core/src/core/{readiness-state,money-admission}.ts` — docs; money keeps eventSigner
- `apps/generic-node/src/boot/boot-lane.ts` — gateway before leadership
- `apps/generic-node/src/boot/signer-leadership-retry.ts` — handover/prolonged logs, no hard cap
- `apps/generic-node/src/boot/readiness.ts` — shell ready = schema∧vault∧gateway
- `apps/generic-node/src/main.ts` — SIGTERM abort on leadership wait
- `apps/generic-node/src/config/env-schema.ts` — prolonged-wait semantics
- tests updated for order + money-only eventSigner

## Repo
Work landed in **zucoins-generic-node** (generic-node trees removed from zupayments monorepo).
