# ZTR-1178 implementer r3 — mid-flight sticky-open (FAIL #2)

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/22
- **Branch:** `ztr-1178-reclose-money-path-latch`
- **Plan:** `tasks/plan-ZTR-1178.md` (review PASS)
- **Prior FAIL:** `tasks/ztr-1178-review-B-fe67c76.md` D1/D2 at `fe67c76`
- **Claim run:** `c229a71d-f7a1-4008-95a9-2e8139ece511`

## What landed

### D1 — sticky-open in `CachedDbProbe.cachedReachable()`
`packages/node-core/src/api/health.ts`: when `cachedOk === true` and `inFlight` is set, return `true` without age check. Bound = existing `timeoutMs` race (inFlight clears on settle). Idle stale / last-false / unknown still fail-closed. `refresh()` write path unchanged.

JSDoc no longer claims “at most one TTL old” unconditionally; documents idle one-TTL + mid-flight sticky exception.

### main.ts comment + named deadline
Removed false “always lands before previous ages out”. Documents keep-warm + sticky composition. `DB_PING_DEADLINE_MS = 4_500` named next to keep-warm (behaviour unchanged).

### D2 — tests
- `health-probes.test.ts`: sticky past TTL on last-true; no sticky on last-false; timeout settle clears sticky (short wall `timeoutMs`, not fake-clock alone).
- `money-admission-db-latch.test.ts`: prod-ratio mid-flight converse — TTL=5000, KEEP=2500, hold=3000, sample every 50 ms while `refresh()` pending; `refusedAt === []`. Harness gained deferred `holdPing`.

## Mutation proof (run locally before push)

| mutation | result |
|---|---|
| Remove sticky (`cachedReachable` age-only) | prod-ratio latch test **RED** (refusals from ~5000); sticky-opens unit **RED** |
| Restore TTL short-circuit inside `refresh()` | δ=120 converse **RED** |
| Sticky restored | health-probes 34 + latch 12 **GREEN** |

## Gates at head (post-commit SHA recorded below / in PR)

```
tsc -b                                          → exit 0
node-core: health-probes + deployment-health + boundaries → 124 passed
generic-node: latch + health-routes + health-route-order + boot-lane + graceful-stop + metrics-snapshot-source → 111 passed
lint on health.ts / main.ts / both test files   → clean
```

## Files
- `packages/node-core/src/api/health.ts` — sticky + JSDoc
- `packages/node-core/test/health-probes.test.ts` — 3 new cases
- `apps/generic-node/src/main.ts` — comment + `DB_PING_DEADLINE_MS`
- `apps/generic-node/test/money-admission-db-latch.test.ts` — hold harness + prod-ratio case

## AC / clear-bar disposition
| item | status |
|---|---|
| D1 sticky under prod constants | satisfied |
| D1 main “always” comment fixed | satisfied |
| D2 mid-flight prod-ratio converse | satisfied |
| Prior converse / boot arm / census | still green |
| Sticky-removal mutation red | demonstrated |
