# ZTR-1178 — rework: re-close the money-admission DB latch as a probe-derived conjunct

Branch `ztr-1178-reclose-money-path-latch`, extends PR #22 (previous head `d46fe1f`).
Governing: `packages/node-core/src/core/readiness-state.ts:5` — `database_reachable` is
deliberately NOT a stamped input, it is live-probed, "because a stamp cannot represent a
condition that changes".

The ticket's diagnosis and the deletion of the old mutable `databaseReachableForMoney`
latch are unchanged — both reviewers credited them. Only the replacement mechanism (the
keep-warm freshness path and the boot arm) is reworked.

## Blocker 1 — keep-warm cadence structurally cannot pre-empt TTL expiry

**Chosen fix: option (b) — a `refresh()` path that bypasses the TTL short-circuit,
performs a real ping, and re-dates `cachedAtMs`.**

`packages/node-core/src/api/health.ts` — `probe()`'s body after the TTL check was extracted
verbatim into a new public `refresh()`; `probe()` now reads

```ts
async probe(): Promise<boolean> {
  const now = this.clock();
  if (this.cachedOk !== undefined && now - this.cachedAtMs < this.ttlMs) {
    return this.cachedOk;
  }
  return this.refresh();
}
```

`apps/generic-node/src/main.ts:310` drives the keep-warm interval through
`dbProbe.refresh()` instead of `dbProbe.probe()`.

### Why (b) and not (a)

Option (a) — giving `cachedReachable()` a staleness horizon `maxAgeMs > ttlMs` — closes the
observed window but couples three constants and weakens the freshness bound:

With keep-warm `= ttlMs/2` and a `probe()`-driven timer, the *effective* refresh period is
`1.5 × ttlMs`, not `ttlMs/2` — verdict dated at `t0`; the tick at `ttlMs/2` is swallowed;
the tick at `ttlMs` re-pings and re-dates to `ttlMs + δ`; the ticks at `1.5 ttlMs` and
`2 ttlMs` are then *both* swallowed (ages `ttlMs/2 − δ` and `ttlMs − δ`); the next real ping
is at `2.5 ttlMs`. So (a) needs `maxAgeMs ≥ 2 × ttlMs` to be safe, which means money
admission would act on a verdict up to two TTLs old, and any later change to the cadence
silently re-opens the window.

Option (b) fixes the mechanism instead of widening the tolerance. Every tick re-dates, so
the age at any read is `≤ keepWarmMs + δ`, the admission-freshness bound stays at exactly
one TTL, and `cachedReachable()` is untouched. No asymmetry to document because none is
introduced.

Reviewer-A's rejected alternative (`invalidate()` + `probe()`) is explicitly not used:
`invalidate()` clears `cachedOk`, so the gate would read closed for the duration of every
refresh ping — a self-inflicted outage once per cadence. `refresh()` leaves the last
verdict readable throughout its ping; that is pinned by a dedicated test.

## Blocker 2 — boot-arm crash-loop regression

`apps/generic-node/src/main.ts:910` — the post-migration arm is now
`await dbProbe.refresh()`, guaranteeing a real ping. Previously `await dbProbe.probe()`
would be served the `false` planted by a single failed keep-warm tick (the timer starts at
`main.ts:311`, before `assertPostMigrationReadiness` runs) and fail a boot whose pool
`assertSchemaCompleteness` and `assertPrivilegeReadiness` had both just passed.

`refresh()` is correct here for the same reason `invalidate()` + `probe()` would also have
been acceptable at this one call site (a one-shot boot gate, not the periodic refresh) —
but `refresh()` needs no second call and no cache-blanking window, so it is used for both.

## Blocker 3 — the tautological test

`apps/generic-node/test/money-admission-db-latch.test.ts:167-173` (source-string +
`setInterval` regex only) is replaced by real behaviour:

1. **`stays admitted across keep-warm cycles while the database is up`** — the converse of
   AC3 the suite never asked. Samples `assertMoneyAdmitted()` every 50 ms of virtual time
   across four keep-warm cadences with a **non-zero ping cost (δ = 120 ms)**, and asserts
   zero refusals plus `pings.length ≥ 4`.
   Two modelling points that matter, both learned the hard way:
   - the harness now charges the clock for the ping (`nowMs += pingCostMs` inside the ping).
     δ = 0 is the single degenerate case where the staleness window vanishes, which is why
     the original harness could not see the bug;
   - the tick schedule starts at `t = 0` and the boot arm happens at `t = 300`, because
     `main.ts` creates the interval at boot and arms the probe later from
     `assertPostMigrationReadiness`. Phase-locking the ticks to the arm makes an expiry land
     exactly on a tick and hides the window (an earlier draft of this test did exactly that
     and only caught the mutation on the weaker ping-count assertion).
2. **`the boot arm re-pings after a failed keep-warm tick inside the TTL`** — reviewer-B's
   D2 reproduction as a behavioural test: failed tick at t=2500, arm at t=3000, must ping
   again and admit.
3. Census cases retained but retargeted: `the keep-warm timer calls refresh(), not probe()`
   and `the post-migration arm is a real ping, not a cached verdict`. These are deliberately
   kept — the behavioural drill proves `refresh()` holds the verdict open, but only a source
   census proves `main.ts` is the thing calling it. A `probe()` timer type-checks and reads
   correctly; nothing but the census notices the one-word difference. Neither is tautological
   alone in the way the deleted case was, because the property each names is now proven
   behaviourally elsewhere in the same file.

Added at the mechanism's own level in `packages/node-core/test/health-probes.test.ts`:

4. `refresh() re-pings and re-dates inside the TTL, where probe() short-circuits`
5. `refresh() leaves the last verdict readable while its ping is in flight` (the
   anti-`invalidate()` guard)

### Mutation proof — the new tests bite

Mutation applied to `refresh()` in `health.ts`, reinstating `probe()`'s TTL short-circuit
(i.e. restoring the shipped-broken same-TTL mechanism at source):

```ts
const nowMut = this.clock();
if (this.cachedOk !== undefined && nowMut - this.cachedAtMs < this.ttlMs) {
  return this.cachedOk;
}
```

| suite | unmutated | mutated |
|---|---|---|
| `apps/generic-node/test/money-admission-db-latch.test.ts` | 11 passed | **1 failed** / 10 passed |
| `packages/node-core/test/health-probes.test.ts` | 31 passed | **2 failed** / 29 passed |

The latch failure is on the property that matters, not a proxy:

```
AssertionError: expected [ 5420, 5470, 5520, 5570, 5620, …(37) ] to deeply equal []
```

42 refusal samples on a database that never fails — the window opens at t=5420 (verdict
dated 420, TTL 5000) and stays open until the tick at t=7500 finally re-pings. That is the
~1-in-3 refusal rate both reviewers measured, reproduced deterministically.

The deleted tautological case survives the mutation, which is why it is deleted.

## Non-blocking items (both fixed)

- **`main.ts:912` discarded the driver error.** `refresh()` collapses a ping failure to
  `false`, so the boot-fail throw now re-issues `pingDb()` once — on the failure path only,
  where the process is already crashing — and attaches the result as `{ cause }`.
- **`dbProbeKeepWarm` is never `clearInterval`'d on graceful stop — left as-is, on purpose.**
  I implemented this first and then backed it out. `boot/graceful-stop.ts:121` calls
  `stopWorkers()` *before* `flushInFlight()` (line 189), so clearing the keep-warm from the
  `stopWorkers` hook lets the shared verdict age out mid-drain: any in-flight money work
  that re-checks `assertMoneyAdmitted()` more than one TTL into the flush would be refused.
  That is the same refusal-window bug class this ticket exists to remove, introduced by a
  tidiness change. The interval is already `unref()`'d so it holds nothing open and leaks
  nothing, and clearing it in the `exit` path would be immediately before `process.exit()`
  and therefore pointless. `main.ts:313` now carries a comment recording why it stays.

## Files touched

| file | why |
|---|---|
| `packages/node-core/src/api/health.ts` | +`refresh()`; `probe()` delegates to it; `cachedReachable()` doc states the composition's obligation. No behaviour change to `probe()`, `invalidate()`, or `cachedReachable()`. |
| `apps/generic-node/src/main.ts` | keep-warm → `refresh()`; boot arm → `refresh()` + error `cause`; `clearInterval` on stop; cadence comment corrected. |
| `apps/generic-node/test/money-admission-db-latch.test.ts` | δ>0 harness; behavioural keep-warm drill; boot-arm blip drill; census retargeted. |
| `packages/node-core/test/health-probes.test.ts` | two `refresh()` contract tests. |

Nothing outside `health.ts`, `main.ts` and the two test files is touched. No signing
payload, no schema, no migration, no contract.

## Deliberately not done

- `cachedReachable()` keeps `ttlMs` as its staleness bound — see Blocker 1 rationale above.
- The keep-warm cadence is still `DEFAULT_DB_PING_TTL_MS / 2`. With `refresh()` the
  cadence is no longer load-bearing for correctness (any value `< ttlMs − δ` works); it is
  left as-is to keep the diff minimal.
</content>
