# ZTR-1274 implementer — FRESH_VERIFIED_T0_EXACT starve on unchanged head

**Linear:** https://linear.app/zutopia/issue/ZTR-1274  
**Branch:** `ztr-1274-fresh-head-dedup`  
**Claim run:** `93db06ef-1d2e-4122-b1de-456e7b4f3c8f`  
**Base:** `origin/main` `f858ca8f9f18d6ba0923fb428f14efc86e7752df`

## Root cause (still live after ZTR-1275)

ZTR-1275 `appendExactRepeat` mints a new `DUPLICATE` row when the expiry
confirm-read opts in. If that flag is off, or persist still returns the
pre-expiry T0 id (`SUPPRESS_AS_SIGHTING` → `last_recorded_observation_id`),
`FRESH_VERIFIED_T0_EXACT` used only `fresh.observed_at` and
`safeUnchangedRelationship` (`DUPLICATE` /
`EQUIVALENT_STATE_DIFFERENT_ENVELOPE`). The T0 row itself is `FIRST` with a
pre-expiry `observed_at`, so the freshness window never held — the safe
unchanged-head case parked forever.

## Fix

Smallest predicate-side admission of a **post-expiry cursor sighting of the
same T0 bytes**:

- `LOAD_OBSERVATIONS` LEFT JOINs `wallet_observation_cursors` for the named
  fresh tip and projects `cursor_last_seen_at`.
- `suppressedT0SightingIsFresh`: `fresh_id === t0_id`, verified exact
  projection, `last_seen_at` in `[expiry+30s, now]` and `now - seen <= 30s`.
- That satisfies `FRESH_VERIFIED_T0_EXACT` and
  `NO_ANOMALY_LINEAGE_OR_SUBMIT` (FIRST on the T0 row is not a lineage gap
  when the cursor proves a post-expiry exact-repeat sighting).
- Release proof `fresh_observed_at` uses the cursor clock in that case.

No `FORCE_RELEASE`. No unsigned custody shortcut. Signing payloads untouched.
`appendExactRepeat` wiring unchanged.

## Tests

- Unit: same-id T0 + post-expiry `last_seen_at` → RELEASED; pre-margin
  `last_seen_at` still parks (`FRESH_VERIFIED_T0_EXACT`).
- Frozen SQL: `LOAD_OBSERVATIONS` projects cursor `last_seen_at`.
- PG: seed T0 only, cursor tip = T0, post-expiry `last_seen_at` →
  `RELEASED_T0_UNCHANGED`.

## Verify

- `vitest` expiry-release unit: 113 passed
- `vitest.pg` `receive-expiry-release.pg.test.ts`: 13 passed
- `tsc -b` clean
