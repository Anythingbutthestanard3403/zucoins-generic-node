# ZTR-1274 r2 implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1274
**Branch:** `ztr-1274-fresh-head-dedup-r2` from `origin/main` `d5efff811`
**Claim:** lane=implementer run=`1b454d54-ded6-4082-9464-275ebfac69f0`
**Supersedes:** PR #172 `80c89ea5` (cursor `last_seen_at` as freshness — Review B FAIL)

## Design

Confirm-read (already on main) calls `persistSqlObservation({appendExactRepeat:true})` **this tick**, outside the SERIALIZABLE expire TX. That appends a `DUPLICATE` row with a new id and `observed_at=now()`.

`expire()` stays DB-only. Admit only `fresh_id !== t0_id` + window + `safeUnchangedRelationship`. Proof names the DUPLICATE row, never T0. No JOIN on `wallet_observation_cursors`. No `FORCE_RELEASE`.

## Files

- `packages/node-core/src/receive/expiry-release.ts` — refuse `fresh_id === t0_id`
- Fixtures that run expire SQL load full `observation-stores.sql` (42P01)
- Persist-then-expire drill in `apps/generic-node/test/receive-expiry-release-proof.pg.test.ts`
- Recovery `RELEASE_EXPIRED_RECEIVE` parks when confirm-read returns T0

## Verify

- Unit: expiry-release 113 passed; money-workers + appendExactRepeat census passed
- PG: receive-expiry-release 13; terminal-race 13; proof 5; recovery RELEASE_EXPIRED_RECEIVE 4
