# ZTR-1268 implementer — enforce wallet money capabilities on admission + leases

**Linear:** https://linear.app/zutopia/issue/ZTR-1268  
**Epic:** ZTR-1266  
**Depends on:** ZTR-1267 (schema/contracts) — PR #125  
**Branch:** `ztr-1268-money-capability-gates` (stacks on `ztr-1267-wallet-money-capability`)  
**Head SHA:** `a777ed1b7f5d0aac8117f41f7898c8a3073ed6c6`
**Claim run:** `806c2963-fe8e-4a37-9ec3-4065e9aeba35`

## Scope

Fail-closed admission using flags from ZTR-1267:

1. RECEIVE pool selection / arm / assign — `allow_external_receive`
2. SEND create + SEND_SOURCE lease — `allow_external_send` (stable `source_wallet_not_eligible` + detail)
3. MOVE create + receive-spawned child — both parties `allow_internal_move`
4. Lease eligibility trigger overlay — in-TX capability recheck under wallet FOR UPDATE
5. PG matrix: four presets × three verbs (+ MOVE_DESTINATION)
6. Thread capability columns through wallet record types / SQL SELECTs

## Decisions

1. **Reuse existing rejection codes** — SEND/MOVE keep `source_wallet_not_eligible` /
   `destination_not_eligible` with detail `allow_external_send=false` /
   `allow_internal_move=false`. No new HTTP mapping required.
2. **Lease structural gate via pack overlay** — do not edit frozen
   `custody-eligibility.sql` (pack sql_sha256). New slice
   `wallet-money-capability-lease-guard.sql` does `CREATE OR REPLACE FUNCTION
   custody_reject_ineligible_lease` after capability columns. Money-schema-pack strip
   keeps OR REPLACE overlays of already-seen functions.
3. **Lease migrator prefers overlay** — `ensureEligibilityGuard` loads the capability
   body when present so re-migrate never reverts capability gates.
4. **Exception codes (DB only)** — `CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED`,
   `CUSTODY_LEASE_SEND_CAPABILITY_REJECTED`, `CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED`.
5. **Receive after_landing INTERNAL_MOVE** — uses `allow_internal_move` on the sink,
   not `allow_external_receive` (receive pool stays receive-flag only).

## AC checklist

| AC | Status | Evidence |
|----|--------|----------|
| Receive selection excludes `allow_external_receive=false` | Done | `pool-allocator.ts` SELECT + `isReceiveEligible` + PG select drill |
| Send create rejects non-send-capable sources | Done | `isSendSourceEligible` + create detail + unit test |
| Move create rejects either side lacking `allow_internal_move` | Done | source/dest eligibility + unit tests |
| Receive-spawned child respects capabilities | Done | child-create uses same move eligibility + flags on SQL mappers |
| Lease claim re-checks capability in-TX | Done | lease-guard overlay + lease migrator install + PG matrix |
| PG matrix four presets × three verbs | Done | `wallet-money-capability-gates.pg.test.ts` |
| Node never chain-submits SEND_EXTERNAL | Unchanged | no submit path touched |
| Forbidden-terms / boundaries clean | Done | no new forbidden vocabulary |
| New error codes HTTP-mapped if introduced | N/A | API reuses existing codes; DB codes are structural only |

## Tests

- Unit: `wallet-money-capability-gates.test.ts`, send/move/receive admission, arm-race, census
- Pack: `money-schema-pack.test.ts` (overlay strip + order)
- PG: `wallet-money-capability-gates.pg.test.ts` (19), migration-integrity, custody suites still green

## Out of scope

- ZTR-1269 admin PATCH UI
- ZTR-1270 auto top-up composition
- ZTR-1271 optional source_wallet_id

**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/127
