# ZTR-1208 — operation_expected_artifacts single owning slice

## Summary

Resolved body divergence / dual CREATE of `operation_expected_artifacts` by making
`expected-artifacts.sql` the sole owner (named CHECKs + insert-only trigger) and
removing the table CREATE (and its trigger/function) from `move-baseline-binding.sql`.

Not a cold-apply fix: `money-schema-pack.ts` already stripped the later CREATE.
This restores one-slice-one-contract and removes the multi-slice allow-list entry.

## Acceptance

1. One owning slice (`expected-artifacts.sql`) — satisfied
2. `move-baseline-binding.sql` drops CREATE, keeps bindings/evidence dependents — satisfied
3. No destructive migration (IF NOT EXISTS / pack order unchanged in effect) — satisfied
4. `node scripts/check-schema-census.mjs` PASS; ZTR-1163 fixture path (owner slice) unchanged — satisfied
5. CONVENTIONS multi-slice row updated to sole owner — satisfied

## Governing

- Ticket + Riley 2026-08-08 premise correction (body divergence, not cold-apply)
- `packages/node-core/src/schema/CONVENTIONS.md` multi-slice / one-slice-one-contract
- Pack order: `expected-artifacts` before `move-baseline-binding` in `MONEY_SCHEMA_PACK_ORDER`

## Files

| File | Why |
|---|---|
| `expected-artifacts.sql` | Sole CREATE; named constraint names; insert-only trigger/function |
| `expected-artifacts.contract.ts` | Anchors + ARTIFACT_INSERT_ONLY_TRIGGER |
| `move-baseline-binding.sql` | Remove dual CREATE + artifact trigger |
| `move-baseline-binding.contract.ts` | Drop artifact invariants; binding/evidence only |
| `money-schema-pack.ts` / `CONVENTIONS.md` | Document sole owner |
| `money-schema-pack.test.ts` | Drop from multi-CREATE allow-list |
| `move-baseline-binding.pg.test.ts` | Composition apply owner + stubs; constraint name |
| `expected-artifacts.census.test.ts` | Named purpose mutation; trigger presence |
| `migration-integrity.test.ts` | Comment only |

## Verify (head SHA at PR open)

- `pnpm install` (CI=true --force on fresh worktree)
- `tsc -b` — clean
- `pnpm --filter @zucoins/node-core lint` — 0 errors (5 pre-existing warnings)
- Tests: expected-artifacts.census 13/13; money-schema-pack 18/18; move-baseline-binding.pg 17/17; move-observation-evidence.census 6/6
- `node scripts/check-schema-census.mjs` — PASS (0 failures)
- migration-integrity greenfield loop: intermittent 30s timeout under load; passed when run alone — not a logic fail from this change

## Deferred

None for AC. Remaining multi-slice tables (`operator_device_keys`, `wallet_active_leases`) out of scope.
