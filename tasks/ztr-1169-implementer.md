# ZTR-1169 — Data-model residuals (implementer)

## Summary

Closed four doc-04 conformance gaps in the persistence layer:

1. **`observation_relationship_adjudications`** — new pack slice with append-only triggers; census disposition promoted `deferred` → `required`. Makes `COMPLETE_PATH_SUCCESSOR` reachable via adjudication rows.
2. **`destinations.label`** — column on cold CREATE + appended `destinations-label` ALTER for already-applied DBs; SQL destination store persists and returns label (no more silent discard).
3. **`lease_role` → `wallet_lease_role` enum** — cold CREATE uses the real enum; appended `lease-role-enum` value-preserves text columns. `CUSTODY_LEASE_ROLE_UNKNOWN` kept load-bearing for `ALTER TYPE ADD VALUE` without a trigger branch (proven in lease-pk PG test).
4. **Dead shadowed eligibility trigger** — removed `lease_foundation_reject_ineligible_lease` + second `wallet_active_leases_eligibility_guard` from `lease-foundation.sql`. Single owner is `custody_reject_ineligible_lease`. Lease migrator loads the custody function explicitly.

## Governing spec

- Doc 04 data model (fixture `packages/node-core/test/data-model.fixture.md` §§4–6, §11, §15)
- `packages/node-core/src/schema/CONVENTIONS.md` §6 (real Postgres ENUMs; append-only money pack)

## Acceptance

| Criterion | Status |
|---|---|
| adjudications table + append-only triggers | satisfied |
| COMPLETE_PATH_SUCCESSOR reachable | satisfied (adjudication CHECK) |
| destinations.label round-trip POST/GET | satisfied |
| lease_role real ENUM + UNKNOWN branch | satisfied |
| dead lease-foundation eligibility copy deleted | satisfied |
| check-schema-census clean | satisfied (`--write-report`) |

## Pack versions (appended after operations-indexes / v150 era)

- `observation-relationship-adjudications`
- `destinations-label`
- `lease-role-enum`

## Verify (head SHA at PR open)

```
pnpm install          # ok
tsc -b                # clean
node scripts/check-schema-census.mjs --write-report  # clean
pnpm exec vitest run packages/node-core/test/{money-schema-pack,sql-destination-store,schema-census/schema-census,custody-eligibility-lease-pk,custody-eligibility.pg,lease-foundation.pg}.test.ts
# with TEST_DATABASE_URL scratch: 6 files, 91 passed
```

Unit-only (no PG URL): money-schema-pack, lease-role-parity, sql-destination-store, lease-foundation.census, custody-eligibility.census, schema-census, migration-integrity, custody-eligibility-canon-conformance — 92 passed / 5 skipped.

## Files

- New: `observation-relationship-adjudications.{sql,contract.ts}`, `destinations-label.{sql,contract.ts}`, `lease-role-enum.{sql,contract.ts}`
- Schema: custody-eligibility, lease-foundation, money-schema-pack
- Runtime: sql-destination-store, leases/migrate, leases/readiness
- Tests + census report/manifest

## Deferred

None for the four ticket items. General multi-slice duplicate-table gate (ZTR-1139 proposal) not added — out of scope; multi-slice body audit already covers wallet_active_leases.
