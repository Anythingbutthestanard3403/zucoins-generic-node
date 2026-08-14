# ZTR-1129 implementer r3

**Linear:** https://linear.app/zutopia/issue/ZTR-1129
**Branch:** `ztr-1129-send-ops-close-cas`
**Claim run:** `9cc7d8d1-88ce-4c90-a25b-3ae80ea3ff07`
**Plan:** `tasks/plan-ZTR-1129.md`

## Ticket
Operator CLOSE updated only `operations` → REJECTED. Sibling `send_operations` stayed
APPROVED / NEEDS_ATTENTION, so `send_operations_one_unsettled_per_source_wallet` kept
`source_wallet_id` pinned (`WALLET_IN_FLIGHT` / `no_free_send_worker` on the next create).

## Design
Same SERIALIZABLE TX as existing CLOSE:

1. Existing `operations` CAS (predicates unchanged).
2. Sibling `send_operations` CAS to REJECTED.
3. Either RETURNING empty → ROLLBACK `predicate_failed`.
4. Then `releaseSourceLeasesForOperation` (proof-only).
5. audit + COMMIT.

Send SQL lives in `SEND_CRASH_RECOVERY_SQL` (`CLOSE_NEVER_STARTED_CAS` kept, including
the independent `row_version = $2` bind against **send_operations**.row_version;
`CLOSE_PROVEN_NOT_LANDED_CAS` added). sql-recovery-store imports those statements.

## Acceptance

| AC | Status |
| --- | --- |
| AC1 never-started both tables REJECTED; second send INSERT allowed; STEP_1 refuses | Yes |
| AC2 proven-not-landed both tables REJECTED (live terminalizer) | Yes |
| AC3 STEP_1 / formation refuse; both stay APPROVED | Yes (new PG drill) |
| AC4 moved head INDETERMINATE; CLOSE withheld; no write | Yes (new PG drill) |
| AC5 lease only via consumed `lease_release_proofs` | Yes (existing AC5 kept) |
| AC6 second `send_operations` INSERT on same source succeeds (no 23505) | Yes |

## Verification

```
npx tsc -b --pretty false                 # exit 0
pnpm --filter @zucoins/node-core exec vitest run \
  test/send-crash-recovery.test.ts --config vitest.unit.config.ts
# Test Files 1 passed | Tests 37 passed
pnpm --filter @zucoins/generic-node exec vitest run \
  test/sql-recovery-store.pg.test.ts --config vitest.pg.config.ts
# Test Files 1 passed | Tests 37 passed
pnpm --filter @zucoins/generic-node exec vitest run \
  test/operator-docs.census.test.ts --config vitest.unit.config.ts
# Test Files 1 passed | Tests 38 passed
eslint (touched .ts files)                # max-warnings 0
```

## Not in this ticket
FORCE_*, unique-index change, EXTERNAL_SEND_LANDED from CLOSE, ZTR-1308 staging cleanup.
