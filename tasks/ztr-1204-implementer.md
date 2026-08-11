# ZTR-1204 — implementer handoff

## Summary
Under multi-lane contention, `vitest.global-setup.ts` probe/CREATE hit `ETIMEDOUT`
(or capacity errors). Failures were treated like "no Postgres", so `TEST_DATABASE_URL`
stayed unset and pg suites silently skipped — green-looking runs that verified nothing
on the money path.

## Fix
- `classifyPsqlError` — transient (ETIMEDOUT/SIGTERM/too-many-clients/startup) vs absent vs other
- `withPsqlRetries` — 5 attempts, exponential backoff from 250ms; loud wrap on exhaustion
- CREATE uses a fresh DB name per attempt + treats "already exists" as success (timeout-after-commit race)
- Transient probe/CREATE failure always hard-fails (independent of `PG_REQUIRED`)
- `PG_REQUIRED=1` still fail-closed on truly absent Postgres; bare local without PG still soft-skips
- Empty `TEST_DATABASE_URL=` is not a pin (auto-provision still runs)
- README Developing documents per-lane `TEST_DATABASE_URL` pinning

## Acceptance criteria
1. ✅ Provision failure loud by default (transient → hard fail after retries)
2. ✅ Bounded backoff on ETIMEDOUT / capacity
3. ✅ `TEST_DATABASE_URL` pinning documented (README)
4. ✅ `PG_REQUIRED=1` absent-server semantics unchanged
5. ✅ Separate from ZTR-1209

## Governing spec
- `docs/proposals/generic-node-redesign-v2/mandatory-database-tests.md`
- Harness comments in `vitest.global-setup.ts` / `pg-required-guard.ts`

## Verification (exact head)
- SHA: `6df1301f3c59f73db2b5f96fcea93bac2455d849`
- PR: https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/84
- `CI=true pnpm install --frozen-lockfile` — ok
- `npx tsc -b` — clean
- provision unit + boundaries — 79 passed / 2 files
- eslint touched files — 0 errors / 0 warnings
- smoke provision + teardown — ok

## Files
- `vitest.global-setup.ts`
- `packages/node-core/test/vitest-global-setup-provision.test.ts`
- `README.md`
- `tasks/ztr-1204-implementer.md`

## Deferred
None for AC. Post-start suite flakes remain ZTR-1209.
