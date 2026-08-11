# ZTR-1211 implementer

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/74
- **HEAD:** `7b8eff775025098a6e48010c4f0450c628ce7f1b`
- **Claim:** implementer run=`e227c8d3-8523-49d4-99e4-e2597de614e8`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1211-impl`
- **Branch:** `ztr-1211-sqlproof-lock` (from `origin/main` @ `7e01e8a`)

## Problem

`SqlProofBodyStore` opened a composition-root TX via `createPoolSqlTransactionRunner` but never took the documented per-`path_proof_id` `pg_advisory_xact_lock`. Concurrent same-path persists could overshoot `MAX_SIGHTINGS_PER_BODY` (storage-cap race; non-authority / not double-apply). Found ZTR-1155 finding 1; sweeper default: take the lock.

## Fix

1. `STATEMENTS.ADVISORY_LOCK_PATH_PROOF` = `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`
2. `SqlProofBodyStore.lockPathProofId(pathProofId)` issues it.
3. `persistProofBodyInTransaction` calls `store.lockPathProofId?.(path_proof_id)` as the first step (inside the outer TX when a runner is present).
4. Contract obligation + §11.1 data-model residual + isolation census updated to ROW_LOCK covering the lock (no longer "KNOWN OPEN").

## AC

| # | Criterion | Status |
|---|---|---|
| 1 | lock inside same TX as write | satisfied |
| 2 | concurrent same-path serialize / no cap overshoot | satisfied (PG race test) |
| 3 | doc/impl agree; no money-path verdict/landing/lease | satisfied |
| 4 | proof-body suite green | satisfied (158 unit + 23 census/PG) |

## Governing spec

- `packages/node-core/src/schema/proof-body-store.contract.ts` cross-call atomicity
- `docs/proposals/generic-node-redesign-v2/04-data-model.md` §11.1
- sql-store header composition-root lock note

## Verify (exact head)

```
pnpm install                         # ok
pnpm exec tsc -b                     # EXIT 0
pnpm --filter @zucoins/node-core build
pnpm --filter @zucoins/node-core lint   # 0 errors
pnpm --filter @zucoins/generic-node lint # 0 errors
```

- node-core proof-body focused: **7 files / 158 passed**
- generic-node `transaction-isolation.census` + `durable-security-ports.pg`: **23 passed**
  (teardown `psql ETIMEDOUT` on global DROP DATABASE is environmental; tests themselves green)

## Money-path dual

`money-path-scan.mjs` is a 0-byte stub. Manual: **moneyPathHit=false** — non-authority candidate store (`pathClass: other`); no lease/landing/verdict/submit. Isolation census marks site ROW_LOCK.

## Residuals

- Per-tenant cap lock + idempotency-tuple lock intentionally not taken (documented soft bounds).
- No merge from this lane.

## Release

QA Review.
