# ZTR-1310 implementer — destination register idempotency

**Linear:** https://linear.app/zutopia/issue/ZTR-1310
**Branch:** `ztr-1310-dest-idempotency`
**Claim run:** `3d381124-470f-4385-8a94-20c9607f6b13`
**Base:** `origin/main` @ `be826b9a1d4e18670ab26941be13b5364e626ab0`

## Problem

`createSqlDestinationStore.findByIdempotencyKey` always returned `null`.
`DestinationService.register` already treated a hit as `already_registered`, and
the in-memory store honored the key, but the live PG store neither persisted
nor looked up `idempotency_key`. A client retry after timeout minted another
wallet every time.

## Decisions

1. **Match the DestinationStore port** — key is `(node_id, idempotency_key)`.
   Destinations are not implementer-API operations, so this is not the
   `(implementer_id, http_method, route, idempotency_key)` ledger. No second
   ledger table.
2. **Column on `destinations`** — appended pack slice
   `destinations-idempotency-key.sql`. Nullable text so mint / pool / backfill
   rows stay valid. CHECK `^[!-~]{16,255}$` when present. Partial UNIQUE
   `(node_id, idempotency_key) WHERE idempotency_key IS NOT NULL`.
3. **Register write** — `insert` now binds the key. `ON CONFLICT (wallet_id)`
   adopts a mint PENDING row and stamps the key only via
   `COALESCE(existing, excluded)` so a later register cannot rebind another
   key. A 23505 on the node+key UNIQUE replays the winner row.
4. **Bless / retire / MOVE eligibility unchanged.**

## AC

- [x] Live PG `findByIdempotencyKey(nodeId, key)` returns the original dest row
- [x] Second `register` with the same key does not mint; `already_registered`
      + original dest id / wallet id / public key
- [x] Persist under DestinationStore port scope `(node_id, idempotency_key)`
- [x] PG test + unit/in-memory stay green
- [x] Numbered SQL slice + matching `*.contract.ts`; appended to
      `MONEY_SCHEMA_PACK_ORDER`
- [x] No forbidden vocabulary
- [x] Bless / retire / public MOVE eligibility not changed

## Verify (this commit)

| cmd | result |
|-----|--------|
| `pnpm install` | lockfile up to date, 324 packages |
| `pnpm exec tsc -b` | exit 0 |
| unit: dest store + census + pack + destination.test | **71 passed** |
| PG: `sql-destination-store.pg` + `migration-integrity` | **14 passed** |
| `pnpm --filter @zucoins/node-core lint` | 0 errors (5 pre-existing warnings) |

Pre-existing on `origin/main` (not this ticket): `openapi-freeze` (WORKER query
enum missing from committed yaml) and `pool-allocator.pg` dest-on-mint `$4`
bind.

## Files

- `packages/node-core/src/schema/destinations-idempotency-key.sql`
- `packages/node-core/src/schema/destinations-idempotency-key.contract.ts`
- `packages/node-core/src/schema/money-schema-pack.ts`
- `packages/node-core/src/api/sql-destination-store.ts`
- `packages/node-core/src/index.ts`
- `packages/node-core/test/sql-destination-store.test.ts`
- `packages/node-core/test/sql-destination-store.pg.test.ts`
- `packages/node-core/test/destinations-idempotency-key.census.test.ts`
- `packages/node-core/test/money-schema-pack.test.ts`
- `packages/node-core/test/migration-integrity.test.ts`
- `packages/node-core/test/schema-census/schema-census.report.json`
- `tasks/ztr-1310-implementer.md`
