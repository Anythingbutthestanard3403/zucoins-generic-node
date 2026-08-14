# ZTR-1306 implementer — dest-on-mint PENDING row

**Linear:** https://linear.app/zutopia/issue/ZTR-1306
**Branch:** `ztr-1306-dest-on-mint`
**Claim run:** `8919d96b-27f5-4398-8195-3e4e174ba0c5`
**Base:** `origin/main` @ `1d1d21545` (rebased after ZTR-1307/1309 landed)
**Head:** `281f7779c069018636d66c8c4b914c1d98f1e7fd`

## Problem

Staging omit-source `POST /v1/external-sends` 503'd when assign picked an older
send-capable wallet with no `destinations` row (`worker_destination_missing`).
Only `POST /v1/destinations` inserted dest rows. Pool scale-up and funding
CREATE minted wallets only.

## Decisions

1. **Single mint composition** — `insertNodeGeneratedWalletWithPendingDestination`
   writes `wallets` then `destinations (state='PENDING')` on the same executor.
   Production mint sites (destination-register keygen, pool `MintWallet`,
   funding CREATE) all call it. Compensate via `deleteNodeGeneratedWalletMint`
   (dest first, then wallet).
2. **Register does not double-row** — `createSqlDestinationStore.insert` uses
   `ON CONFLICT (wallet_id) DO UPDATE` and applies the operator label only when
   the existing row is still `PENDING`.
3. **Backfill is a pack slice** — `destinations-pending-backfill.sql` appended
   to `MONEY_SCHEMA_PACK_ORDER` after `verification-mode`. PENDING only; never
   BLESSED. Imported origin excluded. Idempotent `NOT EXISTS`.
4. **Throwaway restore instance is exempt** — `sql-restored-instance.ts` copies
   archive `wallet_sections` as-is (any `key_origin`). Not a live mint. Fleet
   heal is the pack backfill on the real node.
5. **Blessing stays dual-control.** This ticket is PENDING existence only.

## Production mint paths (all use the helper)

| Site | File |
|---|---|
| Destination-register mint | `apps/generic-node/src/main.ts` `createNodeGeneratedWalletKeyGenerator` |
| Pool scale-up `MintWallet` | `apps/generic-node/src/money-workers/start-money-workers.ts` `createPoolMint` |
| Funding CREATE mint | `apps/generic-node/src/full-http-mount.ts` `mintFundingWallet` |

Census: `apps/generic-node/test/dest-on-mint-production-paths.census.test.ts`
fails if any other live `INSERT INTO wallets` appears under `apps/generic-node/src`.

## Operator path (no re-mint)

Bless the existing wallet's `destination_id` from Destinations (device + TOTP).
Do not POST a new destination.

Fleet query (post-deploy ops check, not required to land):

```sql
SELECT w.id AS wallet_id,
       w.money_mode,
       d.id AS dest_id,
       d.state AS dest_state
  FROM wallets w
  LEFT JOIN destinations d ON d.wallet_id = w.id
 WHERE w.key_origin = 'node_generated';
```

Expect `dest_id IS NOT NULL` for every node_generated row. Intentional
exclusion: `key_origin = 'imported'`.

Documented in `docs/operations/wallet-money-capabilities.md`.

## AC

- [x] No production mint path creates a node_generated wallet without a dest row
- [x] PG/unit coverage for mint + backfill + no double-row
- [x] Operator path documented (bless existing dest; fleet query)
- Staging live fleet check is a later ops step — query documented, not run here

## Verify (this commit)

- `pnpm install` — lockfile up to date, 324 packages
- `rtk tsc -b` — no errors
- node-core unit (dest-on-mint + store + census + pack): **41 pass** (post-rebase)
- node-core unit (plus destination.test): **69 pass** (pre-rebase; dest service unchanged)
- node-core PG (`destinations-pending-backfill.pg` + `migration-integrity`): **14 pass**
- node-core PG (`destinations-pending-backfill.pg` only, post-rebase): **4 pass**
- generic-node unit (production-path census + dest wiring): **10 pass** (post-rebase; 1307 added wiring cases)
- schema-census: **28 pass**
- operator-docs census: **38 pass**
- `pnpm --filter @zucoins/node-core lint` — 0 errors (5 pre-existing warnings)
- `pnpm --filter @zucoins/generic-node lint` — 0 errors

## Files

- `packages/node-core/src/api/insert-node-generated-wallet.ts` (+ unit test)
- `packages/node-core/src/api/sql-destination-store.ts` (ON CONFLICT adopt)
- `packages/node-core/src/schema/destinations-pending-backfill.{sql,contract.ts}`
- `packages/node-core/src/schema/money-schema-pack.ts` (append)
- `packages/node-core/test/destinations-pending-backfill.{census,pg}.test.ts`
- `packages/node-core/test/{money-schema-pack,migration-integrity,sql-destination-store}.test.ts`
- `packages/node-core/test/schema-census/schema-census.report.json`
- `apps/generic-node/src/{main,full-http-mount,money-workers/start-money-workers}.ts`
- `apps/generic-node/test/dest-on-mint-production-paths.census.test.ts`
- `docs/operations/{README,wallet-money-capabilities}.md`

## Out of scope (honoured)

- No auto-bless. No `destination_state` WORKER. No ZTR-1307 push-subscribe.
- Did not touch `/Volumes/Ai Building/Zucoins Generic Node` or ZTR-1129.
