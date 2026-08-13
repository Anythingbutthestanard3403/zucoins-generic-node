# ZTR-1267 implementer — wallet money-capability schema, contracts, defaults

**Linear:** https://linear.app/zutopia/issue/ZTR-1267  
**Epic:** ZTR-1266  
**Branch:** `ztr-1267-wallet-money-capability`  
**Claim run:** `578f03ec-3ff9-44cf-b976-0d47c87a46ff`  
**Head SHA:** `(pending push — r2 fixture fix)`

## Scope (this ticket only)

Schema + frozen pure contracts + defaults. No admission gates (ZTR-1268), no admin PATCH UI
(ZTR-1269), no top-up composition.

## Decisions

1. **New-mint default = FULL** — column defaults, backfill UPDATE, and mint INSERT paths all
   write `allow_* = true` + `money_mode = 'FULL'`. `row_version` stays at DEFAULT 1.
2. **Illegal triples rejected by `wallets_money_mode_flags_consistent`** — the four presets are
   the only legal flag triples; **all-false is illegal** (not a preset). Closed mode vocabulary
   via `wallets_money_mode_closed`. Exactly three money verbs remain (external receive, external
   send, internal move).

## AC checklist + evidence

| AC | Status | Evidence |
|----|--------|----------|
| SQL slice `wallet-money-capability.sql` + `.contract.ts` | Done (WIP + hygiene) | `packages/node-core/src/schema/wallet-money-capability.{sql,contract.ts}` |
| Pure preset matrix in contracts | Done (WIP) | `packages/generic-node-contracts/src/wallet-state/money-capability.ts` + `.test.ts` |
| Append to `MONEY_SCHEMA_PACK_ORDER` (end, never renumber) | Done | after `operations-landed-attention-clear-backfill` |
| Register in `migration-integrity.test.ts` SCHEMA_FILES + NO_TABLE + GREENFIELD | Done | missingRelation `wallets` |
| Export money-capability from wallet-state barrel | Done | `packages/generic-node-contracts/src/wallet-state/index.ts` |
| Extend `WalletInventoryItem` + `WALLET_INVENTORY_FIELDS` | Done | money_mode, allow_*, row_version |
| Admin inventory SQL SELECT + mappers + memory FULL defaults | Done | `apps/generic-node/src/admin-inventory/store.ts` |
| Mint path writes FULL explicitly | Done | `start-money-workers.ts`, `main.ts`, `sql-restored-instance.ts` |
| Census test | Done | `wallet-money-capability.census.test.ts` |
| PG test (defaults, CHECKs, backfill) | Done | `wallet-money-capability.pg.test.ts` |
| Pack test asserts after custody-eligibility | Done | `money-schema-pack.test.ts` |
| Admin SPA / e2e fixtures default FULL | Done | `adminApiFixtures.ts` + page/component tests |
| Drift-gate vocabulary | Done | no forbidden terms in new surface; em-dash stripped to ASCII |
| Schema census report refreshed | Done | `schema-census.report.json` includes slice |

## Tests run

- `packages/generic-node-contracts` — `money-capability.test.ts` PASS (6)
- `packages/node-core` — census PASS (8); pg PASS (7); money-schema-pack PASS (23); migration-integrity PASS (10)
- `apps/generic-node` — `admin-inventory.test.ts` PASS (16); `tsc -b` PASS
- `apps/generic-node/admin` — typecheck PASS; money/WalletHoldCause/WalletsPage tests PASS (52)

## Out of scope (follow-ons)

- ZTR-1268 admission gates using eligibility helpers
- ZTR-1269 admin PATCH + CAS on row_version
- Top-up hub composition

**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/125

