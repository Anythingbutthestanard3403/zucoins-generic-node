# ZTR-1138 implementer

**Head SHA:** `ce444a63ba7a045c77a1af64bd0058ef8ba8fd1e`
**Branch:** `ztr-1138-tx-byte-immutability`
**Governing:** doc 04 §9 / 04:760-767 (transaction material mutability); `packages/node-core/src/schema/transaction-material.contract.ts` regimes; `CONVENTIONS.md` exact-content byte-immutability; pack append after v153 (`lease-role-enum`) → **v154**.

## Acceptance

1. **Triggers reject UPDATE of byte columns / insert-only sign intents** — SATISFIED
   - `external_send_sign_intents`: INSERT-only (`EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY`)
   - `operation_transactions`: insert-time bytes + filled one-way columns frozen (`OPERATION_TRANSACTIONS_BYTE_IMMUTABLE`); NULL→value fills allowed
   - `external_send_partials`: signed bytes frozen; delivery counters mutable (`EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE`)
2. **CONVENTIONS + pack version after main (v153+)** — SATISFIED (pack index 54 → version **154**)
3. **pg tests prove reject** — SATISFIED (`transaction-material-byte-immutability.pg.test.ts` 8 drills + uniqueness drill (i))
4. **census** — SATISFIED (`schema-census.report.json` rewritten)
5. **gates green** — SATISFIED at head (see below)

## Files

| Path | Why |
|---|---|
| `packages/node-core/src/schema/transaction-material-byte-immutability.sql` | Trigger DDL |
| `.../transaction-material-byte-immutability.contract.ts` | Inventory |
| `.../money-schema-pack.ts` | Append slice → v154 |
| `.../transaction-material.contract.ts` | Obligation points at shipped slice |
| `.../core/transaction-material-store.ts` | Comment: engine guards now ship |
| `test/transaction-material-byte-immutability.pg.test.ts` | Live PG reject proof |
| `test/money-schema-pack.test.ts` | Pack order + trigger SQL |
| `test/external-send-partial-uniqueness.pg.test.ts` | Drill (i) now expects reject |
| `test/no-second-external-partial-race.pg.test.ts` | Header: DDL gap closed |
| `test/crash-replay-surfaces.ts` / `crash-replay-obligations.ts` | Point at live PG discharge |
| `test/schema-census/schema-census.report.json` | New sql file |

## Verification

```
pnpm install                          # lockfile up to date
tsc -b                                # exit 0
pnpm --filter @zucoins/node-core exec vitest run --config vitest.config.ts \
  test/transaction-material-byte-immutability.pg.test.ts \
  test/money-schema-pack.test.ts \
  test/external-send-partial-uniqueness.pg.test.ts \
  test/transaction-material.census.test.ts \
  test/crash-replay.exactness.test.ts \
  test/schema-census/schema-census.test.ts
  # → 6 files, 125 passed
pnpm --filter @zucoins/node-core lint # 0 errors (5 pre-existing warnings)
node scripts/check-schema-census.mjs  # OK
```

## Deferred

None. Dual review expected (money-path schema migration).
