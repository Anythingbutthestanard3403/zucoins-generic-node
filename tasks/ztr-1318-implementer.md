# ZTR-1318 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1318
**Branch:** `ztr-1318-send-not-landed-proof`
**Base:** `origin/main` `f858ca8f9f18d6ba0923fb428f14efc86e7752df`
**Claim run:** `66d1c7d4-735f-447e-9bcc-f7c49177cbb3`
**Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1318-466b7c5e`

## Ticket
`CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` minted `lease_release_proofs.proof_kind = EXTERNAL_SEND_LANDED`, the same kind genuine send landing writes. The CHECK had no send-side non-landing value.

## Design
Mirror ZTR-1280: append a CHECK-only pack slice that admits `SEND_PROVEN_NOT_LANDED_CLOSE`, and write that kind from the close path. Genuine landing still writes `EXTERNAL_SEND_LANDED`. Membership `release_reason` stays `RECOVERY_CLOSE_SEND`.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Distinct proof kind on CHECK + writer | Yes — `SEND_PROVEN_NOT_LANDED_CLOSE` |
| Schema slice + contract.ts pair | Yes — `send-proven-not-landed-close.{sql,contract.ts}` |
| Pack appended only (no prior sql_sha256 rewrite) | Yes — after `destinations-idempotency-key` |
| Closing proven-not-landed does not write `EXTERNAL_SEND_LANDED` | Yes — recovery PG assertion |
| No operator release for LANDED-unacked (ZTR-1316) | Yes — not touched |
| Drift-gate forbidden terms | Yes — new files clean |

## Verify

```
pnpm install
pnpm exec tsc -b
node scripts/check-schema-census.mjs
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts \
  test/send-proven-not-landed-close.census.test.ts test/money-schema-pack.test.ts \
  test/schema-census/schema-census.test.ts test/schema-column-types.lint.test.ts
pnpm --filter @zucoins/generic-node exec vitest run --config vitest.pg.config.ts \
  test/sql-recovery-store.pg.test.ts
pnpm --filter @zucoins/node-core exec vitest run --config vitest.pg.config.ts \
  test/migration-integrity.test.ts
```

- tsc -b: exit 0
- census: PASS, 76 schema files
- node-core unit (targeted): 37 + 31 pass
- generic-node PG recovery: 37 pass
- node-core PG migration-integrity: 10 pass
