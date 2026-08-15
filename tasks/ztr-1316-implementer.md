# ZTR-1316 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1316
**Branch:** `ztr-1316-landed-unacked`
**Base:** `origin/main` `d5efff8116601106d187776646afc355e79c8178` (#171)
**Claim run:** `76e3bca4-3f1c-4168-a737-afa1b1dcdbde`
**Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1316-d5efff811`

## Ticket
INDEPENDENT `EXTERNAL_SEND_LANDED` keeps the `SEND_SOURCE` lease until consumer
`POST /v1/operations/{id}/verification-complete`. If that never happens the worker is
lost from the capped pool and invisible in needs-attention (LANDED was filtered out;
`CLOSE_NEVER_STARTED` needs APPROVED; `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` needs
NEEDS_ATTENTION).

## Design
Follow #171 CHECK-append. Status stays `EXTERNAL_SEND_LANDED` (funds already settled).
Operator `CLOSE_LANDED_UNACKNOWLEDGED` releases the lease with distinct proof kind
`SEND_LANDED_UNACKNOWLEDGED_CLOSE`. Not `FORCE_RELEASE`. Not reuse of
`EXTERNAL_SEND_LANDED` or `SEND_PROVEN_NOT_LANDED_CLOSE`. Inbox exception: INDEPENDENT
LANDED + held lease + no verification_acknowledgements; age is oldest lease
`acquired_at` → `diagnostics[0].at` → `attention_since`.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Distinct proof kind on CHECK + writer | Yes — `SEND_LANDED_UNACKNOWLEDGED_CLOSE` |
| Schema slice + contract.ts pair | Yes — `send-landed-unacknowledged-close.{sql,contract.ts}` |
| Pack appended only (no prior sql_sha256 rewrite) | Yes — after `send-proven-not-landed-close` |
| Status stays LANDED | Yes — dual CAS never rewrites status |
| Inbox + age | Yes — WHERE exception + lease acquired_at |
| Refuses when ack exists | Yes — CAS + planner |
| No FORCE_RELEASE | Yes — forbidden catalog unchanged |
| Catalog 11, halt never-gated | Yes |
| Avoided ZTR-1321 write-set | Yes — OpenAPI enum only |

## Verify

```
pnpm install
pnpm exec tsc -b --pretty false
node scripts/check-schema-census.mjs --write-report
UPDATE_OPENAPI=1 pnpm --filter @zucoins/node-core exec vitest run test/openapi-freeze.test.ts
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/operator-halt/halt.census.test.ts gen/json-sync.test.ts \
  src/scan/generic-core.scan-gate.test.ts src/scan/forbidden-terms.test.ts
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts \
  test/send-landed-unacknowledged-close.census.test.ts test/money-schema-pack.test.ts \
  test/schema-census/schema-census.test.ts test/recovery-inspection.test.ts \
  test/recovery-actions.test.ts test/forbidden-recovery-surface.test.ts
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
pnpm --filter @zucoins/generic-node exec vitest run --config vitest.pg.config.ts \
  test/sql-recovery-store.pg.test.ts
pnpm --filter @zucoins/node-core exec vitest run --config vitest.pg.config.ts \
  test/migration-integrity.test.ts
```

- tsc -b: exit 0
- census: PASS, 77 schema files
- halt census + json-sync: 73 pass
- node-core unit (targeted): 137 pass
- SPA money: 39 pass
- generic-node PG recovery: 40 pass
- node-core PG migration-integrity: 10 pass
- drift-gate: 20 pass
- lint: 0 errors
