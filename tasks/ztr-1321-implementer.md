# ZTR-1321 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1321
**Branch:** `ztr-1321-cleanup-batch`
**Base:** `origin/main` `d5efff8116601106d187776646afc355e79c8178`
**Claim run:** `796f0a9d-9b6e-4143-b57a-c80aa090557a`
**Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1321-796f0a9d`

## Ticket
Cleanup batch: unused late-landing-reconcile (~1200 lines, barrel + own tests only), dead `parkPastExpiryAwaitingRedemption`, stale ZTR-1129 lander comment, OpenAPI 503/destination gaps, `assign_not_wired` missing from `SendAssignRejectionCode`.

## Design
Delete, do not wire. Production late landing + park already live in `send-completion-lander` (dual-status scan + inline `CAS_AWAITING_TO_NEEDS_ATTENTION`). Keep SQL catalogue / classify / continue / redeliver on `expiry-attention.ts`. OpenAPI generated, not hand-edited.

## Acceptance

| Criterion | Status |
|-----------|--------|
| late-landing-reconcile deleted + barrel/tests/census | Yes |
| parkPastExpiryAwaitingRedemption removed (lander parks) | Yes |
| Lander comment updated for ZTR-1129 terminal path | Yes |
| 503 `details.reason` enum in OpenAPI | Yes |
| POST /v1/destinations 200+201 (already); bless/retire DestinationResponse | Yes |
| `assign_not_wired` on `SendAssignRejectionCode`; no `as` cast | Yes |
| No ZTR-1316 operator release | Yes |
| Drift-gate forbidden terms | Yes |

## Verify

```
pnpm install
pnpm exec tsc -b
UPDATE_OPENAPI=1 pnpm --filter @zucoins/node-core exec vitest run test/openapi-freeze.test.ts
pnpm --filter @zucoins/node-core exec vitest run --config vitest.unit.config.ts \
  src/send/expiry-attention.test.ts \
  src/protocol/reconcile/landing-oracle-mint.discipline.test.ts \
  test/error-envelope-schema.test.ts test/operation-routes.test.ts \
  test/durable-events-implementer-emitter.census.test.ts \
  test/openapi-freeze.test.ts test/boundaries.test.ts
pnpm --filter @zucoins/generic-node-consumer exec vitest run src/http/errors.test.ts
pnpm --filter @zucoins/node-core exec vitest run --config vitest.pg.config.ts \
  test/send-expiry-attention.pg.test.ts \
  test/no-second-external-partial-race.pg.test.ts
```

- tsc -b: exit 0
- node-core unit (targeted): 190 pass
- consumer errors: 8 pass
- node-core PG (2 files): 17 pass
- eslint on touched files: exit 0
