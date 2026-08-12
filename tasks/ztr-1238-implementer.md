# ZTR-1238 — implementer evidence

## Ticket
Integration-requests store: schema slice + contract for platform-initiated key requests.

## Head
See PR tip SHA at open.

## What landed
- `packages/node-core/src/schema/integration-requests.sql` — `integration_requests` table:
  - closed status set PENDING/APPROVED/DECLINED/EXPIRED/CLAIMED
  - `row_version` CAS counter
  - `claim_token_hash` UNIQUE unsalted SHA-256 hex (no raw claim token)
  - scope CHECK = frozen IMPLEMENTER_SCOPES
  - composite `integration_requests_status_consistency` CHECK
  - indexes `(status, expires_at)` and `(node_id, status)`
  - FKs: nodes, implementers, implementer_credentials
- `integration-requests.contract.ts` — columns, statuses, CAS transition table, invariants, execution obligations
- Pack append: `MONEY_SCHEMA_PACK_ORDER` + `migration-integrity` SCHEMA_FILES/GREENFIELD (`applies:false`, missingRelation nodes)
- Census report rewritten (`check-schema-census.mjs --write-report`)
- Tests:
  - `integration-requests.census.test.ts` (anchors, scopes, hygiene)
  - `integration-requests.pg.test.ts` (CAS, illegal transitions, consistency, claim atomicity + rollback)
  - pack ordering pin after implementer-credentials

## Out of scope (per ticket)
- Public routes (ZTR-1239)
- PWA approval (ZTR-1240)
- Runtime store / writers

## Verify (this tip)
| Command | Result |
|---|---|
| `pnpm --filter @zucoins/node-core build` | green; sql copied to dist |
| Targeted: census + pack + migration-integrity + integration-requests.pg + schema-census | 5 files / 76 tests pass |
| Forbidden terms in new surfaces | clean (`sweep` avoided; expiry-job wording) |
| Full monorepo forbidden-term scan | pre-existing hits on main (drain/order in unrelated files; money-schema-pack ZTR-1214 "pack order" comment) — **none introduced by this change** |

## Dual review
Money-path adjacent frozen schema → strict dual review required before merge.
