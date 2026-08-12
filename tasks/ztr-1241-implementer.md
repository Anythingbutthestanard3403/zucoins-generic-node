# ZTR-1241 — implementer

## Ticket
End-to-end drill + operator runbook for auto-approved external sends.

## Claim
run=`918b32b9-cbae-4eb4-950b-fbaa42f23a10` lane=implementer

## Delivered
- `apps/generic-node/test/auto-approve-e2e-drill.pg.test.ts` — disposable-PG e2e:
  - **Route 2 spine:** public intake → operator tightened approve (cap 100→50 binds) → one-time claim → within-cap send → `AUTO_POLICY` + `SYSTEM`/`send.auto_approved` → `AWAITING_REDEMPTION` + durable transfer code; formation log pins node-never-submits
  - **Boundary probes:** over-cap stays CREATED; halt blocks; policy disable blocks; re-enable clears parked; `wallet_in_flight` second concurrent same-wallet create; claim second GET has no `api_key`
  - **Route 1:** operator implementer + credential + rule → same send-through assertions
  - `registerPgRequiredGuard` after live describe
- `docs/operations/auto-approve-external-sends.md` — fail-closed posture, both routes, spend-vs-cap, three stop levers (halt → disable rule/doc → revoke key), audit tables, spend-never-released, wallet-pool guidance
- `docs/operations/README.md` — index row

## Verify
| Command | Result |
|---|---|
| `pnpm --filter @zucoins/node-core build` | green |
| `pnpm --filter @zucoins/generic-node build` | green |
| `pnpm --filter @zucoins/generic-node typecheck:tests` | green |
| PG drill (`auto-approve-e2e-drill.pg.test.ts`) | 3/3 pass |
| PG worker regression (`auto-approve-worker.pg.test.ts`) | 3/3 pass |
| `operator-docs.census.test.ts` | 38/38 pass |
| eslint drill file | clean |
| Forbidden terms in new surfaces | clean (`drain` avoided) |

## Dual review
Money-path adjacent (e2e over send + auto-approve + integration claim). Strict dual per `ORCHESTRATION.md` / ticket governance.

## Out of scope
- Full monorepo `pnpm test` quiet-machine evidence (merge lane)
- Product code changes (routes 1–2 already landed)
