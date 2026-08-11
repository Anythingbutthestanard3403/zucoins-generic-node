# ZTR-1166 — implementer

**PR:** #91  
**Head SHA:** 57b570a4c42ac0541e34a92ea937e862eeed38a2  
**Branch:** `ztr-1166-dead-code`  
**Governing:** ticket body + sweeper 2026-08-11 locked defaults (`tasks/audit-2026-08-06.md` §6)

## Scope done

| # | Action | Result |
|---|--------|--------|
| 1 | Delete `admin/src/lib/demo-data.ts` | deleted |
| 2 | Delete SPA demo/fixture branch | `demoMode`/`setDemoMode`/`apiOrDemo` gone; soft reads → `apiSoftRead`; demo-only tests removed |
| 3 | Delete 5 dead barrel re-exports | removed from `packages/node-core/src/index.ts` |
| 4 | Delete `createIdempotencyService` | deleted `operator/idempotency.ts` + test; export dropped |
| 5 | Tables | **DEFERRED** — owner decision still required; no schema drop |
| 6 | Unconsumed knobs | removed `INITIAL_ADMIN_USERNAME`, `PROOF_ACCESS_WINDOW_SECONDS`, `WORKER_CLAIM_TTL_MS`, `RECONCILIATION_POLL_INTERVAL_MS` from env-schema/mutable/.env.example + tests. **Kept** `TRUST_PROXY_*` (ZTR-1210) |
| 7 | `enginesQuiesced` | true only when ever-armed **and** `moneySurface === "quiesced"`; never-armed explicit test |
| 8 | Security headers | `admin-spa.ts` uses `computeSecurityHeaders("admin")`; removed unused CORS emission helpers / `NODE_SECURITY_HEADERS` / `isCheckoutFrameAllowed` with zero prod callers. `decideAdminCors` retained (admin-cors + tests) |

## Verify (at head)

- `tsc -b` — clean  
- `pnpm --filter @zucoins/generic-node-ui typecheck` + `build` + `lint` — clean  
- `pnpm --filter @zucoins/generic-node-ui test` — **41 files / 299 passed**  
- `pnpm --filter @zucoins/generic-node` graceful-stop + config tests — **127 passed**  
- `pnpm --filter @zucoins/node-core` security-headers — **7 passed**  
- `pnpm test:boundaries` — **162 passed**  

## Deferred

- Item 5 durable tables (`api_rate_buckets`, `auth_failure_state`, `operator_halts`, `worker_cursors`) — out of scope per sweeper; separate ticket after owner answer.
