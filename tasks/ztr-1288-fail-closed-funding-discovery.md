# ZTR-1288 — fail-closed funding on discovery (post-review FAIL)

## Ticket / PR
- **Ticket:** ZTR-1288
- **PR:** #143 (`feat/ztr-1288-expose-funding`)
- **Prior FAIL head:** `10ccfb71de70a1d901fe2df83180257449508cfc`
- **Governing plan:** `docs/proposals/splitchain-verifiable-funding-wallet.md` §1.2.A
- **Review defect:** silent `.catch(() => null pin)` on `defaultFundingWallet.get()` in
  `apps/generic-node/src/full-http-mount.ts` discoveryDocument — DB/read failures published
  as healthy unset funding on public discovery.

## Fix
- Removed the silent catch. `discoveryDocument` now awaits `defaultFundingWallet.get()`
  directly alongside signing-key registry reads. Rejection propagates; well-known already
  maps discoveryDocument throw → structured 503 `service_unavailable`
  (`runtime-listener.test.ts` "fails discovery closed…").
- Identity path was already fail-closed (`implementer-identity-router.ts` catch → 503);
  discovery now matches that class.

## Regression test
- `apps/generic-node/test/discovery-document.test.ts`
  — "rejects discoveryDocument when the default-funding wallet read throws"
  (pool throws on `node_settings` funding key read).

## Verification (this head)
```
pnpm exec vitest run test/discovery-document.test.ts
  → Test Files 1 passed | Tests 8 passed
pnpm exec eslint src/full-http-mount.ts test/discovery-document.test.ts
  → clean
pnpm exec tsc -p tsconfig.tests.json --noEmit
  → clean
pnpm --filter @zucoins/generic-node test
  → Tests 1302 passed (118 files); one vitest-worker onTaskUpdate timeout noise only
```

## Files
- `apps/generic-node/src/full-http-mount.ts` — remove silent catch
- `apps/generic-node/test/discovery-document.test.ts` — fail-closed regression
- `tasks/ztr-1288-fail-closed-funding-discovery.md` — this handoff

## AC status (post-fix)
1. Healthy funding set → still met (unchanged identity + discovery happy path).
2. Unset not swapped / unhealthy not masked as unset → **now met** for discovery.
3. Contract/census/tests → discovery suite green; no contract change.
4. Dual review + merge → pending re-dual after this push.
