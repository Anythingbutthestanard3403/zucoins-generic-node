# ZTR-1288 — Expose funding_wallet_id + funding_wallet_public_key on discovery / implementer identity

## Status
Implementer complete. PR opened for QA Review.

- **Head SHA:** `13ac86e9bac926c564573668e5c5af44ec3ffb0c`
- **Branch:** `feat/ztr-1288-expose-funding` (based on ZTR-1287 PR #142 head `4636bfaa`)
- **Run id:** `0ffb0090-41ff-4060-bb7e-86747ffd5e29`
- **Blocked on 1287?** Soft-depends: PR stacks on #142. Merge #142 first (or merge-queue will need rebase if 1287 lands differently).

## Governing plan
`docs/proposals/splitchain-verifiable-funding-wallet.md` §1.2.A (also mirrored under sibling “Zucoins Generic Node” tree). Ticket body ZTR-1288.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Healthy integration with funding set returns id + pubkey matching admin selection | **Yes** — `GET /v1/implementer/identity` resolves implementer pin else node default via `resolveEffectiveFundingWallet` |
| Unset funding is not silently swapped to a worker or merchant key | **Yes** — explicit `null` + `funding_configured: false` + `funding_source: "unset"`; discovery publishes nulls for node default when unset |
| Contract/census/tests green | **Yes** — see verification |
| Dual review + merge | **Pending** — `moneyPathHit: true` → STRICT dual review |

## What changed (1288-only atop 1287)

1. **Contracts**
   - `DISCOVERY_RESPONSE_FIELDS` += `funding_wallet_id`, `funding_wallet_public_key` (9 fields)
   - New route `GET /v1/implementer/identity` (`implementer_bearer`, scope null, tenant-scoped)
   - OpenAPI / route-policy / api-schema goldens + census counts updated

2. **Discovery builder** (`packages/node-core/src/api/discovery.ts`)
   - Optional `fundingWalletId` / `fundingWalletPublicKey` on `DiscoveryConfig`
   - Empty string → null; fields always present on wire

3. **Effective pin resolver** (`resolve-effective-funding-wallet.ts`)
   - Precedence: implementer explicit pin → node default → unset
   - Dangling id without pubkey does **not** fall through to default (`configured: false`)

4. **Identity router** (`implementer-identity-router.ts`)
   - Bearer-auth GET returns `{ implementer_id, funding_wallet_id, funding_wallet_public_key, funding_configured, funding_source }`

5. **Wiring**
   - `full-http-mount` discoveryDocument reads `defaultFundingWallet.get()`
   - `implementerIdentityLoaders` from registry + default port
   - `runtime-listener` mounts identity router; main passes loaders

## Unset / unhealthy signal (documented choice)
- **Discovery:** always returns keys; values `null` when node default unset or unresolvable. Never omits fields; never substitutes worker keys.
- **Identity:** `funding_configured: false` when either id or pubkey missing; `funding_source` is `implementer` | `node_default` | `unset`.

## Verification (at `13ac86e9`)

```
pnpm typecheck  # pass

pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/api-schema/api-schema.census.test.ts \
  src/route-policy/manifest.freeze.test.ts \
  src/operations/routes.census.test.ts \
  src/testkit/fixture-drift-gate.test.ts
# Test Files 4 passed | Tests 106 passed

pnpm --filter @zucoins/node-core exec vitest run \
  test/discovery.test.ts test/openapi-freeze.test.ts test/deployment-health.test.ts \
  src/implementer/resolve-effective-funding-wallet.test.ts \
  src/api/implementer-identity-router.test.ts
# Test Files 5 passed | Tests 71 passed

pnpm --filter @zucoins/generic-node exec vitest run \
  test/discovery-document.test.ts test/route-policies-mount.test.ts test/runtime-listener.test.ts
# Test Files 3 passed | Tests 62 passed

node scripts/money-path-scan.mjs scan --base origin/main --head HEAD
# moneyPathHit: true → STRICT dual review
```

## Files touched (why)
- contracts discovery/routes/route-policy + gen goldens — freeze surface
- node-core discovery + identity router + resolver + openapi — wire + pure logic
- generic-node mount/listener/main + tests — production wiring + census

## Deferred
- Per-implementer funding on public discovery (discovery is node-default only; per-integration is identity endpoint)
- `GET /v1/funding/availability` (out of scope)
- Send hop / INSUFFICIENT_FUNDING_WALLET (ZTR-1289)
