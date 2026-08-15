# ZTR-1313 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1313
**Branch:** `ztr-1313-consumer-publishable`
**Base:** `origin/main` `be826b9a1d4e18670ab26941be13b5364e626ab0`
**Claim run:** `41e404a9-80c7-4d54-a9be-d7b31e38680e`

## Ticket
`@zucoins/generic-node-consumer` was unconsumable outside the monorepo (`private: true`, `workspace:*` deps) and missing `verification_mode` on identity/discovery types.

## Design
- Drop `private` on the consumer only. Keep in-repo `workspace:*` for contracts (and node-core as optional peer) so other workspace packages still resolve.
- Both contracts and node-core remain unpublished (`private: true`, `0.0.0`) — no fake npm publish.
- Add contracts `INDEPENDENT | NODE_VERIFIED` on identity/discovery parsers and create/read types.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Published-shape package (`private: false`) | Yes |
| Contracts pin / install path documented | Yes — git-subdir (see PR) |
| Public types + HTTP client consumable; node-core optional peer | Yes |
| `verification_mode` on identity/discovery + parsers | Yes |
| Tests for the new field | Yes |
| No money-worker changes | Yes |
| Drift-gate forbidden terms | Yes — new files clean; consumer not in SCAN_SCOPE |

## Remaining publish blocker
`@zucoins/generic-node-contracts` and `@zucoins/node-core` are still `private: true` / `0.0.0`. A registry publish of consumer cannot resolve them. Independent verification (`pipeline`, verifier re-exports) still needs node-core.

## Verification

```
pnpm exec tsc -b                         # exit 0
pnpm --filter @zucoins/generic-node-consumer test
# Test Files 18 passed | Tests 106 passed
pnpm --filter @zucoins/generic-node-consumer lint
# eslint src --max-warnings 0
```
