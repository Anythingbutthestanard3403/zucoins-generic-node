# ZTR-1167 implementer r2 (post-revert re-land)

**PR:** #94  
**Branch:** `ztr-1167-contract-gate-doc-drift-r2`  
**Base:** `main` @ `dac8a97c` (includes revert #93)  
**Claim run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`  
**Code head (gates proven):** `1661f85a4df7b94ec90db846dc289225c8a82531`  
**PR tip:** pin via `gh pr view 94 --json headRefOid` after this docs commit lands on the branch.

## Why r2

- PR #87 dual-PASS @ `abef7622` merged as `03b62b64`, then **reverted** by #93 (`dac8a97c`).
- #87-attributable red: `route-policy.json` hash `ea36c430…` vs goldenRefs still `3ffb4072…`.
- See `tasks/ztr-1167-merge.md`.

## Commits

1. `51738c03` — cherry-pick product fix from `e7233ecc` (ZTR-1167 body)
2. `1661f85a` — pair goldenRefs + `gen/contract-drift-manifest.json` to actual sha256  
   `ea36c430ecc3d066a3e5c57dae9dc8d0f71edcf423694c603b9f9b94bcee6626`
3. this file — implementer r2 handoff

## Acceptance (same as r1 + golden pair)

| Item | Status |
| --- | --- |
| Product fix re-applied on post-revert main | satisfied |
| `ROUTE_POLICY_CONCERN_MANIFEST.goldenRefs` == file sha256 | satisfied (`ea36c430…`) |
| `gen/contract-drift-manifest.json` pin updated | satisfied |
| fixture-drift / registry-walk / additive-safety | PASS (98 tests w/ freeze + json-sync) |
| node-core boundaries + pipeline stage order | PASS (75) |
| `tsc -b` | PASS |
| No unpaired golden edit | satisfied |

## Evidence (local @ `1661f85a`)

```
npx tsc -b                                          # exit 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/testkit/fixture-drift-gate.test.ts \
  src/drift-audit/registry-walk.test.ts \
  src/drift-audit/additive-safety.test.ts \
  src/route-policy/manifest.freeze.test.ts \
  gen/json-sync.test.ts
  # 5 files, 98 passed

pnpm --filter @zucoins/node-core exec vitest run \
  test/boundaries.test.ts \
  test/request-pipeline-stage-order.test.ts
  # 2 files, 75 passed
```

## Residual (pre-existing on main; not this PR)

`generic-core.scan-gate.test.ts` still fails on unmarked `order`/`drain` in files landed by later tickets (e.g. ZTR-1214 pack comment, safety-alerts, origin-relay-rate-limit, shutdown-registry). Same red on current `main` without this PR. Out of ZTR-1167 r2 scope; do not block re-land of the golden pair.

## Release

- Lane released → **QA Review**
- Do not merge until dual review.
