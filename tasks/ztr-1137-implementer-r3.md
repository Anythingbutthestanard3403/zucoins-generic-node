# ZTR-1137 implementer r3 — dual-FAIL r2 rework

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/45
- **New head:** `28e63bfaced059e77921520a0b81d4f4f20d5665`
- **Claim:** run=54349484-55f9-43f8-b1b6-03414a38c1c0
- **Prior FAIL head:** `7d2edd7c1cd9bc8bb5d513758233c666bb376e9e`
- **Isolated:** `/Volumes/Ai Building/.zup-scratch/ztr-1137-r3/`

## Closed vs r2 Review B residuals

| Attack | Census |
|---|---|
| step/job `if: false` / actor skip | RED |
| `continue-on-error` yes/`"true"`/True/1 | RED |
| block body first-line + `exit 0`/`true` | RED |

Parser: always-true `if:` only; YAML truthy COE; full-body exact gate + SUCCESS_MASK. Files: `packages/node-core/test/ci-workflow.census.test.ts`, `tasks/ZTR-1137-ci-gates.md`.

## Hosted residual (honest, unfixable from repo)

Actions still `startup_failure`/`BuildFailed` jobs=0 (account/entitlement); permissions enabled; protection API 403. Maximized local census; no admin claim.

## Release

Requesting **QA Review** of head `28e63bfaced059e77921520a0b81d4f4f20d5665`. Do not merge from this lane.
