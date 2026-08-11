# ORCHESTRATION — Zucoins Generic Node

Machine-readable release / review gates for this repo. Agent prompts
(`.claude/agents/*`) document call sites; they are not enforcement.

## Review depth

A change is **money-path** if `scripts/money-path-scan.mjs` reports
`moneyPathHit: true` (signing, custody, settlement, golden contracts under
`apps/generic-node/**`, `packages/node-core/**`, `packages/generic-node-contracts/**`,
plus name-pattern hits). Money-path forces **STRICT dual review**.

A change is **funded-affecting-control** if `scripts/release-targets.mjs classify`
reports `manualReviewRequired: true` (hits under `release/**`,
`scripts/release-targets*.mjs`, `scripts/money-path-scan*.mjs`,
`scripts/claim*.py`, decision-check shells + `scripts/release-targets-strict-dual.mjs`,
workflows, …) → same dual-review dispatch as money-path. Merger enforces via
machine fence:

```
node scripts/release-targets-strict-dual.mjs check \
  --base <merge-base-sha> --head <head-sha> --pr <n> [--ticket ZTR-<n>]
```

Exit codes:

- `0` — dual not required, or dual satisfied
- `3` — `REFUSE_MERGE` (strict dual required and unmet, or FAIL at head)
- `2` — gate did not run (usage / unreachable evidence / untrustworthy range)

The fence derives the PASS count from the PR's own **published** verdict
comments (head-pinned, claim-window-checked, unedited, one effective verdict per
reviewer lane). `--pass-count` is an audited operator override that verifies
nothing.

## Dual review = two reviewer runs

For money-path / funded-affecting-control PRs the fence requires:

1. Two distinct lanes: `lane=reviewer-A` and `lane=reviewer-B` (exact case),
   different run ids.
2. Each PASS is a **published PR comment** (an untracked verdict file is not
   admissible). First non-blank heading line carries `PASS` + the exact head SHA.
3. Each comment's `created_at` falls inside that run's live claim window
   (`python3 scripts/claim.py windows <ticket>`).
4. Unedited: `created_at == updated_at` (edited comments are rejected).
5. Pinned to the **current** PR head; verdicts at superseded heads are ignored.
6. Both must be PASS; a single FAIL or a single PASS blocks.

## Single-review path

Non-money, non-funded-affecting-control PRs (data-model / api ordinary path):
dual is not required. One reviewer PASS still follows the same comment / window /
head / unedited rules when evidence is collected; the fence exits 0 without two
PASSes when `dualRequired` is false.

## Related scripts

| Script | Role |
|--------|------|
| `scripts/release-targets.mjs` | Deploy/control classification + registry validate |
| `scripts/money-path-scan.mjs` | Money-path sentinel (review depth only) |
| `scripts/release-targets-verdict-evidence.mjs` | PR comment + claim-window evidence |
| `scripts/release-targets-strict-dual.mjs` | Machine merge fence (this gate) |
| `scripts/claim.py` | Claim windows the fence reads |
| `release/targets.v1.json` | Deploy/control registry |

Governing principles: control hits stay merge-neutral for deploy; money-path
depth is an orthogonal axis; the fence itself is adversarially reviewed (its
paths match `scripts/release-targets*.mjs` controlGlobs).
