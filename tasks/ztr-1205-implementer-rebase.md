# ZTR-1205 implementer rebase (PR #81)

- **lane:** implementer
- **run:** `7690cdf8-676f-47eb-a019-a1f39143a4a1`
- **prior dual-PASS head:** `dc5f6826c0509aa84f9af71dd0c26b277f27de14`
- **product HEAD:** `2de5b6456587148ba79e0928f7e54512614f7528`
- **branch tip (docs pin):** `3da67d0e5a9fc41df396f19469db37de408106e9`
- **base:** `origin/main` @ `aee2eb8121db36aa7ff0682cbcac183dc3d8e457` (includes #85 ZTR-1227 + #83 ZTR-1206)
- **PR:** #81 (`ztr-1205-fleet-scripts`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1205-rebase`

## Why

Merger blocked: `mergeable=CONFLICTING` after #85 landed the real strict-dual fence.
PR head still carried loud-fail stubs for `ORCHESTRATION.md` and
`scripts/release-targets-strict-dual.mjs`. Dual PASSes at `dc5f682` are void after rebase.

## Conflicts (add/add) — resolution

| File | Resolution |
|------|------------|
| `ORCHESTRATION.md` | **ours = main** — keep #85 real gate doc (70 lines). Drop PR fleet-bootstrap ORCH draft. |
| `scripts/release-targets-strict-dual.mjs` | **ours = main** — keep #85 real 488-line fence. Never re-stub. |

`scripts/claim.py` was identical on main (#85) and dropped from the rebased commit
(already present; no delta).

## Product still unique to this PR (vs main)

```
M  .gitignore
M  release/targets.v1.json
A  scripts/assert-origin-url.mjs
A  scripts/assert-origin-url.test.mjs
A  scripts/linear.py
A  scripts/verify-local.sh
```

### Registry follow-up (required after #85)

Main now fail-closes on unknown non-doc paths. Without registry entries,
`release-targets.mjs classify` returned `UNCLASSIFIED_PATH` for
`assert-origin-url*.mjs` and `verify-local.sh`. Added controlGlobs:

- `scripts/assert-origin-url*.mjs`
- `scripts/verify-local.sh`

(`scripts/linear.py` was already on `ignoredGlobs` from #85.)

## Classification at new head

```
manualReviewRequired: true
moneyPathHit: false
controlPaths: release/targets.v1.json, scripts/assert-origin-url.mjs,
              scripts/assert-origin-url.test.mjs, scripts/verify-local.sh
ignoredPaths: .gitignore, scripts/linear.py
affectedTargets: []
```

Funded-affecting-control → STRICT dual re-review required at new head.

## Local verify (PASS) @ `2de5b6456587148ba79e0928f7e54512614f7528` (tip `3da67d0e5a9fc41df396f19469db37de408106e9`)

| check | result |
|-------|--------|
| `node scripts/release-targets.mjs validate` | VALID |
| `node scripts/release-targets.mjs classify --base origin/main --head HEAD` | exit 0, dual required |
| `node scripts/money-path-scan.mjs scan --base origin/main --head HEAD` | moneyPathHit: false |
| `python3 scripts/linear.py selftest` | selftest ok |
| `python3 scripts/claim.py selftest` | selftest ok |
| `node --test scripts/assert-origin-url.test.mjs` | 11/11 pass |
| `bash scripts/verify-local.sh` | exit 2, cites ZTR-1227 |
| fence vs main | byte-identical (488 lines, no stub) |
| ORCHESTRATION vs main | byte-identical |
| claim.py vs main | byte-identical |
| `pnpm release:test` (pre-second-rebase) | 86/86 pass |

## Push

`git push --force-with-lease origin ztr-1205-fleet-scripts`

## Hand-off

Dual re-review at product head `2de5b6456587148ba79e0928f7e54512614f7528` (branch tip `3da67d0e5a9fc41df396f19469db37de408106e9`). Ticket → **QA / In Review**.
