# ZTR-1137 CI-gates handoff (r3)

- Head under test: see PR tip after push (implementer r3).
- Base at branch creation: `12603b1d2663c47fbeaffb114f398fb5271b8ebd`.
- Prerequisites: ZTR-1163 / ZTR-1164 remain ancestors of `origin/main`.

## r3 changes (dual-FAIL r2 rework)

1. **Census residual bypasses closed** (`packages/node-core/test/ci-workflow.census.test.ts`)
   - Reject step/job `if:` that is not always-true (`false`, actor filters, etc.).
   - Treat YAML truthy `continue-on-error` (`true` / `True` / `yes` / `on` / `y` / `1` / quoted).
   - Gate match requires **full run body** exact command (not first-line-only).
   - `SUCCESS_MASK` / soft-exit (`exit 0`, bare `true`, `|| true`, `set +e`) over full body.
2. Workflow YAML unchanged in structure (already SHA-pinned; no skippable `if:`).
3. Prior r2 base-owned lint/scan/migration/harness fixes retained.

## Local gates at r3 tip

| Gate | Result |
|---|---|
| workflow census | 6/6 PASS |
| mutation battery | RED then restore GREEN (see below) |

### Mutation battery (must hold RED)

| Attack | Result |
|---|---|
| step `if: false` + live `run: pnpm build` | RED |
| job `if: false` / `if: github.actor == 'nobody-ever'` | RED |
| `continue-on-error: yes` / `"true"` / `'true'` / `True` / `1` / `true` | RED |
| job `continue-on-error: yes` | RED |
| block `run: \|\n  pnpm build\n  exit 0` / bare `true` | RED |
| same-line `pnpm build \|\| true` | RED (r2 hold) |

## Hosted Actions / branch protection (residual — account, not YAML)

- Hosted tip runs still conclude `startup_failure` / path `BuildFailed`, **jobs=0**.
- actionlint-clean workflow; permissions enabled; cannot force job schedule from repo YAML alone.
- Branch protection / rulesets API: **403** on private free plan — cannot mark required checks from this lane.
- **Unfixable from repo:** account/runner entitlement residual. Delivery enforcement maximized via local census + fail-closed parser; hosted proof blocked until Actions schedules ≥1 job.

## Deliberately broken commit

- Local: census mutations prove gate neutering fails closed (table above).
- Hosted: requires a run that schedules jobs; blocked while `BuildFailed` persists.

## Scope

Census fail-closed only in r3 (plus retained r2 fixes). No production money-path guard relaxed.
