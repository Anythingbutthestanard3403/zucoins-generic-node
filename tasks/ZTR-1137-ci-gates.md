# ZTR-1137 CI-gates handoff (r2)

- Head under test: see PR tip after push (implementer r2).
- Base at branch creation: `12603b1d2663c47fbeaffb114f398fb5271b8ebd`.
- Prerequisites: ZTR-1163 / ZTR-1164 remain ancestors of `origin/main`.

## r2 changes (dual-FAIL rework)

1. **Fail-closed workflow census** (`packages/node-core/test/ci-workflow.census.test.ts`)
   - Parses active (comment-blanked) workflow YAML; required gates must be live `run:` steps.
   - Rejects `# run: …`, `run: … || true`, `continue-on-error: true`, and comment+echo smuggling.
   - Disposable mutations held RED then restored GREEN (comment-out build, `|| true`, echo-skip, job continue-on-error, strip `PG_REQUIRED`).
2. **SHA-pin third-party actions** in `.github/workflows/ci.yml` (checkout / pnpm / setup-node).
3. **Base-owned gate reds fixed on this branch** (so required CI can go green):
   - `leadership.ts` `no-useless-catch` (lint)
   - `leadership.test.ts` forbidden term `drain` → `flush` (scan / boundaries / contracts)
   - `migration-integrity` inventory + greenfield characterizations for
     `transaction-material-byte-immutability.sql`, `lease-foundation` enum-first miss,
     `observation-relationship-adjudications` enum-first miss; composition `pgcrypto` search_path
   - `destination-bless-atomic` fixture adds `destinations.label`
   - `durable-security-ports` supplies `vaultRootKey` for SqlAdminUserStore default
   - `send-completion-lander` pins signed expiry at seed time (insert-only sign intents)

## Local gates at r2 tip

| Gate | Result |
|---|---|
| `pnpm build` | PASS |
| `pnpm lint` | PASS (0 errors; pre-existing warnings only) |
| workflow census | 6/6 PASS + mutation battery RED→GREEN |
| `pnpm test:boundaries` | 5 files / 162 tests PASS |
| contracts suite | 225 files / 2732 tests PASS (r2 pre-fix + scan green after drain rewrite) |
| schema census | 39 nouns OK |
| admin unit | (covered by root projects; not re-run full in r2) |
| Playwright Chromium | 23/23 PASS |
| migration-integrity | 10/10 PASS with `TEST_DATABASE_URL` |
| destination-bless-atomic | 4/4 PASS |
| durable-security-ports | 13/13 PASS |
| send-completion AC3 + F1.1 | PASS |

## Hosted Actions / branch protection (residual)

- Prior head `004b8df` runs concluded `startup_failure` / path `BuildFailed`, zero jobs.
- Actions permissions API: enabled=true, allowed_actions=all; account has admin on repo.
- Branch protection / rulesets API: **403** plan gate on private free repo — this lane cannot mark required checks without Pro/public or org admin plan change.
- Sibling private repos show recent `BuildFailed` on schedules and sparse successes since mid-July — possible account-minutes / runner entitlement residual outside YAML.
- After r2 push head `bc2e0d2`: runs 31448970879 (push) and 31448973820 (pull_request) still `startup_failure` / `BuildFailed`, jobs=0. Residual is account/entitlement, not workflow parse (actionlint 0; yaml.safe_load ok).

## Deliberately broken commit

- Local: census mutations prove gate neutering fails closed (see above).
- Hosted: requires a run that actually schedules jobs; blocked while `BuildFailed` persists.

## Scope

Workflow + census + base-owned harness/inventory fixes only. No production money-path guard relaxed.
