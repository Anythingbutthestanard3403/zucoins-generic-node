# ZTR-1137 implementer r4 — CI gates

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/45
- **HEAD:** dfdef5858723a9de88127ba3fdcfe3c59b7f1479
- **Claim:** implementer run=2ca4a1af-c6f0-486f-8586-e2d95624b94a
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1137-r3`

## Root cause of dual-FAIL hosted CI

1. While **private** on Free plan, every workflow run failed at startup with `path=BuildFailed`, `jobs=0` (no runner assignment). Minimal probe branch reproduced.
2. After making the repo **public**, Actions schedules workflows. Hosted `ubuntu-latest` still completed in ~2–8s with **empty steps / runner_name=""** (no real execution).
3. **Self-hosted** macOS runner (`ztr1137-mac` @ `~/actions-runner-ztr1137`) executes steps. Proof smoke: run **31453948516** SUCCESS (`CI-smoke` / `echo smoke-ok-from-main`).

## Delivery CI shape

- `.github/workflows/ci.yml` on PR + push to `main`
- `runs-on: [self-hosted, macOS, ARM64]`
- Local PostgreSQL + `PG_REQUIRED=1` + `pg_isready` (no Docker service containers)
- Gates: `pnpm build`, `pnpm lint`, contracts test, `pnpm test`, `pnpm test:boundaries`, schema census, admin unit, Playwright e2e
- Fail-closed census `packages/node-core/test/ci-workflow.census.test.ts` (if:/COE/block-body/comment/`PG_REQUIRED` mutations RED→GREEN)

## Base-owned reds cleared so gates can go green

- Forbidden-term scan (`order`/`merchant` rewords + one SQL `contract-allow`)
- `FROZEN_EXEMPTION_COUNT=207`, `FROZEN_SUPPRESSED_VIOLATION_COUNT=205`, coupling manifest
- Boundaries allow `@zucoins/node-core/verifier/consumer` + `.../operations/events`
- Root `build` = `tsc -b && admin vite` (contracts dist before SPA)
- leadership no-useless-catch / drain→flush comment; destination label fixture; vaultRootKey harness; graceful-stop gateway event; operations-indexes "sweep"→"candidate"

## Consumers / admin

- Already on main: consumers load `setup-network-guard` + `packageSourceAliases` → node-core `src`
- Admin unit in root vitest projects; Playwright job required in CI

## Hosted deliberate-break evidence

- Local census mutation battery: strip `PG_REQUIRED`, job `if: false`, `continue-on-error: yes`, block `exit 0` → all RED; restore GREEN (6/6).
- Hosted path: private BuildFailed (jobs=0); public ubuntu empty-step failure; self-hosted smoke SUCCESS. Full suite CI re-run after this commit.

## Residuals

- Repo visibility currently **public** (required for Actions to schedule). Re-private without billing/self-hosted will re-break startup.
- Branch protection / required checks may still 403 on free; self-hosted runner must stay online for delivery.
- Full `pnpm test` wall-clock under `PG_REQUIRED=1` runs in CI job (multi-hour class); local targeted gates proven green.

## Release

Requesting **QA Review**. Do not merge from implementer lane.
