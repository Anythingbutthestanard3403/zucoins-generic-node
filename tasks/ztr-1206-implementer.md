# ZTR-1206 implementer handoff

**PR:** #83  
**Head SHA:** `07d756a082b315c914836a657f0ad9d4dc35df37`  
**Branch:** `ztr-1206-template-backup-gate`  
**Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1206-impl`  
**Run:** `9c53f403-0fd8-4f82-9740-7049b9cae2ec`

## Problem
`.env.example` shipped `NODE_ENV=production` with `BACKUP_SCHEDULE_ENABLED=false`.
`loadStage1Config` refuses that pair (durable backup policy), so a local
`cp .env.example .env` failed stage-1 boot after filling CHANGE_ME secrets.

## Decision (sweeper-locked)
Template posture = local-dev friendly: set `NODE_ENV=development`. Keep the
production+backup-off gate fail-closed.

## Change
1. `.env.example`: `NODE_ENV=development`; comments at NODE_ENV and
   BACKUP_SCHEDULE_ENABLED requiring production to enable the schedule.
2. `env-template.census.test.ts`: pin the pair; assert `loadStage1Config` accepts
   the copied template; drop forced NODE_ENV override now that template is dev.
3. `stage1-config.ts` **unchanged**.

## AC
| # | Criterion | Status |
|---|-----------|--------|
| 1 | Template boots stage-1 without backup-off refusal | satisfied |
| 2 | NODE_ENV=development in template | satisfied |
| 3 | Comments at both vars | satisfied |
| 4 | Census/tests updated | satisfied |
| 5 | Gate stays fail-closed | satisfied (untouched; stage1-production still covers) |

## Governing spec
Ticket sweeper AC 2026-08-11; stage-1 durable backup policy in
`apps/generic-node/src/stage1-config.ts`; ops: `docs/operations/README.md`.

## Verification at `07d756a082b315c914836a657f0ad9d4dc35df37`
- `pnpm install` — ok
- `tsc -b` — exit 0
- `pnpm --filter @zucoins/generic-node lint` — exit 0
- vitest: env-template.census + stage1-production + config-schema + config-placeholders
  — **4 files, 97 tests passed**
  (global-setup teardown may ETIMEDOUT on local `psql DROP DATABASE` — not a test fail)

## Files touched
- `apps/generic-node/.env.example`
- `apps/generic-node/test/env-template.census.test.ts`

## Deferred
None.
