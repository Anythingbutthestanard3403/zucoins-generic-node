# ZTR-1204 implementer r2 (Review B clearance)

**PR:** #84  
**Head:** 8bc0009bb8c82a1a27bc304899bd62ffa01f0986  
**Lane:** implementer run=72b9e953-48be-44d7-b138-7c399dcbab8e

## Blocker

Review B FAIL: README claimed empty `TEST_DATABASE_URL=` disables provision / skips pg;
code at `vitest.global-setup.ts` treats empty as not a pin (`pinned !== ""`) and still
auto-provisions. Adjacent comment still described the old footgun.

## Fix

- `README.md` Developing / PostgreSQL for tests: empty export is **not** a pin; prefer unset;
  pin only non-empty URL; auto-provision still runs for empty.
- `vitest.global-setup.ts` header: `PG_REQUIRED=1` (CI exports it) refuses silent skip — not bare
  `CI=true`; empty is not a pin.
- `vitest.global-setup.ts` pin site comment: empty treated like unset; continue auto-provision.
- **No code behavior change** — only docs/comments aligned to existing guard.

## Verification

- `CI=true pnpm install --frozen-lockfile` ok
- `npx tsc -b` exit 0
- node-core vitest provision + boundaries: **79 passed** (2 files)
- eslint on touched setup + provision test: exit 0

## AC status

All five original ACs still satisfied; AC3 doc accuracy restored for dual-review clearance.
