# ZTR-1225 — implementer r2 (Review B rework)

## Binding
- PR #90 · branch `ztr-1225-typecheck-tests`
- Prior FAIL head: `8df4d4222b76a881631c3e3c16df925f6d822222`
- Claim run: `7be9a03f-0b91-473a-9701-dc8a6d855c38`
- Worktree: `/Volumes/Ai Building/.zup-scratch/ztr-1225-impl-r2`

## B FAIL root cause
Review B: `makeRouter` in `admin-device-keys.test.ts` dropped required `nodeId: NODE_ID` from `createAdminRouter` deps and cast the incomplete object `as never`. Production inventory uses `deps.nodeId` → `store.listActiveByNode(nodeId)` (`admin-router.ts`), so inventory returned `{ keys: [] }` with HTTP 200. Same `nodeId` drop + `as never` pattern in `admin-g4-device-dual-push.test.ts` `makeRouter` (and a trailing `as never` on the absent-policy fixture that already had `nodeId`).

## Fix
1. Restore `nodeId: NODE_ID` on `createAdminRouter` deps in:
   - `apps/generic-node/test/admin-device-keys.test.ts` `makeRouter`
   - `apps/generic-node/test/admin-g4-device-dual-push.test.ts` `makeRouter`
2. Remove the router-deps `as never` casts on those fixtures (and `makeRouterWithEnrol` / g4 absent-policy fixture). Keep legitimate brand-field casts on enrol body payloads (pre-existing, not deps holes).
3. `AdminUser` login fixtures correctly omit `nodeId` (not on `AdminUser`).

## Head SHA
`HEAD_SHA_PLACEHOLDER`

## Verification
| Command | Result |
|---|---|
| `pnpm install --frozen-lockfile` | ok |
| `pnpm build:tsc` / `tsc -b` | ok |
| `pnpm --filter @zucoins/generic-node typecheck:tests` | **0 errors** |
| `pnpm typecheck` | ok |
| `vitest run test/admin-device-keys.test.ts test/admin-g4-device-dual-push.test.ts` | **23 passed** (incl. inventory returns 1 key) |

## Files
- `apps/generic-node/test/admin-device-keys.test.ts`
- `apps/generic-node/test/admin-g4-device-dual-push.test.ts`
- `tasks/ztr-1225-implementer-r2.md`

## Deferred
None. Dual review required again (money-path + funded-affecting CI control from original PR scope).
