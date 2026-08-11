# ZTR-1172 implementer rebase (wave9)

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/68
- **Prior product (r2):** `ed60ca22563b22f83160fbbadb48ae37d8ac8d57`
- **Prior tip (docs pin):** `cd65bb4203037b507f109f70aed40fe259b76031`
- **New HEAD:** `e71f7614fd3579d617272d977497f1cac5c56095` (docs tip pinning rebased product `00511381ed74f4234064df262853b5a23d69d6d5`)
- **Rebased product:** `00511381ed74f4234064df262853b5a23d69d6d5`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1172-rebase-w9`
- **Base:** `origin/main` @ `295486f4399e8227c9f128067b454a9af38e10b6` (after #58/#66/#67)

## Conflicts resolved (smallest keep-both)

1. `apps/generic-node/src/money-workers/gateway-t0-observer.ts` — kept ZTR-1162 `readGatewayAction?` **and** ZTR-1172 `bootPriorRawByStreamKey?` on `GatewayT0ObserverDeps`.
2. `apps/generic-node/src/money-workers/start-money-workers.ts` — `resolveMoneyPathT0Observer` forwards **both** optional deps into `createGatewayT0Observer`.

r2 product preserved: live restore_hold probe, real drill boot, stream-writer seed handoff, case-5 refuse.

## Verify (at branch tip)

| suite | result |
|---|---|
| `pnpm exec tsc -b` | 0 |
| contracts readiness | 9 files / 68 tests pass |
| node-core health-probes | 1 file / 35 tests pass |
| gn dr + readiness + boot-queue + storage + metrics | 19 files / 141 tests pass |
