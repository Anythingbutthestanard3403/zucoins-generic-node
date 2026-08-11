# ZTR-1172 implementer r2

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/68
- **Head (product):** `ed60ca22563b22f83160fbbadb48ae37d8ac8d57`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1172-r2/`
- **Prior FAIL A/B:** drill not real boot; seeds write-only; case5 dump refuse; release never restamps ready

## Fixed
1. Live `CachedRestoreHoldProbe` + ready `onBeforeEvaluate`/keep-warm restamp after dual-gate release (no restart).
2. Drill boots `NodeReadiness` + `evaluateReadinessFromProbes`; release + live probe re-opens ready.
3. Boot seeds → stream-writer first `loadPrior`; first money tick asserts receive queue vs durable CREATED.
4. Case 5: dump-derived trusted markers → `nonce_burn_high_water_mismatch` refuse.

## Verify
`pnpm exec tsc -b` 0 · contracts readiness 9/68 · health-probes 1/35 · gn dr+readiness+boot-queue+storage+metrics 18/140
