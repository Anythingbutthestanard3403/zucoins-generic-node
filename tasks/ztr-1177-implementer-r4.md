# ZTR-1177 implementer r4 — Review B r3 FAIL remediation

- **Lane:** implementer · run=`4383dac6-6276-4309-a776-8c34fc1e989c`
- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/53
- **Branch:** `ztr-1177-vault-unlock-canary`
- **Prior FAIL head:** `1825eea67053fd85a4b715f149ade902d1012ef3`
- **New head:** `f84a8daa41013b331e3574bd13d53dc543f668cf`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1177-r4/wt`
- **Blocker (Review B r3):** D-B5 `rewrapBootCanary({old,new})` false-settled STABLE when durable canary still under old (in-memory reseal, no commit)
- **Released to:** QA Review (dual custody A+B)

## Fix

1. **`master-key-rotation.ts` `verifyCompletedStoreCensus`:** restore r2 new-only open-proof (`oldRootKey === newRootKey === new`) after live envelope reload. Do not call both-roots rewrap on finalize.
2. **Ceremony (ROTATING):** unchanged — new-then-old rewrap + `commitBootCanary`.
3. **Tests:** live OLD + ROTATION_COMPLETE refuses settle; pure rewrap new-only roots refuse still-old durable; D-B5 live-new still asserts new-only roots.

## Verify

```
pnpm exec tsc -b --pretty false                                    # exit 0
boot-canary + rotate-cli + master-key-rotation                     # 3 files / 75 passed
```
