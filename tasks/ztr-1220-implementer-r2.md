# ZTR-1220 — implementer r2 (Review B FAIL clearance)

## Summary
Tightened the create/reissue structure floor so Crockford×26 residual low-entropy
secrets no longer seal. SPA mirror matches; last-resort weak emit removed.

## Review B clearance
1. **Near-period / repeated structure** — `hasRepeatedStructure` rejects exact
   tilings, lag-p match runs ≥6, match fraction ≥0.4, and any substring of
   length ≥4 appearing twice (closes letmein/hunter2/PACKSECRET near-tiles).
2. **Same-symbol + multi-triple blocks** — `hasLongSameRun` (max same-run 4;
   ≥2 blocks of length ≥3).
3. **Step-k monotone** — any constant non-zero alphabet delta run ≥6 (not only ±1).
4. **Letter-only run ≥14** — catches Crockford-mapped dictionary phrases
   (CORRECTHORSE…, MASTERKEY…).
5. **Vacuous 128-bit belt** — no longer constant-true on the secret; now a
   compile-time alphabet×length floor check only. `estimateRecoverySecretEntropyBits`
   stays diagnostics-only.
6. **SPA** — structure floor mirrored; throws after 64 redraws instead of
   last-resort weak emit.
7. **Tests** — unit + seal + HTTP cover Review B residual list; SPA throw path.

## Acceptance criteria
1. **Satisfied** — residual false-accepts refused (named Review B secrets + prior ticket literals).
2. **Satisfied** — shape + tightened structure guards in `recovery-pack.ts`.
3. **Satisfied** — SPA CSPRNG generate-by-default; no weak last-resort emit.
4. **Satisfied** — unit / HTTP / SPA tests accept strong / reject residual weak.

## Head SHA
`e13a01d803c3d5e0607a16f7c27b6e10038a999d`

## Verification (at head)
```
pnpm exec tsc -b                                      # exit 0
pnpm --filter @zucoins/generic-node-ui typecheck      # exit 0
pnpm --filter @zucoins/generic-node lint              # exit 0
pnpm --filter @zucoins/generic-node-ui lint           # exit 0
pnpm --filter @zucoins/generic-node exec vitest run src/ops/recovery-pack.test.ts
  # 34 passed
pnpm --filter @zucoins/generic-node exec vitest run test/admin-recovery-pack.test.ts
  # 11 passed
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 38 passed
```

## Files
- `apps/generic-node/src/ops/recovery-pack.ts` — near-period / same-run / step-k / letter-run
- `apps/generic-node/src/ops/recovery-pack.test.ts` — residual class tests
- `apps/generic-node/test/admin-recovery-pack.test.ts` — HTTP residual rejects
- `apps/generic-node/admin/src/lib/money.ts` — SPA mirror + throw on floor miss
- `apps/generic-node/admin/src/lib/money.test.ts` — SPA throw test
- `docs/operations/recovery-ceremony.md` — structure floor wording
- `tasks/ztr-1220-implementer-r2.md` — this handoff
