# ZTR-1220 — implementer r4 (Review B r3 FAIL clearance)

## Summary
Closed the residual human-pattern class that still sealed under the r3
row/dict floor: keyboard **columns** (+ reverse stitches / diagonals),
reversed dictionary skeletons, off-list English/media mnemonics, broken
step-k / same-delta walks, paired doubles, custody single-token marks, and
Fibonacci digit prefixes. SPA structure mirror kept in lockstep; throw-not-emit
retained. Generate-only wire change still deferred (client-CSPRNG must open the
shown seal; server cannot return secret on create).

## Review B r3 clearance
1. **Keyboard columns / diagonals / multi-column stitches** — walk builder from
   physical QWERTY layout; closes `1QAZ2WSX…`, `ZAQ1XSW2…`, reverse column-order.
2. **Reversed dictionary skeleton** — match forward + reversed letter/leet
   skeletons and reversed tokens; closes `TCERR0CESR0HYRETTABE1PATS2`.
3. **Media / English / song / ticket tokens** — expanded ≥5 dict + custody
   single-hit LEN4 (`NODE`/`PASS`/…); closes B-r3 FA table mnemonics.
4. **Broken step-k** — same-delta pair count ≥10 + strided monotone ≥6;
   closes `BP1CQ2DR3…`, `5AFMS49E…`.
5. **Paired doubles** — ≥4 distinct doubled-letter blocks; closes `AA1BB2CC3…`.
6. **Fibonacci digit run** — ≥5 consecutive digits exact/mod-10 Fib;
   closes `112358…`.
7. **SPA** — `recoveryPackSecretStructureOk` mirrors byte-for-byte; generate
   still throws after 64 redraws.
8. **Tests** — unit + seal + HTTP + SPA cover B-r3 opposed bar sample table.

## Acceptance criteria
1. **Satisfied** — B-r3 residual false-accepts refuse `weak_secret` / HTTP
   `weak_recovery_secret`; `createRecoveryPack` throws (named list below).
2. **Satisfied** — shape + extended structure floor in `recovery-pack.ts`.
3. **Satisfied** — SPA CSPRNG generate-by-default; mirror rejects same residual
   set; no weak last-resort emit.
4. **Satisfied** — unit / HTTP / SPA tests for residual class.

## Named residual list (must reject — B-r3 opposed bar + extended)
- `1QAZ2WSX3EDC4RFV5TGB6YHN0P` / `…7V` / `ZAQ1XSW2…` / `P0MJV7…`
- `THEQV1CKBR0WNFXJVMPS2024AX` / `STR4NGERTH1NGS…` / `HACKTHEP1ANET…`
- `TCERR0CESR0HYRETTABE1PATS2`
- `BP1CQ2DR3ES4FT5GV6HW7JX8KY` / `5AFMS49EKRX8DJQW1CHPV05GNT`
- `AA1BB2CC3DD4EE5FF6GG7HH8JJ`
- `MANP1NXG3TXKEYN0DE2024ABC2` / `112358DN2QSG9S2VXRND2FH0HH`
(+ full FA table in unit tests)

## Design note
Generate-only (refuse caller-supplied secrets) remains deferred: the SPA
ceremony posts a client-CSPRNG secret that must open the same seal the operator
is shown; server-side generate would require returning the secret in the create
response (forbidden on the durable idempotency row). The non-list structure
proxies above close the residual class without changing that wire contract.
CSPRNG reject rate under the tighter floor ≈4.5% at n=26; 64 redraws remain ample.

## Verification
```
pnpm --filter @zucoins/generic-node exec tsc -b
pnpm --filter @zucoins/generic-node-ui exec tsc --noEmit
pnpm --filter @zucoins/generic-node lint
pnpm --filter @zucoins/generic-node exec vitest run src/ops/recovery-pack.test.ts
  # 36 passed
pnpm --filter @zucoins/generic-node exec vitest run test/admin-recovery-pack.test.ts
  # 11 passed
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 40 passed
```

## Files
- `apps/generic-node/src/ops/recovery-pack.ts` — columns/stride/doubles/rev-dict/fib
- `apps/generic-node/src/ops/recovery-pack.test.ts` — B-r3 residual unit + seal
- `apps/generic-node/test/admin-recovery-pack.test.ts` — HTTP residual rejects
- `apps/generic-node/admin/src/lib/money.ts` — SPA mirror
- `apps/generic-node/admin/src/lib/money.test.ts` — SPA parity residual rejects
- `docs/operations/recovery-ceremony.md` — structure floor wording
- `tasks/ztr-1220-implementer-r4.md` — this handoff

## Head SHA
`d67b2ba0b3d13a3eadd28efbc7f8f43a9ab3960c`
