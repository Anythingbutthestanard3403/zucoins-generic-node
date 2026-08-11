# ZTR-1220 — implementer r5 (Review B r4 FAIL clearance)

## Summary
Closed the residual human-pattern class that still sealed under the r4 finite
dictionary/media floor. Non-list defenses (math digit constants, ceremony
mnemonic pad shape, high Latin-vowel letter skeletons, open English n-gram
density, open-lexicon cover) refuse off-list English/media/geo/song mnemonics
and π-prefix digit heads without extending a ticket-by-ticket allowlist.
SPA structure mirror kept in lockstep; throw-not-emit retained. Generate-only
wire change still deferred (client-CSPRNG must open the shown seal; server
cannot return secret on create) — class floor closes the residual without that
wire contract change.

## Review B r4 clearance
1. **Math digit constants / long digit runs** — max digit run ≥8 and π/e/√2
   prefixes; closes `314159265358979323846ABCDA`.
2. **Ceremony mnemonic pad** — year `20xx` + `KEY`/`ABC` on letter-heavy
   bodies; closes HOGWARTS/GANGNAM/STARWARS/… hand-rolled pads.
3. **High Latin-vowel fraction** — leet-folded skeleton vowel frac ≥0.40 with
   ≥18 letters; closes compound English without year pad
   (`TAB1ECHA1RH0VSEWATER2024XA`).
4. **Open English n-grams** — classic bigram/trigram density thresholds
   (not ticket FA lists).
5. **Open-lexicon cover** — non-overlapping ≥4-letter general English cover
   ≥8 (or ≥6 with elevated vowels).
6. **SPA** — `recoveryPackSecretStructureOk` mirrors; generate still throws
   after 64 redraws.
7. **Tests** — unit + seal + HTTP + SPA cover B-r4 opposed FA table (10 named).

## Acceptance criteria
1. **Satisfied** — B-r4 residual false-accepts refuse `weak_secret` / HTTP
   `weak_recovery_secret`; `createRecoveryPack` throws (named list below).
2. **Satisfied** — shape + extended structure + non-list human-pattern floor.
3. **Satisfied** — SPA CSPRNG generate-by-default; mirror rejects same residual
   set; no weak last-resort emit.
4. **Satisfied** — unit / HTTP / SPA tests for residual class.

## Named residual list (must reject — B-r4 opposed bar)
- `THECAKE1SA11EP0RTA12024XXA`
- `H0GWARTSEXPRESS2024KEYABXA`
- `GANGNAMSTY1E2024KEYABCDEXA`
- `HARRYP0TTERWAND2024KEYABXA`
- `STARWARSJED1K1GHT2024ABXAB`
- `GAME0FTHR0NES2024KEYABCXXA`
- `314159265358979323846ABCDA`
- `TAB1ECHA1RH0VSEWATER2024XA`
- `NEWY0RKC1TY2024KEYABCDEXAB`
- `SPH1NX0FB1ACKQVARTZ2024XXA`

## Dual-review VOID fence
Prior r1–r4 PASS/FAIL pairs are VOID at this tip until both opposed lanes PASS
again (money-path hit). Binding prior FAIL: B r4 @ `192ed0603b0331bf55a0b9091d23b3eb2d77ade9`.

## Design note
Generate-only (refuse caller-supplied secrets) remains deferred: the SPA
ceremony posts a client-CSPRNG secret that must open the same seal the operator
is shown; server-side generate would require returning the secret in the create
response (forbidden on the durable idempotency row). The non-list class proxies
above close the residual without changing that wire contract.
Added reject rate under the new floor is ~1.5% CSPRNG FPR on the human-pattern
guards alone; combined with prior structure floor, 64 redraws remain ample.

## Verification
```
pnpm --filter @zucoins/generic-node exec tsc -b
pnpm --filter @zucoins/generic-node exec vitest run src/ops/recovery-pack.test.ts
  # 37 passed
pnpm --filter @zucoins/generic-node exec vitest run test/admin-recovery-pack.test.ts
  # 11 passed
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 41 passed
```

## Files
- `apps/generic-node/src/ops/recovery-pack.ts` — human-pattern class floor
- `apps/generic-node/src/ops/recovery-pack.test.ts` — B-r4 residual unit + seal
- `apps/generic-node/test/admin-recovery-pack.test.ts` — HTTP residual rejects
- `apps/generic-node/admin/src/lib/money.ts` — SPA mirror
- `apps/generic-node/admin/src/lib/money.test.ts` — SPA parity residual rejects
- `docs/operations/recovery-ceremony.md` — structure floor wording
- `tasks/ztr-1220-implementer-r5.md` — this handoff

## Head SHA
`fd37af33be20c7db30c740cf6a4fdf6a8ebf437d`
