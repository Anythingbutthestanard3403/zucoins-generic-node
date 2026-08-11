# ZTR-1220 — implementer r6 (Review B r5 FAIL clearance)

Claim run: `7be9a03f-0b91-473a-9701-dc8a6d855c38`

## Binding FAIL
B r5 @ `1b4a827d7ed5fd36e40b9bad2b0272f6a0946053` — residual human mnemonics still SEAL
when caller-supplied. List/proxy growth is not clearance.

## Fix (generate-only create — mandatory)

1. **`createRecoveryPack` / `reissueRecoveryPack`** refuse any caller-supplied seal
   secret (`caller_supplied_secret`). Seal key is always `generateRecoverySecret()`
   CSPRNG (Crockford×26 + structure redraw).
2. **Admin create** `parseRecoveryPackCreateBody` rejects any body `recovery_secret`
   with `caller_supplied_recovery_secret` (weak or strong, including B r5 table).
3. **Show-once response**: live create response includes `recovery_secret`; durable
   idempotency row strips it via `durableResponseBody` on atomic admin mutation
   (pack file + seal key never co-persist on replay row).
4. **SPA**: no pre-create secret field; `postRecoveryPackCreate` never sends a secret;
   shows `result.recovery_secret` once after create.
5. **Docs**: recovery-ceremony.md states generate-only + Crockford×26 structure; drops
   measured 128-bit content-entropy floor claim for operator-chosen strings.
6. **`createRecoveryPackForTests`**: fixture-only path for prove/open tests with fixed
   secrets (production create/reissue never call it).

## Tests (failing→passing)

- Unit: caller-supplied weak + strong + B r5 residual sample → `caller_supplied_secret`;
  omit secret → seals; open works.
- HTTP: same residuals + strong PACK_SECRET → `caller_supplied_recovery_secret`;
  generate path returns secret once and open matches master; re-issue generate-only.
- SPA: throw-not-emit retained on `generateRecoveryPackSecret`; page is generate-only UI.
- Do **not** clear by growing `OPEN_ENGLISH_WORDS`.

## Verification

```
pnpm --filter @zucoins/generic-node exec vitest run \
  src/ops/recovery-pack.test.ts test/admin-recovery-pack.test.ts
  # 51 passed
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/admin-auth-errors/codes.census.test.ts
  # 11 passed
pnpm --filter @zucoins/generic-node-ui exec vitest run \
  src/lib/money.test.ts src/pages/ceremony/RecoveryCeremonyPage.test.tsx
  # 48 passed
pnpm --filter @zucoins/generic-node exec tsc -b
  # exit 0
```

## Files

- `apps/generic-node/src/ops/recovery-pack.ts`
- `apps/generic-node/src/ops/recovery-pack.test.ts`
- `apps/generic-node/src/ops/atomic-admin-mutation.ts`
- `apps/generic-node/src/admin-router.ts`
- `apps/generic-node/test/admin-recovery-pack.test.ts`
- `apps/generic-node/admin/src/lib/money.ts`
- `apps/generic-node/admin/src/pages/ceremony/RecoveryCeremonyPage.tsx`
- `apps/generic-node/admin/src/pages/ceremony/RecoveryCeremonyPage.test.tsx`
- `packages/generic-node-contracts/src/admin-auth-errors/codes.ts`
- `docs/operations/recovery-ceremony.md`
- `tasks/ztr-1220-implementer-r6.md`

## Head SHA

(see git tip after commit)
