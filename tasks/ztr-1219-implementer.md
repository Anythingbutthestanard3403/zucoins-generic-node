# ZTR-1219 — implementer handoff

## Summary
`createECDH("prime256v1").getPrivateKey()` returns a **minimal-length** big-endian
P-256 scalar. ~1/256 keys are 31 bytes (leading zero dropped). Callers seal and
assert a fixed 32-byte field (`toHaveLength(32)` on open), so short scalars
corrupted the push ECE path intermittently.

## Fix
- `packages/node-core/src/push/crypto.ts`
  - `P256_PRIVATE_KEY_LENGTH = 32`
  - `padP256PrivateKeyBytes()` left-pads short scalars
  - `generateEcdhKeypair()` always returns a 32-byte private scalar
  - `ecdhFromPrivateKeyBytes()` pads on load (legacy short seals still work; same curve point)
- Export pad helper + constant from `packages/node-core/src/push/index.ts`
- Unit tests: `packages/node-core/src/push/crypto.test.ts`

## Acceptance criteria
1. ✅ Private scalar left-padded to 32 bytes before seal/use at crypto.ts generation site
2. ✅ Test forces 31-byte short scalar and asserts pad → 32; seal/aes128gcm tests green
3. ✅ No public-key / ECE algorithm change beyond length normalisation
4. ✅ `pnpm --filter @zucoins/node-core test` green

## Governing spec
- Module contract in `packages/node-core/src/push/crypto.ts` + `seal.ts` (32-byte P-256 ECDH scalar)
- Ops context: `docs/operations/README.md` — Push delivered-envelope shape
- No new decision register entry required (length normalisation only)

## Verification (exact head)
See PR body for SHA + command output summaries.

### Commands
- `CI=true pnpm install --frozen-lockfile` — ok
- `npx tsc -b` — clean
- `pnpm --filter @zucoins/node-core test` — 8094 passed | 10 skipped | 5 todo (447 files)
- `pnpm --filter @zucoins/node-core lint` — 0 errors, 5 pre-existing warnings

## Files
- `packages/node-core/src/push/crypto.ts` — pad + generate/load
- `packages/node-core/src/push/crypto.test.ts` — short-scalar forced case + sample
- `packages/node-core/src/push/index.ts` — exports
- `tasks/ztr-1219-implementer.md` — this handoff

## Deferred
None.
