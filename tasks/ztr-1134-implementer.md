# ZTR-1134 implementer

**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/42  
**Head SHA:** `b522810eb497178bdb21cb7c24aca7517c73f3c2`  
**Branch:** `ztr-1134-totp-seal` ← `origin/main`  
**Claim run:** `47e526d2-6699-4048-ba31-0aaba6293fa8`

## Done
1. Seal site `packages/node-core/src/totp/seal.ts` — AES-256-GCM, HKDF `zupayments/totp-secret/v1`, AAD = admin_operators.id
2. Rewrap `totp/rewrap.ts` + master-key-rotation / CLI ports (IMPLEMENTED)
3. Registry: `productionSealSite`, `rewrapStatus: IMPLEMENTED`, `table: admin_operators` FROZEN
4. `SqlAdminUserStore` seals on write / opens on read via vault root
5. Migrate: drizzle `0007` add `totp_secret_sealed`, `0008` conditional DROP plaintext; boot `migrateTotpSecretsAtRest` seals residual base32 then drops column
6. Tests: seal/open wrong-AAD, rewrap after rotation, plaintext migrate drill, census/boundaries

## Verify @ b522810
| cmd | result |
|-----|--------|
| `tsc -b` node-core + generic-node | clean |
| node-core targeted (totp seal, census, boundaries, rotation, admin-totp-enrol) | 149 passed |
| generic-node (route-policies, rotate-cli, migrate-guards) | 44 passed |

## AC
- [x] Seal site matches registry
- [x] Plaintext migrated to sealed envelopes
- [x] Plaintext column removed / not readable as base32
- [x] Enrol/login TOTP works
- [x] Tests + migration drills
- [x] Gates green
