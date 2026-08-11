# ZTR-1171 implementer evidence

**Head SHA:** `28a56fcfbb79a773b157c143ddc5dedef1b59077`
**Branch:** `ztr-1171-custody-hardening`
**Claim run:** `780bd0d7-f39e-4b50-8127-daa68c9ff6f9`

## Governing spec
- Doc 07 custody (§5.5.2 master-key channel; §5.4.3 device evidence; §3 enrolment authority)
- Spec-conformance audit 2026-08-07 residuals group

## Acceptance

| # | Criterion | Status |
|---|-----------|--------|
| 1 | CLI recovery ceremony does not read master key from persistent env by default | **met** — `resolveCeremonyMasterKey`: FD / interactive TTY; env only with `VAULT_MASTER_KEY_ALLOW_ENV=1` + loud warning |
| 2 | `key_fingerprint_hex` removed or salted high-cost | **met** — PBKDF2-SHA256-600k salt\|\|dk (96 hex); migration 0009 drops legacy 64-hex oracle rows |
| 3 | Device-enrolment events durable in `audit_log` | **met** — `createSqlEnrollmentAuditLog` / `createSqlDeviceRevocationAuditLog` wired in production mount |
| 4 | `passcode` / `pack_file_b64` redacted + test | **met** — `safe-log.ts` + recovery-pack body test |
| 5 | depth-8 / stack emission | **already met on main** — `MAX_DEPTH_MARKER` + `scrubText(stack)`; left as-is |
| 6 | Signer refuses QUARANTINED after lease | **met** — TX-scoped `assertWalletMaySign` in `runLockedSignSection` + SQL state read in `send-signer-deps`; outer `getWallet` on money ports |
| 7 | No `InMemory*` enrolment/revocation audit in production composition | **met** — census test; dual-control uses `fixedDualControlPolicy`. Remaining process-local stores (second-device ceremony, challenge issuer, operator-push) are fail-soft re-issue side stores (commented as such); not enrolment audit authority. |

## Verification (at `28a56fcfbb79a773b157c143ddc5dedef1b59077`)

```
rtk tsc -b                          # No errors found
vitest (targeted): 93 passed / 7 files
  safe-log-redaction, signer-boundary, master-key, census, setup-wizard,
  dual-control-mode-wiring, admin-device-keys
Also green earlier: admin-g4-device-dual-push (18), admin-never-403 (4)
eslint on touched TS sources: clean (when run)
```

## Files
- `apps/generic-node/src/ops/run-recovery-ceremony.ts` — interactive/FD master key
- `apps/generic-node/src/setup-vault-master.ts` + seal-store + drizzle `0009_`
- `packages/node-core/src/device/sql-enrollment-audit.ts` + mount wiring
- `packages/node-core/src/observability/safe-log.ts`
- `packages/node-core/src/core/signer-boundary.ts` + `send-signer-deps.ts` + `main.ts` getWallet

## Deferred
- Full SQL durability for second-device ceremony / approval-issuer / operator-push side stores (ticket called them out to check; not load-bearing permanent-authority enrolment evidence).
- `rotate-master-key.cli.ts` still uses env keys (out of ticket scope; recovery ceremony was the named outlier).
