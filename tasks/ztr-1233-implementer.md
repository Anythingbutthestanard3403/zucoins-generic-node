# ZTR-1233 — implementer evidence

## Ticket
Approval-stores amendment: `AUTO_POLICY` approval method for machine-committed SEND_EXTERNAL approvals.

## Head
See PR for exact full head SHA (this file is committed on the branch tip).

## What landed
- `approval_method` enum gains `AUTO_POLICY` (greenfield `base-enums-domains.sql` + TS `APPROVAL_METHOD` / `ApprovalMethod`).
- `operation_approvals.challenge_id` and `totp_timestep` nullable; `challenge_id` remains UNIQUE.
- Three-arm method CHECK: `TOTP_AND_DEVICE` / `TOTP_ONLY` / `AUTO_POLICY`.
- Partial unique index `operation_approvals_totp_single_use … WHERE totp_timestep IS NOT NULL`.
- Composite FK retained (MATCH SIMPLE) — NULL `challenge_id` vacuously passes.
- Appended pack slices for already-applied DBs:
  - `approval-method-auto-policy-enum` (ADD VALUE in its own committed slice)
  - `approval-stores-auto-policy` (DROP NOT NULL, replace CHECK, rebuild partial index)
- Contracts, censuses, data-model fixtures, api-schema golden + drift sha updated.
- Real-PG drills: `test/approval-stores-auto-policy.pg.test.ts` (14 cases).

## Out of scope (per ticket)
No behavior change for the manual approve path. Machine writer is ZTR-1234.

## Verify (this tip)
| Command | Result |
|---|---|
| `pnpm build` | green |
| `pnpm lint` | 0 errors (pre-existing warnings only) |
| Targeted node-core (census/pack/migration/pg/boundaries) | 9 files / 171 tests pass |
| Approve path unit + race PG | 11 files / 242 tests pass |
| `@zucoins/generic-node-contracts` api-schema + fixture-drift | 73 pass |
| AUTO_POLICY PG drills | 14 pass |
| `pnpm test` full monorepo | pre-existing failures on main (forbidden-term scan `drain`/`order` in unrelated files; flaky auth-abuse lockout; config-mutable census drift; receive-expiry race) — **none introduced by this change** |
| Forbidden terms in touched files | clean (`pack sequence` wording) |

## Dual review
Money-path adjacent frozen contract → strict dual review required before merge.
