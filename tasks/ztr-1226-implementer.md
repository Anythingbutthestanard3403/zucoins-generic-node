# ZTR-1226 implementer

- **Decision:** (b) AUTHORIZE bounded `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` (Riley lock)
- **PR:** (filled after open)
- **Head:** (filled after push)

## Changes

1. `packages/generic-node-contracts/src/operator-halt/halt.contract.ts`
   - Removed `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` from `RESERVED_RECOVERY_ACTIONS` (only `REBUILD_INTERNAL_MOVE` remains).
   - Prose: CLOSE granted under bounded oracle (expiry+margin AND head-unchanged OR complete-path exclusion); D9.6 generic ban intact.
2. `apps/generic-node/src/operations/sql-recovery-store.ts`
   - `SEND_NON_LANDING_CLOSE_ACTIVATED = true` with ZTR-1226 authorization comment.
3. Admin SPA (`money.ts`): LIVE derived from catalog − RESERVED → CLOSE becomes live automatically; reserved reason text updated for REBUILD-only.
4. Ops notes: `docs/operations/attention-triage.md`, `docs/operations/incidents.md`.
5. Tests: halt.census, recovery-actions (withheld still refuse; oracle-true permitted+executable), sql-recovery-store.pg activation drill, admin money + ApproveInbox.

## Bounds kept

- Not timer-only (aging margin is a gate, not sole license).
- No generic PROVEN_NOT_LANDED oracle.
- `REBUILD_INTERNAL_MOVE` still RESERVED.
- External send hard expiry via signed T2 / `SEND_REDEMPTION_WINDOW` + `redemption_expiry_at NOT NULL` on sign intents (unchanged).

## Verification

- halt.census + recovery-actions + recovery-inspection + forbidden-recovery-surface + send-expiry-contract-freeze: pass
- admin UI suite: 305 pass
- sql-recovery-store.pg ZTR-1226 activation + listNeedsAttention: pass
