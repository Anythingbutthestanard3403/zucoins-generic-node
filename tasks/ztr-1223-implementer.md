# ZTR-1223 implementer

## Ticket
Move retraction leaves `status=NEEDS_ATTENTION` so an ambiguous move can never re-raise.

## Spec / contract
- Frozen MOVE_INTERNAL transitions: `packages/generic-node-contracts/src/operations/states.contract.ts` — no `NEEDS_ATTENTION → NEEDS_ATTENTION` edge; retraction is flag-only (not a status transition).
- Operator retraction: `apps/generic-node/src/operations/sql-attention-retraction-store.ts` clears `attention_required` / `attention_reason`, leaves `status`.
- Re-park call site: `apps/generic-node/src/money-workers/move-advanced-ports.ts` `reconcileAndLand`.

## Fix
1. Re-park guard keys on `attention_required` (live flag), **not** `status === 'NEEDS_ATTENTION'`.
2. When status is already `NEEDS_ATTENTION` but the flag was cleared (post-retraction), re-raise attention only: CAS `attention_required false→true` + dual-chain `operation.needs_attention` event; do **not** call `persistMoveOutcome` (would throw on missing frozen edge).
3. Unchanged while flag is raised: hold, no re-append, leases retained.

## AC
1. Guard on `attention_required` — **met**
2. After retraction, subsequently-ambiguous move re-raises — **met**
3. Regression test retract → re-ambiguous → re-park — **met** (`ZTR-1223` case in `move-advanced-ports.pg.test.ts`)
4. No frozen transition table change — **met**

## Files
- `apps/generic-node/src/money-workers/move-advanced-ports.ts` — guard + re-raise path
- `apps/generic-node/test/move-advanced-ports.pg.test.ts` — regression

## Verify (this head)
- `pnpm install` — ok
- `tsc -b` — no errors
- `pnpm --filter @zucoins/generic-node lint` — clean
- `vitest run test/move-advanced-ports.pg.test.ts -t "INDETERMINATE|ZTR-1223|INVARIANT_BREACH"` — **3 passed** | 12 skipped
  - INDETERMINATE park + one-shot hold
  - ZTR-1223 retract → re-raise → hold
  - INVARIANT_BREACH park

## Money-path
Touches `apps/generic-node/src/money-workers/**` — money-path dual review required. `scripts/money-path-scan.mjs` is a 0-byte stub on tree; classified from path ground truth.

## Deferred
None.
