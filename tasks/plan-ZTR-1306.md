# ZTR-1306 technical-FAIL remediation plan

**Pinned origin/main:** `1d1d2154535b699c3eedc7678b2478167d2419e8`  
**Pinned PR #162 head:** `e07f0ecec57af0600d09c5db70416d2834f8a3c4` (`ztr-1306-dest-on-mint`)  
**Kind:** planning only. Do not implement in this checkout.  
**Trigger:** Review B FAIL — dest-on-mint / backfill write PENDING dests that `SELECT_ELIGIBLE_WALLET` treats as “not a receive worker”. Ticket stays QA Review / FREE.  
**Path:** amend/rebase on PR #162. Do not open a new PR.

## 1. Root cause (allocator predicate vs mint composition)

Causal chain:

1. Receive assignment is `RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET` (`packages/node-core/src/receive/pool-allocator.ts` 107–132). Positive conjuncts are D9.17 receive-eligibility plus `allow_external_receive`. Extra dest exclusion:

   ```
   NOT EXISTS (
     SELECT 1 FROM destinations d
      WHERE d.wallet_id = w.id
        AND d.state IS DISTINCT FROM 'RETIRED')
   ```

   Any non-RETIRED dest row (PENDING or BLESSED) makes the wallet unassignable.

2. That exclusion is **not** D9.17. Governing comments treat dests as sink-only and receive as dest-less:
   - allocator 101–105: predicate is deliberately **not** the automatic-sink form (that one *requires* BLESSED). “Receivers never move and destinations are never blessed.”
   - `docs/proposals/generic-node-redesign-v2/04-data-model.md` 1271: receive-eligibility has **no** `destinations.state` conjunct; automatic-sink = receive-eligibility **plus** `BLESSED`. “Importing `BLESSED` into receive-eligibility would break the pool.”
   - `packages/generic-node-contracts/src/pool-policy/selection.ts` 14–15: “a receiver is never blessed, so no destinations.state predicate.”
   - `packages/generic-node-contracts/src/pool-policy/eligibility.ts` 16–17: “custody selection rule recovery conjunct MINUS blessing (a pool receiver is not a move destination and is never blessed).”
   - `packages/node-core/src/api/destination.ts` 7–10: PENDING is register; only **BLESSED** is internal custody / move / send sink; RETIRED is terminal.
   - `packages/node-core/src/assign-and-topup.ts` 167–177: omit-source top-up resolves `d.state = 'BLESSED'` only (`worker_destination_missing` when that row is absent).

   Historically dest rows existed only via `POST /v1/destinations` (operator intending a sink). “Any live dest ⇒ not a receive worker” was a coarse proxy for that register path. It was never the receive-eligibility spec.

3. PR #162 replaced that world. `insertNodeGeneratedWalletWithPendingDestination` (`packages/node-core/src/api/insert-node-generated-wallet.ts` 16–62) always writes:
   - wallet `money_mode='FULL'` + all three allow flags true
   - `destinations (state='PENDING')` on the same executor

   All three live mint sites call it: destination-register (`apps/generic-node/src/main.ts` 282–289), pool scale-up `MintWallet` (`apps/generic-node/src/money-workers/start-money-workers.ts` 418–426), funding CREATE (`apps/generic-node/src/full-http-mount.ts` 778–782). Census: `apps/generic-node/test/dest-on-mint-production-paths.census.test.ts`.

4. `destinations-pending-backfill.sql` inserts PENDING for **every** `key_origin='node_generated'` wallet missing a dest. No `money_mode` / `allow_*` filter. Imported origin excluded. Idempotent `NOT EXISTS`. PENDING only — never BLESSED.

5. Composition collision:
   - **Migrate:** existing receive-pool workers (AVAILABLE, recovery-verified, `allow_external_receive`) get a PENDING dest → allocator returns empty → receives fall through the backpressure ladder.
   - **New mints:** scale-up / funding / register are born FULL + PENDING dest → also unassignable even before an operator sets RECEIVE_ONLY.
   - Mint has no receive-role parameter. There is no dest-less receive-pool mint today.

Ticket AC still requires a dest row on every node_generated mint so a send worker can be blessed without a second mint (`DESTINATIONS_PENDING_BACKFILL_SOURCE`; `docs/operations/wallet-money-capabilities.md` 48–78). That AC is the original `worker_destination_missing` fix. It cannot be met by writing PENDING on receive-capable wallets **while** the allocator treats dest existence as “not a receive worker.”

## 2. Target design

Evaluate only the two candidates. Do not invent mint-time roles, dest delete-on-mode-flip, or a `WORKER` dest state.

### Candidate A — restrict dest-on-mint / backfill; RECEIVE_ONLY stay dest-less

Keep allocator `IS DISTINCT FROM 'RETIRED'`. Write dests only for send-capable / INTERNAL / FULL / SEND_ONLY. RECEIVE_ONLY remain dest-less so assign still works.

Fails the specs as they stand:

- Mint SQL hardcodes `FULL` (`insert-node-generated-wallet.ts` 16–23). Pool scale-up never writes `RECEIVE_ONLY`. A “skip dest when RECEIVE_ONLY” filter is a no-op at mint; new workers are still born FULL+PENDING and stay unassignable.
- Making pool mint dest-less RECEIVE_ONLY is a new product cut (role-at-mint). Not in ZTR-1306.
- FULL is both receive-capable and send-capable (`docs/operations/wallet-money-capabilities.md` 24–32). Skipping dest on FULL reopens `worker_destination_missing`. Writing dest on FULL reopens this FAIL.
- Restricting backfill to non-RECEIVE_ONLY heals only wallets already flipped to RECEIVE_ONLY. FULL receive workers (the default fleet) still get poisoned.
- Ticket AC “every node_generated mint has a dest” is then false for the receive pool.

A does not work without inventing product. Reject.

### Candidate B — allocator excludes only BLESSED (send-sink) dests, not PENDING

Keep dest-on-mint + unfiltered node_generated backfill (PENDING existence = blessable, not “is a sink”). Narrow the dest exclusion to the automatic-sink token the rest of the tree already uses:

```
AND NOT EXISTS (
  SELECT 1 FROM destinations d
   WHERE d.wallet_id = w.id
     AND d.state = 'BLESSED')
```

PENDING dest-on-mint / backfill no longer poison assign. RETIRED dests stay eligible (already allowed). BLESSED sinks stay out of the receive T0 set — including FULL wallets the operator has blessed.

This is the D9.17 split the allocator comments already name: receive-eligibility has no dest-state *requirement*; automatic-sink **adds** BLESSED. The bug is that the runtime extra-conjunct treated *any live dest* as a sink. Dest-on-mint made that proxy false. PENDING is register/blessability (`destination.ts` 7–10), not custody. `SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL` still requires BLESSED for omit-source top-up.

Do **not** drop the dest exclusion entirely (a BLESSED FULL wallet would become a receive T0). Do **not** exclude “PENDING ∧ send-capable” (that re-poisons default FULL mints). Do **not** require BLESSED as a positive conjunct (that *is* the automatic-sink leak the pg freeze exists to catch).

Historical change: a wallet that was `POST /v1/destinations`’d but not yet blessed, and is still `allow_external_receive`, can be assigned as a receive worker until bless. That matches “only BLESSED is a sink.” After bless it leaves the pool. Acceptable; dest-on-mint already made PENDING mean “every mint,” not “operator designated a sink.”

### Pick: B (smallest correct cut)

Mint helper, three call sites, backfill INSERT filter, `ON CONFLICT (wallet_id)` adopt, unique `destinations.wallet_id` — unchanged.

Comment rewrite on `SELECT_ELIGIBLE_WALLET` (same block, 101–105): dest exclusion is “already a BLESSED sink,” not “any dest row.” Dest-on-mint PENDING is blessability. Still must not import the automatic-sink *requirement* of BLESSED.

`COUNT_AVAILABLE_WALLETS` already omits dest exclusion (`pool-scaler.ts` 112–113). Leave scaler SQL alone. After B, PENDING dests no longer create a scaler/allocator split; BLESSED receive-capable wallets remain the documented dest-exclusion gap.

## 3. File-level change list (amend/rebase PR #162)

Keep as-is (AC still holds):

- `packages/node-core/src/api/insert-node-generated-wallet.ts` + unit
- `packages/node-core/src/api/sql-destination-store.ts` (`ON CONFLICT (wallet_id) DO UPDATE` label adopt)
- `packages/node-core/src/schema/destinations-pending-backfill.sql` INSERT filter (all node_generated missing a dest)
- `packages/node-core/src/schema/destinations-pending-backfill.contract.ts` invariants except any prose that implies dest existence is receive-safe without the allocator change
- `packages/node-core/src/schema/money-schema-pack.ts` append
- `apps/generic-node/src/{main,full-http-mount,money-workers/start-money-workers}.ts`
- `apps/generic-node/test/dest-on-mint-production-paths.census.test.ts`

Change:

1. `packages/node-core/src/receive/pool-allocator.ts` — dest `NOT EXISTS` → `d.state = 'BLESSED'` only. Rewrite the 101–105 comment as in §2. Do not touch lock / attach / release-proof conjuncts.
2. `packages/node-core/test/receive/pool-allocator.pg.test.ts` — retarget the frozen-literal test (360–377): today it requires `d.state IS DISTINCT FROM 'RETIRED'` and `expect(sql).not.toContain("BLESSED")`. After B the exclusion *token* is `BLESSED`; keep the automatic-sink negative as “no positive `d.state = 'BLESSED'` outside the `NOT EXISTS`.” Add the PG drills in §4.
3. `packages/node-core/test/destinations-pending-backfill.pg.test.ts` — keep mint + no-double-row + imported + idempotent. Add (or share a helper with the allocator suite) a backfill → still-selectable receive-eligible wallet case. Prefer asserting `SELECT_ELIGIBLE_WALLET` here only if the scratch schema already has allocator tables; otherwise keep that proof in the allocator pg suite and only seed a PENDING dest the way the backfill would.
4. `docs/operations/wallet-money-capabilities.md` — PENDING dest is blessable, not a receive-pool exclusion. BLESSED (or send-only / internal-only flags) is. Extend the “Receive assign never picks a wallet” row (~119). Fleet query “every node_generated has `dest_id`” stays.

Do not touch: scaler SQL, `UNIQUE (wallet_id)`, destination-register adopt, blessing ceremony, money-mode PATCH, `destination_state` enum.

Amend/fixup on `ztr-1306-dest-on-mint` at `e07f0ece`. Rebase onto `origin/main` `1d1d21545` only if main has moved.

## 4. Test strategy

Existing coverage to keep green: mint helper unit; dest store ON CONFLICT; backfill census + pg (mint one PENDING, register no second row, imported dest-less, re-apply no-op); production-path census; pack order.

Must add (real PG unless noted):

| Drill | Pass condition |
| --- | --- |
| **Receive assign after dest-on-mint** | Mint SQL (or helper) writes FULL + PENDING dest; stamp `recovery_verified_at`; `SELECT_ELIGIBLE_WALLET` / `assignReceiveWallet` selects that wallet. |
| **Send-capable mint still PENDING dest** | Existing mint pg case stays: exactly one dest, `state='PENDING'`. Do not drop it. |
| **Backfill does not poison receive pool** | Seed dest-less receive-eligible node_generated wallet; apply `destinations-pending-backfill.sql`; same wallet still admitted by `SELECT_ELIGIBLE_WALLET`. Imported stays dest-less. |
| **BLESSED still excluded** | Same wallet, dest flipped to BLESSED (valid blessing columns) → allocator returns empty. Negative: widened old conjunct would also exclude PENDING — prove PENDING is admitted. |
| **RETIRED dest still eligible** | Dest `RETIRED` + receive-eligible wallet still selected (no regression). |
| **Register no double-row** | Existing ON CONFLICT case stays: one row, PENDING label adopt. |

Retarget `pool-allocator.pg.test.ts` “frozen literal” so a revert to `IS DISTINCT FROM 'RETIRED'` fails, and so `BLESSED` appearing only inside `NOT EXISTS` does not trip the automatic-sink leak check.

Scaler equivalence test (`pool-scaler.pg.test.ts` 587+) uses dest-less seeds — leave it. Do not add dests there unless also changing scaler (out of cut).

## 5. What not to do

- No auto-bless. Blessing stays device + TOTP.
- No `destination_state` value `WORKER` (or any fourth dest state).
- Do not drop or widen `destinations.wallet_id` UNIQUE.
- Do not invent mint-time RECEIVE_ONLY / dest-less pool mint.
- Do not DELETE dests on money-mode flip to RECEIVE_ONLY.
- Do not filter backfill by receive-mode (that leaves FULL receive workers dest-less *or* still poisoned, and fights the fleet query).
- Do not require BLESSED on receive select (automatic-sink leak).
- Do not drop dest exclusion entirely (BLESSED FULL must stay out of receive T0).
- Do not change scaler / cap / `SKIP LOCKED` / release-proof conjuncts.
- No ZTR-1307 / push-subscribe work.

## 6. Per-AC mapping

| AC | After this change |
| --- | --- |
| Every production node_generated mint has a dest row | Unchanged helper + three call sites + census. |
| Operator can bless that dest without re-mint | Unchanged PENDING row + Destinations bless path. Fleet query still `dest_id IS NOT NULL` for node_generated. |
| Backfill heals dest-less node_generated (not imported); PENDING only; idempotent | Unchanged slice + filter. |
| Register does not double-row | Unchanged `ON CONFLICT (wallet_id)`. |
| Receive assign still works after dest-on-mint / backfill (Review B) | Allocator excludes **BLESSED** only. PENDING dest is not a receive-role mark. New pg drills in §4. |
| BLESSED sinks never become a later receive T0 | Dest `NOT EXISTS` on `d.state = 'BLESSED'` kept. |
| No auto-bless / no WORKER state / unique dest wallet_id | Honoured. |
