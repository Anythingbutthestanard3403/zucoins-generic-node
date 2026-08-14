# ZTR-1129 technical-FAIL remediation plan

**Pinned origin/main:** `4522c668a741b22e64c6c378f751de25c94daf6b`  
**Kind:** planning only. Do not implement in this checkout.  
**Trigger:** Review A PASS vs Review B FAIL → orchestrator TECHNICAL FAIL. Ticket stays QA Review / FREE.  
**Live confirm (ZTR-1308, do not absorb):** op `df31265d` — `operations` REJECTED, `send_operations` still NEEDS_ATTENTION; unique index still pins; next create is `WALLET_IN_FLIGHT` / `no_free_send_worker`. Three stuck sends already have STEP_1.

## 1. Root cause

Causal chain:

1. One-in-flight is **not** the `operations` status and **not** the source lease. It is the partial unique index `send_operations_one_unsettled_per_source_wallet` (`packages/node-core/src/schema/send-external-create.sql`) — `WHERE status NOT IN ('EXTERNAL_SEND_LANDED','REJECTED')`. `SqlSendCreateStore` maps that 23505 to `WALLET_IN_FLIGHT`.
2. Operator CLOSE is `createSqlRecoveryActionStore` under `BEGIN ISOLATION LEVEL SERIALIZABLE` (`apps/generic-node/src/operations/sql-recovery-store.ts`). `SQL_CAS_CLOSE_NEVER_STARTED` and `SQL_CAS_CLOSE_PROVEN_NOT_LANDED` UPDATE **only** `operations` → REJECTED (clear attention, bump `row_version`). They never UPDATE `send_operations`.
3. After a “successful” CLOSE the UI/`operations` row looks terminal, `releaseSourceLeasesForOperation` may mint/consume `lease_release_proofs` and drop `wallet_active_leases`, but `send_operations` stays APPROVED / NEEDS_ATTENTION. The index still holds `source_wallet_id`.
4. Existing AC6 drill (`sql-recovery-store.pg.test.ts` “wallet is re-leasable”) only `insertLease`s a second **operations** row. It never `INSERT`s a second `send_operations` row, so the unique-index pin is invisible. `seedSendOperation` writes `operations` only; `seedSendOperationsRow` exists solely for the ZTR-1226 oracle tripwire.
5. Live stuck sends already have STEP_1. `CLOSE_NEVER_STARTED` is illegal even when head == Ts0 (`SQL_CAS_CLOSE_NEVER_STARTED` `NOT EXISTS signer_audit` / five formation negatives). The path that must actually terminalize `send_operations` is `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` (bounded F2.2 oracle). Today that path also leaves `send_operations` unsettled.

Sibling already correct, not reused: landing locksteps `send_operations` then `operations` in one TX (`send-sql-ports.ts` / `landing-sql-store.ts`). `SEND_CRASH_RECOVERY_SQL.CLOSE_NEVER_STARTED_CAS` already UPDATEs `send_operations` APPROVED→REJECTED under the same negatives — **unit-tested only**, not called from the SQL recovery store.

## 2. Target design

Same SERIALIZABLE CAS transaction that already consumes nonce + burns TOTP must terminalize **both** rows, then release the lease the way it already does. Fail-closed if either write misses.

Per CLOSE, in order, same client:

1. Existing `operations` CAS (predicates unchanged).
2. Sibling `send_operations` CAS to the **same** terminal (`REJECTED` for both CLOSE kinds; `EXTERNAL_SEND_LANDED` is not a CLOSE effect — that remains the lander / F2.2 late-land path).
3. If either `RETURNING` is empty → `ROLLBACK`, `predicate_failed` (do not leave a split brain).
4. Then `releaseSourceLeasesForOperation` (mint `lease_release_proofs` `EXTERNAL_SEND_LANDED` + `releaseLease` + `completeGroupOperation`). Lease still only via a consumed proof row.
5. Existing audit_log insert + COMMIT.

`send_operations` guards:

- Never-started: reuse / keep lockstep with `CLOSE_NEVER_STARTED_CAS` — `status = 'APPROVED'` AND no sign_intent / partial / signer_audit. Do **not** require `send_operations.row_version == operations.row_version` (independent counters).
- Proven-not-landed: new statement — `status = 'NEEDS_ATTENTION'` → `REJECTED`, clear `attention_required` / `attention_reason` (co-presence CHECK in `send-external-expiry.sql`), bump `row_version`. Do **not** re-encode the oracle in SQL (planner already re-proved). Do **not** touch partial / approval / audit rows.
- Missing `send_operations` row on a SEND_EXTERNAL close is a miss (fail-closed). Production always has the pair.

Do not auto-advance CLOSE to `EXTERNAL_SEND_LANDED`. Late land stays `verifyExternalSendLanding`.

## 3. File-level change list

1. `packages/node-core/src/core/send-crash-recovery.ts` — keep `CLOSE_NEVER_STARTED_CAS`; add `CLOSE_PROVEN_NOT_LANDED_CAS` (NEEDS_ATTENTION→REJECTED + attention clear). Export both as the send-side authority.
2. `apps/generic-node/src/operations/sql-recovery-store.ts` — both CLOSE arms: after operations CAS wins, run the matching send CAS on the same client; 0 rows → ROLLBACK; only then `releaseSourceLeasesForOperation`. Import node-core SQL rather than forking a third copy of the never-started negatives.
3. `apps/generic-node/test/sql-recovery-store.pg.test.ts` — seed `send_operations` on every SEND close drill; assert both statuses; add the unique-index second-INSERT drill; add STEP_1 refuse + moved-head INDETERMINATE; tighten AC6 so re-lease is not enough.
4. `packages/node-core/test/send-crash-recovery.test.ts` — freeze the new proven-not-landed send SQL the same way never-started is frozen (`NOT EXISTS` / status / attention clear).
5. Optional one-line ops note in `docs/operations/attention-triage.md` (CLOSE terminals **both** tables). No schema / index / contract DDL change.

Do not touch: unique index text, `FORBIDDEN_RECOVERY_ACTIONS`, lander, ZTR-1308 staging rows, `FORCE_*`.

## 4. Test strategy

All new proofs in `sql-recovery-store.pg.test.ts` against real PG (existing harness). Use `STATEMENTS.INSERT_CREATED` or a raw `INSERT INTO send_operations` that would hit `send_operations_one_unsettled_per_source_wallet`.

Must add:

| Drill | Pass condition |
| --- | --- |
| **CLOSE then second send INSERT** | After `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` (and a twin for never-started), `operations` **and** `send_operations` are REJECTED; a second `send_operations` insert for the same `source_wallet_id` **succeeds** (no 23505). |
| **STEP_1-present never-started refused** | `signer_audit` purpose `STEP_1` (and/or sign_intent / partial) + `operations`/`send_operations` APPROVED → CLOSE_NEVER_STARTED `predicate_failed` / `close_never_started_cas_miss`; **both** rows stay APPROVED. Head==Ts0 does not license this path. |
| **Moved head INDETERMINATE** | Durable partial + expired+margin + fresh head ≠ Ts0 and no complete-path exclusion → `classifyRecovery` INDETERMINATE; CLOSE_PROVEN_NOT_LANDED **not** permitted; no status write. |
| **Lease still only via proof** | Keep existing AC5: close with a held lease → one consumed `lease_release_proofs` row (`proof_kind = EXTERNAL_SEND_LANDED`); no `wallet_active_leases`; membership `released_at` set. |

Also repair the two existing close tests (never-started / proven-not-landed) to seed `send_operations` and assert the pair. Repair AC6: after close, second send **insert** + new lease, not lease-only.

Unit: keep recovery-actions / recovery-inspection predicates; add send-crash-recovery SQL freeze for the new CAS.

## 5. What not to do

- No `FORCE_RELEASE`, `FORCE_LANDED`, or any `FORBIDDEN_RECOVERY_ACTIONS` token.
- No hand SQL on staging / live to flip `send_operations` (that is ZTR-1308 after this lands).
- Do not drop, widen, or invert `send_operations_one_unsettled_per_source_wallet`. Terminal pair stays an exclusion list.
- No auto-bless / timer-only close / generic PROVEN_NOT_LANDED oracle. Bounded ZTR-1226 oracle unchanged.
- Do not treat lease release as AC6. Lease-free + index still holding is the live bug.
- Do not close never-started when STEP_1 / signer_audit / sign_intent / partial exists, even if head == Ts0.
- Do not write `EXTERNAL_SEND_LANDED` from a CLOSE arm.
- Do not absorb ZTR-1308 stuck-row cleanup into this ticket.

## 6. Per-AC mapping after remediations

| AC | After this change |
| --- | --- |
| **AC1** CLOSE_NEVER_STARTED APPROVED→REJECTED when five negatives hold | Both tables REJECTED in one TX; second send insert allowed. STEP_1 still refuses. |
| **AC2** CLOSE_PROVEN_NOT_LANDED under bounded oracle (expiry+margin AND head==Ts0 OR complete-path exclusion) | Both tables REJECTED; this is the live terminalizer for STEP_1-present parked sends. |
| **AC3** Formation-boundary / STEP_1 never-started refuse | Unchanged predicates; new PG proof both rows stay APPROVED. |
| **AC4** Moved / unproven head stays INDETERMINATE | Unchanged classifier; new PG proof CLOSE withheld, no write. |
| **AC5** Lease only via consumed `lease_release_proofs` | Unchanged order: dual status CAS **then** proof mint/consume. Existing drill stays. |
| **AC6** Wallet returns to the pool and is re-leasable | **Met only when** lease is gone **and** unique index no longer holds — proven by a successful second `send_operations` INSERT on the same `source_wallet_id`. Lease-only re-acquire is insufficient. |

Landing ACs in `send-completion-lander.pg.test.ts` (F1.1 park, F2.2 late land) stay out of this diff.

## 7. Staging follow-up (ZTR-1308 only)

After this merges, re-issue `CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED` on the stuck sends (`df31265d` and the other two with STEP_1). That is ZTR-1308. This ticket does not ship a backfill, a one-shot SQL, or a FORCE path.
