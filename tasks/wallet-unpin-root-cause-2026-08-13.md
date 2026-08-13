# Wallet unpin root cause — 2026-08-13

**Ticket epic:** ZTR-1274  
**Incident child:** ZTR-1281  
**Environment:** staging generic-node (2026-08-12)

## Summary

After the ZTR-1247 fix wave deployed (2026-08-12 ~13:23Z), four expired
`RECEIVE_EXTERNAL` operations stayed attention-parked (`T0_RELEASE_MISMATCH`)
with their wallets `PINNED`. Every sanctioned release path failed. At
15:32–15:33Z the operator was forced into raw SQL and stamped
`wallet_lease_memberships.release_reason = 'EXPIRED_T0_UNCHANGED'` **without**
minting `receive_release_proofs` rows and **without** `audit_log` entries —
forged protocol evidence (re-audit finding F2).

Affected operation ids (full UUIDs):

| Short | UUID |
| --- | --- |
| `4bec5ae4` | `4bec5ae4-2b46-4542-b7e2-9d57105ab9fe` |
| `4fc07a73` | `4fc07a73-9b84-474f-a1ca-1ff9f7e70820` |
| `5316a5f2` | `5316a5f2-5d19-40f7-9324-fe0ad677646e` |
| `e123d38d` | `e123d38d-3451-4bfe-9e00-7e587debd3e0` |

## Mechanism (proven live 2026-08-13)

The expiry-release rule demands a **post-expiry** proof that the wallet head is
unchanged:

- Predicate `FRESH_VERIFIED_T0_EXACT` requires
  `fresh.observed_at >= expiry + 30s`
  (`packages/node-core/src/receive/expiry-release.ts`).
- `safeUnchangedRelationship` admits only
  `DUPLICATE` / `EQUIVALENT_STATE_DIFFERENT_ENVELOPE`.

But the observation ledger's exact-repeat dedup refuses to record a read of an
unchanged head:

- `ExactRepeatService.classify` returns `SUPPRESS_AS_SIGHTING` for
  byte-identical verified bytes (`packages/node-core/src/observation/dedup.ts`)
  — cursor counter only, **no new row**.
- `persistSqlObservation` then returns the cursor's
  `last_recorded_observation_id`, i.e. the **pre-expiry T0 row**
  (`apps/generic-node/src/money-workers/sql-observation-persistence.ts`).

So:

| Head | What happens | Outcome |
| --- | --- | --- |
| Unchanged (the safe, releasable case) | Read suppressed → fresh id == T0 id → freshness window unsatisfiable | `FRESH_VERIFIED_T0_EXACT` + `NO_ANOMALY_LINEAGE_OR_SUBMIT` fail → parked forever |
| Changed (unsafe) | Row appended, T0-exact fails | Parked (correct) |

**Auto-release of an assigned expired receive with an unchanged head was
structurally impossible on this codebase at the time of the incident.**
Break-glass `RELEASE_EXPIRED_RECEIVE` delegates to the same reader + service
and rolls back. `RETRY_OBSERVATION`'s `PROVEN_NOT_LANDED` classification feeds
no release action. The remediation script refuses terminal ops. `FORCE_RELEASE`
deliberately does not exist. The operator was structurally cornered.

## Live evidence (staging, 2026-08-12 / 13)

- All four ops: zero `gateway_submit_attempts`, zero `operation_transactions`,
  zero anomalies; every `receive_expiry_attention_events` row recorded
  `failed_predicates = ["FRESH_VERIFIED_T0_EXACT","NO_ANOMALY_LINEAGE_OR_SUBMIT"]`.
- `gateway_observations`: 9 rows ever as of the investigation window; latest
  ~11:32Z Aug 12 — zero rows appended after the deploy despite the worker
  reading every ~2s until 15:33 (deploy logs showed parks; zero
  `fresh-head read failed` lines).
- Live in-container replay of deployed `createSqlFreshHeadReader` against
  op `5316a5f2`'s receiver wallet: `READ_OK` returning that op's **own T0
  observation id**, observation row count unchanged. Gateway reachable
  (HTTP 200).

## Related tickets

| Ticket | Role |
| --- | --- |
| ZTR-1247 | Fix wave that deployed before the parks |
| ZTR-1251 | Fresh-head wiring — necessary but insufficient alone |
| ZTR-1274 | Epic: make expiry-release satisfiable |
| ZTR-1275 | Append exact-repeat confirm-reads as `DUPLICATE` |
| ZTR-1277 | Exclude attention-parked receives from the expiry sweep |
| ZTR-1278 | Needs-attention inbox must list parked EXPIRED/REJECTED |
| ZTR-1281 | This incident record + staging audit annotations |
| ZTR-1265 | Forced cleanup this epic makes unnecessary |

## What we are trying to avoid

- Wallets pinned forever with no working release path (dead custody capacity).
- Operators forced outside the audit trail; forged release evidence in money tables.
- A "proof-backed" release protocol whose proofs are unmintable by construction.
- Later readers treating the four forged memberships as evidence that auto-release
  worked before the fix.

## Durable follow-ups (not this doc)

- Code fix path: ZTR-1275 (+ siblings under ZTR-1274).
- Staging data hygiene + operator training artifact: ZTR-1281
  (`docs/operations/incidents.md` § forged EXPIRED_T0_UNCHANGED releases).
