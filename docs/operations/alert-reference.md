<!-- GENERATED FILE — do not edit by hand.
     Source: packages/node-core/src/operator/safety-alerts.ts
     Regenerate: node scripts/gen-operator-alert-docs.mjs
     Gate: apps/generic-node/test/operator-docs.census.test.ts -->

# Alert reference

One section per entry in `SAFETY_ALERT_SIGNALS`. Severity, citation, posture, the
diagnostic-only flag and the numeric bands are the values the running evaluator uses.

A **fire is advisory**. No alert advances a cursor, infers chain truth, releases a lease
or changes money state — the operator does, through the actions in
[`incidents.md`](incidents.md).

`Feeds` states whether the reading is actually produced on a live node. A signal marked
*unbound* has a correct rule and a permanently zero input: it will never fire, and you
must not treat its silence as an all-clear. Prometheus rules that watch the exposed
metrics directly are in [`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml).

## Summary

| Signal | Severity | Diagnostic only | Feeds |
| --- | --- | --- | --- |
| [`invariant_breach`](#invariant_breach) | P0 | no | **unbound** |
| [`duplicate_submit_attempt`](#duplicate_submit_attempt) | P0 | no | **unbound** |
| [`lease_age`](#lease_age) | P1 | yes | live |
| [`path_gap`](#path_gap) | P1 | no | **unbound** |
| [`regression`](#regression) | P1 | no | **unbound** |
| [`endpoint_disagreement`](#endpoint_disagreement) | P1 | no | **unbound** |
| [`storage_pressure`](#storage_pressure) | P1 | no | live |
| [`queue_caps`](#queue_caps) | P1 | no | live |
| [`signer_loss`](#signer_loss) | P1 | no | live |
| [`backup_age`](#backup_age) | P1 | no | live |
| [`push_no_transfer_code_streak`](#push_no_transfer_code_streak) | P1 | no | live |

## invariant_breach

- **Severity:** P0
- **Thresholds:** P0 when reading ≥ 1
- **Diagnostic only:** no
- **Feeds:** **unbound — this rule cannot fire today.** input hardcoded 0; no `invariant_breach` metric exists (ZTR-1144)

**Rule.**

> INVARIANT_BREACH classification; P0 (lease uniqueness / missing exact bytes after signer use)

**Required posture.**

> Stop money engines, quarantine affected wallets, preserve evidence, operator escalation.

## duplicate_submit_attempt

- **Severity:** P0
- **Thresholds:** P0 when reading ≥ 1
- **Diagnostic only:** no
- **Feeds:** **unbound — this rule cannot fire today.** input hardcoded 0; no metric at the uniqueness-rejection site (ZTR-1144)

**Rule.**

> Single-use submit_decision_id; the database prevents reuse. P0 (possible duplicate submit/sign over changed bytes)

**Required posture.**

> Stop money engines, quarantine affected wallets, preserve evidence, operator escalation. Alert on submit_decision_id uniqueness-constraint rejection only — never on raw retry count.

## lease_age

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 300000
- **Diagnostic only:** yes — this signal must never drive an automatic lease release or money-state change
- **Feeds:** live — `gn_oldest_lease_age_seconds`, suppressed while `gn_database_truth_available` is 0

**Rule.**

> Lease age alert over active and pinned leases; axiom 5 — heartbeat expiry is not release

**Required posture.**

> Diagnostic only: page operator on stale heartbeat_at. Never automatic lease release. Escalates to P0 only when combined with an invariant-breach classification (separate signal).

## path_gap

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 1
- **Diagnostic only:** no
- **Feeds:** **unbound — this rule cannot fire today.** input hardcoded 0 (ZTR-1144)

**Rule.**

> INDETERMINATE on gap; P1 (persistent lineage gap)

**Required posture.**

> Stop affected wallet/operation, keep other isolated lanes operating if invariants hold, operator escalation.

## regression

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 1
- **Diagnostic only:** no
- **Feeds:** **unbound — this rule cannot fire today.** input hardcoded 0; `gn_observation_anomalies_total{kind}` is emitted but unconsumed (ZTR-1144)

**Rule.**

> REGRESSION row; P1 (regression observation)

**Required posture.**

> Park affected operations; page operator; never release or rebuild.

## endpoint_disagreement

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 1
- **Diagnostic only:** no
- **Feeds:** **unbound — this rule cannot fire today.** input hardcoded 0 (ZTR-1144)

**Rule.**

> Cross-endpoint disagreement fails closed; P1 (proof barrier mismatch)

**Required posture.**

> Fail closed for money decisions until the configured authority policy resolves disagreement; operator escalation. Switching gateways starts a new observation stream and does not erase disagreement.

## storage_pressure

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 0.9; P0 when reading ≥ 0.95
- **Diagnostic only:** no
- **Feeds:** live — `gn_storage_pressure` — a 0/1 band flag, not a utilization fraction

**Rule.**

> Permanent retention of canonical containers; P1, escalating to P0 when exhaustion threatens evidence retention (storage bounds)

**Required posture.**

> P1 on approach to configured storage bounds; P0 when critical/exhaustion band threatens evidence retention. Refuse new evidence at pressure; halt operations at critical (storage-backpressure).

## queue_caps

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 0.9
- **Diagnostic only:** no
- **Feeds:** live — queue depth, pool-cap utilization and pinned ratio; the 503 rate input is hardcoded 0 (ZTR-1144)

**Rule.**

> RECEIVE_QUEUE_CAP overflow → 503 create-nothing; minting stops at POOL_CAP_TOTAL. P1 (pinned-cap exhaustion)

**Required posture.**

> Stop affected admission/mint path; keep other isolated lanes operating if invariants hold; operator escalation. Alert on sustained cap utilization and on 503 receive_queue_full rate.

## signer_loss

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 1; P0 when reading ≥ 2
- **Diagnostic only:** no
- **Feeds:** live — `gn_signer_leadership_held`; the ambiguity input that raises P0 is hardcoded 0 (ZTR-1144)

**Rule.**

> Signer unavailable; readiness false. P0 when in-flight signing outcome is ambiguous

**Required posture.**

> P1 readiness-degraded when leadership is lost or cannot be re-acquired. P0 if loss coincides with an in-flight signing attempt whose outcome is ambiguous. Unsigned ops stay in existing public state; no alternate instance signs without leadership.

## backup_age

- **Severity:** P1
- **Thresholds:** none by default — supplied at construction (source: `operator-backup-cadence`)
- **Diagnostic only:** no
- **Feeds:** live — `gn_backup_last_success_age_seconds`, suppressed while `gn_backup_last_success_available` is 0; threshold only exists when `backupMaxAgeMs` is passed

**Rule.**

> Key rotation and backup; the threshold value comes from the injected backup cadence (not invented here)

**Required posture.**

> Operator escalation; renew backup before retention/recovery risk. Threshold ms is injected by the caller — never hard-coded independently in this module.

## push_no_transfer_code_streak

- **Severity:** P1
- **Thresholds:** P1 when reading ≥ 20
- **Diagnostic only:** no
- **Feeds:** live — `gn_push_no_transfer_code_streak` process-local gauge; in-process SAFETY_ALERT_SIGNALS fire on threshold via composePush + custodyAlertEvaluator

**Rule.**

> ZTR-1154 — consecutive no_transfer_code push receives with no intervening enqueued (delivered-envelope shape-break detector). Default threshold DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD (20)

**Required posture.**

> Page operator. Compare a freshly decrypted live cleartext against goldens/push/delivered-envelope.data.v1; if the nest moved, update payload.ts precedence and refresh the golden in the same reviewed commit. Do not change the 204 discard response. Do not treat silence of other signals as an all-clear on the push channel.

## Invariants asserted by the source module

- `LEASE_AGE_AUTOMATIC_RELEASE` = `false` — a lease heartbeat expiring is not a lease release.
- `BACKUP_AGE_THRESHOLD_SOURCE` = `operator-backup-cadence` — the backup-age number comes from the configured cadence and is never invented locally.
- Every notification carries `automaticRelease: false`, so no sink can promote a fire into a release.
- A non-finite reading fails closed: it is treated as crossing the threshold.
