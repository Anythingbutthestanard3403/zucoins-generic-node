<!-- GENERATED FILE — do not edit by hand.
     Source: packages/node-core/src/operator/safety-alerts.ts
     Regenerate: node scripts/gen-operator-alert-docs.mjs
     Gate: apps/generic-node/test/operator-docs.census.test.ts -->

# Escalation matrix

Severity → who → how. The severity ladder, the channel routing and the posture text are
rendered from `packages/node-core/src/operator/safety-alerts.ts`; the roles are fixed by
this repository, and the humans behind them belong in your deployment's on-call record.

Channels widen monotonically: a higher severity never drops a channel a lower one uses
(`validateEscalationPath` refuses a configuration that narrows).

## Severity → role

| Severity | Role reached | What that role is expected to do |
| --- | --- | --- |
| P0 | Custody escalation | Authorized to stop money engines and quarantine wallets. Reached immediately, day or night. Cannot be the same person who is mid-incident on the node unless the deployment runs single-operator. |
| P1 | Primary operator | Holds the admin session, TOTP device and enrolled device key. Works the incident runbook; escalates to custody escalation on any P0 trigger. |
| P2 | Primary operator (next business day) | Reviews the log channel. No paging obligation. |

## Severity → channels → signals

| Severity | Channels | Signals that reach this severity |
| --- | --- | --- |
| P0 | `log`, `webhook` | `duplicate_submit_attempt`, `invariant_breach`, `signer_loss`, `storage_pressure` |
| P1 | `log`, `webhook` | `attention_backlog`, `backup_age`, `endpoint_disagreement`, `gateway_read_failure`, `lease_age`, `path_gap`, `push_no_transfer_code_streak`, `queue_caps`, `queue_oldest_age`, `regression`, `signer_loss`, `storage_pressure` |
| P2 | `log` | — |

## P0 signals and their required posture

These are the only signals that reach custody escalation. Each posture below is the
verbatim `posture` field of its rule.

### `invariant_breach`

`gn_invariant_breach_total` from applyMoveInvariantBreachQuarantine / receive-expiry breach sites

> Stop money engines, quarantine affected wallets, preserve evidence, operator escalation.

### `duplicate_submit_attempt`

`gn_duplicate_submit_rejection_total` on submit_decisions mint loser (move + receive claim paths)

> Stop money engines, quarantine affected wallets, preserve evidence, operator escalation. Alert on submit_decision_id uniqueness-constraint rejection only — never on raw retry count.

### `storage_pressure`

`gn_storage_pressure` — a 0/1 band flag, not a utilization fraction

> P1 on approach to configured storage bounds; P0 when critical/exhaustion band threatens evidence retention. Refuse new evidence at pressure; halt operations at critical (storage-backpressure).

### `signer_loss`

`gn_signer_leadership_held` + `gn_signer_in_flight_ambiguous` (raises P0 when both)

> P1 readiness-degraded when leadership is lost or cannot be re-acquired. P0 if loss coincides with an in-flight signing attempt whose outcome is ambiguous. Unsigned ops stay in existing public state; no alternate instance signs without leadership.

## Delivery

| Channel | Meaning |
| --- | --- |
| `log` | Written to the node's stdout logger. Always available. |
| `webhook` | Configured `AlertChannel` of kind `webhook`. |

**Nothing pages today.** The composition root registers a `log` channel only, and no
webhook URL is configurable — so every P1/P0 above is delivered to stdout and to nobody
else. Configure OPERATOR_ALERT_WEBHOOK_URL (https, no credentials) for P1/P0 paging; absent keeps log-only
the metrics endpoint with the rules in
[`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml), not on this escalation
path.
