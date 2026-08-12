# Auto-approved external sends

How this node can auto-approve `SEND_EXTERNAL` for trusted integrations, how to
set that up, how to watch spend against caps, and how to stop it in a hurry.

Fail-closed is the design: missing, unreadable, invalid, or disabled policy
means **no** machine approvals. Manual approval still works. The money worker
never invents a rule.

Related code surfaces (for operators who read source):

| Surface | Where |
| --- | --- |
| Policy document (`ops.auto_approve_sends`) | Admin **Auto-approve** page · `GET/POST /admin/v1/auto-approve-policy` |
| Worker step | Money worker tick: auto-approve pending sends, then form approved sends |
| Route 2 intake | `POST /v1/integration-requests` + claim poll `GET /v1/integration-requests/:id` |
| Route 2 operator decide | Admin integrations inbox · `POST /admin/v1/integration-requests/:id/approve` |
| Route 1 operator setup | Admin implementers + API keys + auto-approve policy |
| Audit action | `send.auto_approved` (`actor_kind = SYSTEM`) |
| Approval method | `AUTO_POLICY` on `operation_approvals` |

## What auto-approval is

An enabled policy document holds one or more **rules**. Each rule binds one
implementer id to:

- `per_send_max_zkz` / optional `per_send_min_zkz`
- `window_hours` + `window_cap_zkz` (trailing window spend)
- optional `expires_at`, and per-rule `enabled`

On each money-worker tick, CREATED / approval-pending external sends are
evaluated. A match commits in one transaction:

1. Implementer-scoped advisory lock (serialises window spend)
2. `AUTO_POLICY` approval row
3. CREATED → APPROVED status CAS
4. SYSTEM audit row (`send.auto_approved`)

Formation then runs like any other approved send: the node forms and signs the
transfer material and parks the operation at `AWAITING_REDEMPTION` with a
deliverable transfer code. **The node never submits the external send to the
chain.** Redemption is off-node; completion monitoring only observes.

Anything that does not match (no rule, over max, under min, window full, rule
disabled, document disabled, halt engaged, money path not admitted) **falls
through silently** and stays on the manual approval queue.

## Fail-closed posture

| Policy state | Effect |
| --- | --- |
| Setting key absent | Disabled (`absent`) — no auto-approvals |
| Unreadable / DB error on read | Disabled (`unreadable`) |
| Invalid JSON / structure | Disabled (`invalid`) — refuse to guess |
| `enabled: false` | Disabled (`off`) — rules retained for edit |
| Enabled, no rule for implementer | Fall-through (manual queue) |
| Enabled, rule match | Auto-approve under caps |

There is no "best effort" parse. Corrupt documents do not partially apply.

## Setting up an integration

### Route 2 — platform requests, operator decides

1. Platform `POST /v1/integration-requests` with `display_name`,
   `requested_scopes` (subset of `send:create`, `send:read`), and a
   `proposed_rule` (amounts and window — **no** implementer id yet).
2. Response returns `request_id` + one-time `claim_token` (`irq_…`). The raw
   claim token is never stored; only its hash is durable.
3. Operator opens the integrations inbox, reviews the proposal, and approves
   with a **final** rule. Operator values bind: you may tighten caps relative to
   the proposal (common: platform asks for `100` / 288h; you approve `50`).
4. Approval creates the implementer, merges the rule into the auto-approve
   policy document, and CAS-moves the request PENDING → APPROVED.
5. Platform polls `GET /v1/integration-requests/:id` with the claim token.
   First successful claim returns the implementer API key (`ik_…`) **once** and
   moves the row to CLAIMED. Subsequent polls return status only.
6. Platform `POST /v1/external-sends` with that bearer key within the approved
   caps. The worker auto-approves and forms; the platform reads the transfer
   code when the operation reaches `AWAITING_REDEMPTION`.

### Route 1 — operator creates everything

1. Admin: create implementer (`POST /admin/v1/implementers`).
2. Admin: issue API key with `send:create` / `send:read`
   (`POST /admin/v1/api-keys`) — raw key shown once.
3. Admin: Auto-approve page — add a rule for that implementer id, set caps,
   enable the document, save (fresh TOTP).
4. Hand the key to the integration; same send path as Route 2 from there.

## Reading spend vs cap

On the Auto-approve policy page, each rule shows trailing-window spend against
`window_cap_zkz`. Spend is the sum of amounts on `AUTO_POLICY` approvals for
that implementer inside `window_hours`.

**Spend is never released early.** An auto-approved send that later expires or
needs attention still consumes window cap until the trailing window slides past
its approval time. Do not expect "failed delivery" to free budget.

## Three stop levers (fastest first)

Use the first lever that matches the blast radius you need.

### 1. Operator halt (immediate)

Engage operator halt so `SEND_EXTERNAL` is refused by the money-path gate.
The auto-approve worker step checks halt per candidate and leaves rows CREATED.
Disengage when ready; parked sends auto-approve on later ticks if policy still
admits them.

- Admin halt control · `POST /admin/v1/halt` with `engaged: true`
- Fastest whole-node brake for external sends (and other halted kinds)

### 2. Disable policy or a single rule

On the Auto-approve page:

- Set document `enabled: false` to stop **all** auto-approvals while keeping
  rules for later edit, or
- Disable one rule (`enabled: false` on that rule) to stop one implementer.

Save with fresh TOTP. Effect is on the next worker tick (no restart).

### 3. Revoke the integration credential

`POST /admin/v1/api-keys/:id/revoke` (TOTP). New creates with that key fail
auth. In-flight CREATED sends for that implementer still sit on the manual
queue unless you also disable the rule or engage halt — revoke alone does not
CAS-reject existing operations.

## How to audit history

| Evidence | Where |
| --- | --- |
| Machine approval | `operation_approvals.method = 'AUTO_POLICY'` for the operation id |
| System audit | `audit_log.action = 'send.auto_approved'`, `actor_kind = 'SYSTEM'`, `actor_id` like `auto_policy:<rule_id>` |
| Policy edits | `audit_log.action = 'ops.auto_approve_sends_changed'`, `actor_kind = 'OPERATOR_SESSION'` |
| Route 2 decisions | `integration_request.approved` / `.declined` audit rows |
| Credential lifecycle | `IMPLEMENTER_CREDENTIAL_ISSUED` / `…_REVOKED` |

Admin operation detail and the policy page surface the live document; durable
truth is always the tables above.

## Wallet-pool guidance (one unsettled send per source wallet)

The schema enforces **at most one unsettled external send per source wallet**
(partial unique index). A second create against a wallet already held by
CREATED / APPROVED / AWAITING_REDEMPTION / NEEDS_ATTENTION is refused with
`wallet_in_flight`.

This is intentional, not a defect. High-cadence integrations must spread creates
across a **wallet pool** large enough for their concurrency, and only reuse a
wallet after the prior send has fully settled (or been terminal-rejected).
Size the pool from peak concurrent unsettled sends, not from daily volume.

## Monitoring checklist

- Policy page: enabled flag, per-rule spend vs cap, rule expiry
- Manual approval inbox growth while policy is enabled → often over-cap or halt
- Halt engaged unexpectedly → no auto-approvals until disengage
- `send.auto_approved` rate vs create rate (gap implies fall-through)
- Credential revoke / implementer retire for off-boarded integrations
- Transfer codes only after `AWAITING_REDEMPTION`; create-time responses keep
  `transfer_code` null by design

## Emergency stop runbook (short)

1. Engage halt.
2. Disable auto-approve document (or the single bad rule).
3. Revoke the integration's API key.
4. Confirm new creates stop and pending auto-approvals stay CREATED.
5. Triage any CREATED rows on the manual queue; reject or approve deliberately.
6. Disengage halt only after policy and credentials are in the state you want.

## Related

- [`README.md`](README.md) — operating model and document index
- [`incidents.md`](incidents.md) — alert-driven response
- [`attention-triage.md`](attention-triage.md) — `needs_attention` reasons
- Full-suite / CI expectations: [`full-suite-test-runs.md`](full-suite-test-runs.md)
- E2E drill (developers): `apps/generic-node/test/auto-approve-e2e-drill.pg.test.ts`
