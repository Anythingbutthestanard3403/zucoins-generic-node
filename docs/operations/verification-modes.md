# Verification modes (INDEPENDENT / NODE_VERIFIED)

Per-operation custody close path. Admission freezes `operations.verification_mode`
at create time. The mode is **metadata only** — it does not invent new operation
statuses or durable events. It chooses *who* may release the wallet lease after
landing proof.

Related surfaces:

| Surface | Where |
| --- | --- |
| Policy document (`ops.allow_node_verified`) | Admin **Node-verified policy** page · `GET/POST /admin/v1/allow-node-verified-policy` |
| Discovery / identity | `verification_mode` on `GET /.well-known/zupay-node` and `GET /v1/implementer/identity` (always emitted; currently `INDEPENDENT`) |
| Create body field | `verification_mode` on receive / move / send create (omit → `INDEPENDENT`) |
| Transfer-code path | NODE_VERIFIED auto-releases code at ready (ZTR-1302); INDEPENDENT still arms |
| Lease release stamp | `RELEASED_NODE_VERIFIED` on landing when mode is NODE_VERIFIED (ZTR-1303/1304) |
| Audit action | `ops.allow_node_verified_changed` |
| Operator badge | Operation detail + needs-attention rows |

Companion automated matrix: `packages/node-core/test/verification-mode-e2e.matrix.test.ts`
plus landing-release PG proofs under receive/move/send.

## Modes

### INDEPENDENT (default)

Consumer-side verification is required for custody close:

1. Create → ready (transfer code withheld until arm on receive)
2. Consumer arms / obtains material
3. Consumer posts verification-complete (or equivalent path)
4. Lease releases under the independent proof path

Omitted `verification_mode` on create always resolves to INDEPENDENT. No operator
policy is required.

### NODE_VERIFIED

The node's own landing proof closes custody in the same transaction that records
land — **zero consumer-side verification calls** after create:

1. Operator enables `ops.allow_node_verified` for the implementer (fresh TOTP)
2. Implementer creates with `"verification_mode": "NODE_VERIFIED"`
3. Receive: code auto-released at ready; land → lease release + `RELEASED_NODE_VERIFIED`
4. Send / move: land → same-TX lease release + `RELEASED_NODE_VERIFIED`
5. Consumer only polls operation status until terminal

Without policy, create returns **422** `verification_mode_not_allowed` (fail-closed;
never silently downgraded to INDEPENDENT).

## Enablement (ops.allow_node_verified)

Document shape (closed keys):

```json
{
  "enabled": true,
  "implementers": [
    { "implementer_id": "<uuid>", "enabled": true }
  ]
}
```

An implementer is allowed only when the document is `enabled: true` **and** that
implementer's entry exists with `enabled: true`.

| Policy state | Effect |
| --- | --- |
| Setting key absent | Disabled (`absent`) — NODE_VERIFIED refused |
| Unreadable / DB error on read | Disabled (`unreadable`) |
| Invalid JSON / structure | Disabled (`invalid`) — refuse to guess |
| `enabled: false` | Disabled (`off`) — entries retained for edit |
| Enabled, no entry for implementer | NODE_VERIFIED refused for that implementer |
| Enabled, entry `enabled: true` | NODE_VERIFIED admitted |

There is no "best effort" parse. Corrupt documents do not partially apply.
Admission re-reads policy per create (no multi-request cache). After disable +
save, the next create that requests NODE_VERIFIED must 422 immediately.

### Operator SPA steps

1. Admin → **Node-verified policy** (`/verification-mode`)
2. Enable policy, add the integration, toggle allow
3. Save with a **fresh single-use TOTP**
4. Confirm audit row `ops.allow_node_verified_changed`

API keys can never set or widen this policy — operator session only.

## Residual risk (accepted)

NODE_VERIFIED makes the **node's chain view** the custody authority for lease
release. The primary residual is **gateway eclipse**: a compromised or partitioned
gateway could present a false land that the node trusts.

Existing mitigations (not eliminated by this mode — they still apply):

- TLS leaf pinning to the gateway
- Byte recomputation of expected artifacts before land acceptance
- Double head read / confirm-read patterns on observation
- Anomaly quarantine when observation invariants break

Enable NODE_VERIFIED only for implementers whose threat model accepts
single-point-of-trust on the node's gateway-observed chain tip. Prefer INDEPENDENT
when the consumer can run verification-complete.

## Staging drill checklist (NODE_VERIFIED receive)

Honest style: leave boxes unchecked until actually run on staging.

### Preconditions

- [ ] Build containing ZTR-1299–1304 (mode column, admission, transfer code, receive/send/move land release) is deployed
- [ ] Money workers running; leadership held; vault unlocked
- [ ] Gateway OBSERVE live (`SPLITCHAIN_GATEWAY_URLS`)
- [ ] Operator admin session; lab implementer API key with receive scope
- [ ] At least one recovery-verified pool wallet eligible for receive

### Drill — NODE_VERIFIED receive, zero consumer verification calls

1. **Enable policy** for the lab implementer (SPA or `POST /admin/v1/allow-node-verified-policy` with fresh TOTP).
2. **Create** `POST /v1/receives` with `"verification_mode": "NODE_VERIFIED"`. Record `operation_id`, wallet, ready code path.
3. **Confirm** ready surfaces the transfer code without a consumer arm call (ZTR-1302).
4. **Pay** the receive on-chain (lab faucet / known pay path). Do **not** call arm or verification-complete from the consumer.
5. **Observe** money worker / lander: status → `RECEIVE_LANDED`; lease gone; release stamp `RELEASED_NODE_VERIFIED`.
6. **Confirm** admin operation detail shows mode badge **Node-verified**.
7. **Negative control:** disable policy (or remove implementer), create again with NODE_VERIFIED → **422** `verification_mode_not_allowed`.

**Pass signals (all required):**

| Check | Expected |
| --- | --- |
| Create with policy | 2xx, `verification_mode=NODE_VERIFIED` |
| Consumer arm / verification-complete | **not called** |
| Operation terminal | `RECEIVE_LANDED` (or kind-equivalent) |
| Lease | absent on receiver wallet |
| Release proof / status | `RELEASED_NODE_VERIFIED` |
| Admin badge | Node-verified |
| Policy off | create 422 |

### Evidence capture

Paste into ZTR-1305 (or PR comment) before moving the ticket:

| Field | Value |
| --- | --- |
| Environment / deploy SHA | |
| `operation_id` | |
| Implementer id | |
| Policy enable audit id / time | |
| Land time (UTC) | |
| `receive_release_status` / proof | |
| Consumer calls after create | none (list any accidental calls) |
| Negative 422 request id | |

**Status:** staging drill **pending** until the table above is filled from a live run.
Credentials for live staging were not assumed available at implementer time; automated
matrix + PG landing proofs cover CI. Operators run this checklist on first staging
promote of the epic.
