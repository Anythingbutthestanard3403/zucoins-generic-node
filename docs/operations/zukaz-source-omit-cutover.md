# Zukaz / implementer cutover — stop supplying source wallet

Track completion of the integration-side cutover for optional
`source_wallet_id` on `POST /v1/external-sends` (node: ZTR-1271; cutover:
ZTR-1272). Application code for Zukaz lives in the Zukaz repo; this checklist
is the written operator / implementer contract. Link any external ticket from
Linear ZTR-1272 when opened.

**Product outcome must stay unchanged:** create send → awaiting redemption /
transfer code → recipient redeems. The node still **never chain-submits SEND**.

## Preconditions (node)

- [ ] Node release includes optional `source_wallet_id` (ZTR-1271 merged)
- [ ] Assign + multi-hub top-up composition live (ZTR-1270)
- [ ] Wallet money modes available on admin (internal-only hubs + send-capable workers)
- [ ] Auto-approve policy (if used) still configured per
      [`auto-approve-external-sends.md`](auto-approve-external-sends.md)

## Operator topology (before flipping clients)

- [ ] ≥1 wallet set to **internal-only** hub; funded for peak top-up demand
- [ ] ≥1 wallet set to **send-capable** worker (send-only or full)
- [ ] Worker pool sized for peak **concurrent unsettled** external sends
- [ ] Confirm internal-only wallets never appear as SEND sources in a dry-run
- [ ] Confirm new creates can omit `source_wallet_id` and still return a resolved
      `source_wallet_id` on the response

## Config keys / fields to remove (Zukaz and similar)

Delete any required configuration that pins a node send wallet. Names vary by
deployment; treat the following as the search set and remove **all** matches
that feed `POST /v1/external-sends` bodies or “send wallet” setup wizards:

| Kind | Keys / fields to purge (search these literals) |
| --- | --- |
| Env | `SOURCE_WALLET_ID`, `SEND_SOURCE_WALLET_ID`, `EXTERNAL_SEND_SOURCE_WALLET_ID`, `NODE_SOURCE_WALLET_ID`, `ZUKAZ_SOURCE_WALLET_ID`, `ZUKAZ_SEND_WALLET_ID`, `HOT_WALLET_ID`, and any `*_WALLET_ID` that names a node send source (including legacy product-projection names) |
| Nested env / secrets | `NODE_SEND_SOURCE_WALLET`, `GENERIC_NODE_SOURCE_WALLET_ID`, `ZU_NODE_SOURCE_WALLET_ID` |
| App config / JSON | `sourceWalletId`, `source_wallet_id`, `sendSourceWalletId`, `externalSend.sourceWalletId`, `node.sourceWalletId`, `wallets.sendSource` |
| Ops runbooks / Helm | values that inject the above into Zukaz pods or SSM/Parameter Store |
| Onboarding UI | any required “node wallet id” / “send wallet” field shown to operators |

Keep (do **not** remove):

- Node base URL / discovery pin
- Implementer API key (`ik_…`) and scopes `send:create` / `send:read`
- Auto-approve is **node-side** policy — not a Zukaz wallet id
- Destination address and amount fields on each create

## API client changes

- [ ] Request type: `source_wallet_id` optional or removed from required fields
- [ ] Default create path builds body with only `destination_address`, `amount_zkz`,
      and optional `client_reference` / `description` / `references_operation_id`
- [ ] Always send a stable `Idempotency-Key`
- [ ] Read resolved `source_wallet_id` from the **response** (and later GET) for
      logs/support — do not require it in local config
- [ ] If a legacy code path still passes explicit source, gate it behind an
      explicit “legacy” flag and plan removal; do not document it as the happy path
- [ ] Refresh OpenAPI / `@zucoins/generic-node-consumer` types to the node release
      that made source optional

### Preferred request shape

```json
{
  "destination_address": "<recipient public key>",
  "amount_zkz": "10.00000000"
}
```

### Legacy request shape (transition only)

```json
{
  "source_wallet_id": "<send-capable wallet uuid>",
  "destination_address": "<recipient public key>",
  "amount_zkz": "10.00000000"
}
```

Omitting source vs passing source are different idempotency fingerprints.

## QA

- [ ] Create omit-source send under auto-approve (or manual approve) → status reaches
      `AWAITING_REDEMPTION` with non-null transfer code
- [ ] Recipient redeem path unchanged
- [ ] Response `source_wallet_id` is a send-capable worker (never internal-only)
- [ ] Concurrent creates succeed up to worker-pool size; excess get clear backpressure
      (busy / no worker) rather than silently pinning one hot wallet
- [ ] Legacy explicit source still works once during soak, then disabled in staging
- [ ] Explicit internal-only source is refused
- [ ] Confirm no UI/copy claims the node chain-submits SEND

## Support runbook delta

| Question | Answer after cutover |
| --- | --- |
| Which wallet sent? | Node `GET /v1/external-sends/:operation_id` (or admin operation detail) → `source_wallet_id` |
| Where is “the send wallet id” configured in the product? | It is not. Ops set wallet **modes** (hub vs worker) and fund hubs on the node admin dashboard |
| Send stuck / wallet busy? | One unsettled send per source wallet; size worker pool; see auto-approve wallet-pool guidance |
| Did the node broadcast? | No. Node forms and signs; recipient redeems off-node; completion only observes |

## Rollout sequence

1. Node deploy with ZTR-1270 + ZTR-1271 behaviour
2. Operator hub/worker modes + funding
3. Staging Zukaz: remove keys, ship omit-source client, QA checklist
4. Production Zukaz: remove keys, deploy client
5. After soak: delete legacy explicit-source code paths in Zukaz
6. Optional later: node metric/log when explicit source is still used (cutover signal)

## Owners

| Workstream | Owner | Status |
| --- | --- | --- |
| Node docs (this repo) | generic-node implementer (ZTR-1272) | this PR |
| Node wallet modes + funding | node operator | |
| Zukaz env/config purge | Zukaz implementer | |
| Zukaz API client types/calls | Zukaz implementer | |
| QA omit-source path | Zukaz + node ops | |
| Support runbook publish | support / ops | |

## Related

- [`auto-approve-external-sends.md`](auto-approve-external-sends.md) — omit-source default, auto-approve E2E, wallet pool
- Pack P external-send guide (admin kit generator) — implementer-facing copy
- Linear: ZTR-1272 (this checklist), ZTR-1271 (API), ZTR-1266 (epic)
