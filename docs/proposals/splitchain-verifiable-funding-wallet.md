# SplitChain-verifiable funding wallet for generic-node campaigns

**Status:** Accepted design (v1) — 2026-08-14  
**Trackers:** ZTR-1286 (node epic) · ZUK-2145 (Zukaz epic)  
**Related:** omit-source cutover (ZTR-1266 / ZUK-2131), money capabilities

## Goal

A Zucoins campaign cannot go live unless Zukaz can **independently verify on SplitChain** that a known public wallet holds enough ZKZ to honour it.

After go-live, Zukaz keeps verifying that wallet:

- before every collect (fast path for that reward),
- on a background cadence (e.g. hourly) for whole-campaign remaining liability.

If the wallet can no longer cover remaining inventory, **soft-shrink** what is still collectable and notify the business — do **not** rewrite history of what was already collected, and do **not** punish the merchant when balance fell only because legitimate collects moved coins out.

**Send path stays node-owned: omit-source.** The funding wallet is a reserve / proof address, not necessarily the key that signs the hunter transfer.

## Shared vocabulary

| Term | Meaning |
|------|---------|
| **Funding wallet** | One SplitChain pubkey the node exposes for an integration. Zukaz only balance-checks this key on-chain. |
| **Sender / worker wallet** | Node-internal hot wallet that forms the external send to the hunter. May be topped up from the funding wallet at collect time. |
| **Original campaign budget** | What the merchant published (e.g. 100 ZKZ). Immutable audit/marketing figure (or only changed by explicit merchant edit). |
| **Remaining offerable liability** | Sum of rewards still on active, uncollected drops (+ unsettled in-flight claims still owed). This is what funding must cover. |
| **Paid / collected** | Already collected amounts. Left remaining liability; must not be “taken back” when we shrink. |
| **Soft shrink** | Deactivate or reduce remaining drops so remaining liability ≤ what the funding wallet can still cover (after other commitments on the same wallet). Notify Biz. Partial inventory may remain live. |

## Liability math (critical)

For funding wallet `W` and merchant campaigns funded from `W`:

```
on_chain(W)     = SplitChain getWalletBalance(W)   // independent; source of truth for Zukaz gates

other_commit(W) = remaining offerable + unsettled claims
                  for OTHER live campaigns on W
                  (v1: Zukaz-only; non-Zukaz reserve not modelled)

available(W, C) = on_chain(W) - other_commit(W)

remaining(C)    = sum(hidden_reward on C's active drops)
                + unsettled claims for C still owed

// Publish new campaign C with budget B:
allow publish iff available(W, C) >= B

// Pre-collect reward amount A on C:
allow collect dispatch iff available(W, C) >= A  (and drop still active)

// Background / post-drain reconcile for C:
if remaining(C) > available(W, C):
  shrink remaining(C) down to available(W, C)
  // never reduce below what's already collected
  // never treat "balance dropped because we paid collects" as a shrink
  //   if remaining and on_chain moved together correctly
```

### Collects vs external drain

| Event | on_chain(W) | remaining(C) | Action |
|-------|-------------|--------------|--------|
| Hunter collects 1 ZKZ; node pays from W (via sender) | −1 (when paid) | −1 | In balance — no shrink |
| Merchant withdraws 3 ZKZ from W off-platform | −3 | unchanged | Soft shrink remaining by 3 (or deactivate drops) + notify |
| W has 4; remaining active rewards sum to 5 | 4 | 5 | Shrink remaining to 4 + notify |

Biz messaging: **“Adjusted campaign total to X”** means *remaining still available to collect*, not “this campaign was never 100.” UI should show:

- Original budget: 100 ZKZ  
- Collected: 12 ZKZ  
- Remaining offerable: 4 ZKZ (adjusted — funding wallet low)  
- Funding wallet balance (snapshot): …

## Payout flow (agreed shape)

```
Merchant tops up Funding wallet W (integrations may share W)

Publish: Zukaz verifies on_chain(W) covers new budget + other commits

Collect 1 ZKZ:
  1. Zukaz: SplitChain check W can cover this 1 ZKZ (+ commits)
  2. Zukaz: create claim, POST external-send (no source_wallet_id)
  3. Node: ensure a sender has 1 ZKZ (internal: W → sender if needed)
  4. Node: sender → hunter (transfer code / external send)
  5. Hunter redeems
```

Zukaz never needs the sender’s private key. Zukaz may record `source_wallet_id` for attribution only.

---

## Part 1 — Node

### 1.1 Funding wallet as first-class integration setting

When an operator attaches an integration, choose funding wallet:

| Option | Behaviour |
|--------|-----------|
| Use shared default funding wallet | Node-level default; integration points at it |
| Select existing wallet | Any node-managed wallet the operator may use as reserve |
| Create new wallet | Fresh wallet marked as this integration’s funding wallet |

Requirements:

- Stable public key (SplitChain-verifiable) + stable node wallet id  
- Integration stores `funding_wallet_id` + resolvable `funding_wallet_public_key`  
- **Not** the same field as forced send/source wallet — sends stay worker-pool / omit-source  
- Optional later: wallet purpose `integration_funding` vs `worker`

### 1.2 API surface

**A. Report funding wallet on identity / registration**

Expose on `GET /.well-known/zupay-node` and/or implementer “who am I” / integration endpoint:

```json
{
  "funding_wallet_id": "uuid",
  "funding_wallet_public_key": "<base64url ed25519>"
}
```

Zukaz stores the public key and uses SplitChain directly. Node id is ops/debug.

**B. Optional:** `GET /v1/funding/availability?integration_id=…` — node view of free liquidity. **Not** a substitute for chain; Zukaz must not trust this alone.

**C. External send (collect path)** — omit-source unchanged:

1. Resolve integration → funding wallet W  
2. Before form/approve amount A: ensure economic cover from W (prefer W → sender hop, then send)  
3. Assign sender/worker as today  
4. Return `source_wallet_id` of **sender** (attribution), not necessarily W  
5. Fail with stable code e.g. `INSUFFICIENT_FUNDING_WALLET` if W cannot fund A  

**D. Operator docs / UI copy** — funding vs workers; drain shrinks Zukaz inventory.

### 1.3 Multi-integration sharing one wallet

Allowed. Node does not partition chain balance per integration on-chain. Each integrator accounts for its own commitments.

**v1:** Document oversubscribe risk; recommend dedicated funding wallet per high-value integration.  
**v2 (later):** Node reserved amounts per integration against W + residual free balance; still backstop with chain total.

### 1.4 Node does not

- Implement Zukaz campaign objects or drop deactivation  
- Require Zukaz to pass `source_wallet_id` on create-send  
- Replace SplitChain as balance oracle for Zukaz gates  

### 1.5 Node acceptance criteria

1. Operator can set funding wallet per integration: shared default / existing / create new  
2. Implementer API (or well-known) returns funding wallet public key  
3. External send can fund from that wallet via internal hop to sender, then recipient  
4. Insufficient funding → clear, idempotent-safe error  
5. Docs: funding vs worker; shared-wallet oversubscribe risk  

### Node ticket split

| Ticket | Scope |
|--------|--------|
| ZTR-1286 | **Epic** — SplitChain-verifiable funding wallet (node) |
| ZTR-1287 | Schema + admin: funding wallet on integration (default / existing / create) |
| ZTR-1288 | Expose funding pubkey on discovery / implementer identity |
| ZTR-1289 | External-send: W → sender hop + `INSUFFICIENT_FUNDING_WALLET` |
| ZTR-1290 | Ops docs + admin copy; multi-integration shared-wallet risk (v1) |

Optional later (not v1): node-side availability endpoint; wallet purpose enum; v2 reservation ledger.

---

## Part 2 — Zukaz

### 2.1 Data model

`treasury_webhooks` (generic_node):

| Field | Change |
|-------|--------|
| `treasury_wallet_public_key` | Required for healthy generic_node once this ships (funding pin). Reuse column; not “legacy diagnostic only.” |
| `funding_wallet_id` (optional new) | Node wallet id for support/debug |
| `source_wallet_id` | Remains legacy/optional; not happy-path sends |

Registration: probe node → funding pubkey → persist. Missing/invalid → incomplete/unhealthy; cannot publish Zucoins.

Campaigns: keep original budget immutable on soft-shrink; remaining offerable from active drops; snapshots; optional `reward_funding_status` / audit fields. Do **not** lower original total when shrinking.

### 2.2–2.5 Gates and shrink

- **Publish:** reverse ZUK-2132 skip for generic_node funding checks (keep omit-source for sends). Fail closed `TREASURY_UNDERFUNDED` if chain balance &lt; budget + other commits.  
- **Pre-collect:** balance gate before claim success / enqueue send; order: lock drop → reward A → balance(W) → insert claim → enqueue.  
- **Background:** hourly `treasury-funding-reconcile`; soft-shrink; multi-campaign fair share v1 (document: newest-first or largest-remaining-first).  
- **UI truth:** original / collected / remaining / snapshot; notify on adjustment with debounce.  

### 2.6–2.8 Biz + wrong-key + notify

- Biz: show funding pubkey, snapshot, test-connection includes funding present  
- Never COALESCE to merchant app wallet for generic_node  
- Notify: funding_adjusted copy; debounce  

### 2.9 Zukaz acceptance criteria

1. Cannot publish without funding pubkey + SplitChain balance ≥ budget + other Zukaz commits  
2. Pre-collect rejects when pin can’t cover that reward  
3. Hourly soft-shrink; original + collected coherent in UI  
4. Legitimate collects in step with remaining do not false-destroy campaign  
5. No send-wallet pin; create-send remains omit-source  
6. Merchant notified on remaining adjustment  
7. Tests: publish gate, multi-campaign commit, pre-collect fail-closed, soft-shrink math, collect doesn’t false-shrink, wrong-key never used  

### Zukaz ticket split

| Ticket | Scope |
|--------|--------|
| ZUK-2145 | **Epic** — SplitChain-verifiable funding wallet (Zukaz) |
| ZUK-2146 | (A) Persist funding pubkey from node; registration/health; Biz display |
| ZUK-2147 | (B) Publish funding gate for generic_node (un-skip balance path) |
| ZUK-2148 | (C) Pre-collect SplitChain gate + correct funding key only |
| ZUK-2149 | (D) Soft-shrink reconcile + multi-campaign `available()` + notify copy |
| ZUK-2150 | (E) Hourly funding reconcile job |
| ZUK-2151 | (F) Biz campaign UI: original vs remaining vs snapshot; runbook |

---

## Sequencing

1. **Node:** funding wallet on integration + expose pubkey + send funds from W via sender  
2. **Zukaz:** store pubkey + publish gate ← first “can’t go live without coins”  
3. **Zukaz:** pre-collect gate ← stop new collects when dry  
4. **Zukaz:** soft-shrink + notify + hourly job ← stay honest after go-live  
5. **Polish:** Biz UI, runbooks, multi-integration docs  

Do **not** ship publish-as-funded without (1)+(2). Pre-collect without publish gate still allows over-promise at create time.

## Explicit non-goals (v1)

- SplitChain smart-contract escrow / hard lock  
- Zukaz choosing or pinning send wallet ids  
- Perfect cross-integrator reservation on a shared funding wallet  
- Changing hunter redeem UX beyond clearer “reward unavailable” if funding fails at collect  

## Decision summary

| Question | Answer |
|----------|--------|
| Verify coins on SplitChain? | Yes — balance of declared funding pubkey |
| Pin = send wallet? | No — pin = funding/reserve; node may hop pin → sender → hunter |
| Who picks the wallet? | Node operator per integration (shared / existing / new) |
| Check when? | Publish + every collect + ~hourly background |
| Underfunded behaviour | Soft-shrink remaining offerable; keep original budget & collected; notify Biz |
| Trust node balance API alone? | No |
