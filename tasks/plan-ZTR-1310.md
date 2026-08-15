# ZTR-1310 technical-FAIL remediation plan

**Pinned origin/main:** `be826b9a1d4e18670ab26941be13b5364e626ab0`  
**Pinned PR #166 head:** `bb51881e6f9d73d5c3f988be73fadbb358512de7` (`ztr-1310-dest-idempotency`)  
**Kind:** planning only. Do not implement in this checkout.  
**Trigger:** Review A PASS vs Review B FAIL (technical) — mint-before-reserve. Ticket stays QA Review after this plan is cited.  
**Path:** amend/rebase on PR #166. Do not open a new PR.

## 1. Root cause (mint-before-reserve)

Causal chain:

1. `DestinationService.register` (`packages/node-core/src/api/destination.ts` 259–279) is still:

   ```
   findByIdempotencyKey(node, key)
     → miss
     → keyGenerator.generate(nodeId)     // commits wallet + dest
     → store.insert(record, key)         // first UNIQUE claim of the key
   ```

   The in-memory store honors the key. PR #166 made the live PG store honor it too (`findByIdempotencyKey` SELECT + dest INSERT stamps `idempotency_key`). That only closes the **serial retry after a committed key**.

2. Production `generate` is `createNodeGeneratedWalletKeyGenerator` (`apps/generic-node/src/main.ts` 258–314). It always:

   - `insertNodeGeneratedWalletWithPendingDestination(pool, {walletId, nodeId, publicKey})` — wallet + PENDING dest, **`idempotency_key` NULL**
   - `vault.seal` on a **separate** connection (comment 282–284: seal must see the committed `wallets` FK target)
   - `onWalletMinted` post-commit (ZTR-1307 push)

   Those two INSERTs are autocommit pool queries (`insert-node-generated-wallet.ts` 80–99). The key is not in `INSERT_PENDING_DESTINATION_FOR_WALLET_SQL`.

3. `createSqlDestinationStore.insert` (PR #166) then `INSERT … idempotency_key` / `ON CONFLICT (wallet_id) DO UPDATE … COALESCE(key)`. The partial UNIQUE `destinations_node_idempotency_key_uidx` on `(node_id, idempotency_key) WHERE key IS NOT NULL` is the first time the key is reserved. A 23505 replays the winner row and **does not delete** the caller's already-committed mint.

4. Overlap that Review B named:

   | Interleave | What commits | Retry / loser |
   | --- | --- | --- |
   | Timeout after `generate`, before `insert` | WA + DA (`key` NULL) | Retry mints WB + DB, stamps key on WB. **WA+DA stay NULL-key orphans** (pool leak, dest-on-mint row with no register key). |
   | Two first-uses both miss `find` | WA+DA and WB+DB, both NULL keys | One `insert` wins UNIQUE; loser 23505 replays winner; **loser mint remains**. Service can still return `created` for the winner path only; the orphan is silent. |

5. Existing PG suite (`packages/node-core/test/sql-destination-store.pg.test.ts`) only proves serial replay after a successful keyed insert, plus a raw 23505 on a second dest row. It never overlaps two `generate`s, and its test `generate` inserts a wallet **without** going through dest-on-mint+seal. That is why Review A could PASS and Review B FAIL.

`deleteNodeGeneratedWalletMint` already exists for seal-fail compensation. It is not invoked on 23505, does not delete `vault` (`vault.wallet_id REFERENCES wallets(id)` has no `ON DELETE CASCADE`), and cannot see a timeout after a successful mint.

## 2. Target design

Evaluate only the three candidates Review B listed. Schema UNIQUE stays (see §6).

### Candidate B — txn + delete loser mint

Keep mint-then-claim. On 23505, `deleteNodeGeneratedWalletMint` the loser's wallet/dest (and vault if sealed).

Reject:

- **Timeout overlap is not a 23505.** First attempt commits WA+DA with NULL key and dies before `insert`. There is no loser signal and nothing to delete. Retry still mints WB. This is the Review B sentence “Serial PG retry after a committed key does not cover this.”
- Compensation after a **committed** mint races ZTR-1307 `onWalletMinted` (push already provisioned) and a `vault` row the current delete helper does not remove.
- Treating 23505 as “delete my mint” still allows a window where two AVAILABLE node_generated wallets exist.

B is a cleanup of the concurrent arm only. The FAIL is mint-before-reserve, not missing cleanup.

### Candidate C — insert dest row with key first, then attach wallet

Reserve by writing `destinations` (`id, node_id, key, state='PENDING'`) before any wallet exists, then point `wallet_id` at the later mint.

Reject:

- `destinations.wallet_id` is `NOT NULL UNIQUE REFERENCES wallets(id)` (`custody-eligibility.sql` 62–65). Insert-without-wallet is a schema break.
- Making `wallet_id` nullable (or adding a stub wallet) touches custody insert trigger, bless CAS, list/eligibility, dest-on-mint backfill, and MOVE sink predicates. Ticket forbids bless / retire / MOVE changes.
- A second reservation table would duplicate uniqueness next to `UNIQUE (node_id, idempotency_key)` and invent a ledger the DestinationStore port does not have.

C is dest-first in name only; the FK makes it a product/schema cut.

### Candidate A — reserve key before `generate()` commits a wallet (pick)

The UNIQUE claim must be the **first committed write** of a register. No `wallets` / `destinations` row for this attempt may commit unless that row set already carries the key.

Register-path persist becomes one transaction on a **pinned client**, then seal:

```
findByIdempotencyKey(node, key) → hit? already_registered

materialize ed25519 in memory (no DB)

BEGIN                          -- same client
  INSERT wallets (…)
  INSERT destinations (…, idempotency_key)   -- UNIQUE decides
COMMIT                         -- loser: 23505 → ROLLBACK → no wallet, no dest

vault.seal                     -- separate connection, wallets FK visible
onWalletMinted                 -- post-seal only, unchanged
```

23505 / typed `IdempotencyKeyClaimed` → `findByIdempotencyKey` → `already_registered`. Never leave a committed mint to delete.

How this maps onto today's types:

- `DestinationWalletKeyGenerator.generate` grows an optional second argument `{ idempotencyKey, label }` (or a required register-only overload). In-memory test generators ignore it. Production register generator is the only live caller (`destination-service-for-sql-wiring.test.ts` already freezes one `createNodeGeneratedWalletKeyGenerator(`).
- `insertNodeGeneratedWalletWithPendingDestination` accepts optional `idempotencyKey` and binds it on the dest INSERT. When the key is present, **both** INSERTs run inside a caller-supplied executor that is already in a transaction (do not autocommit them on `pool`).
- Pool scaler / funding CREATE keep calling the helper **without** a key (NULL keys remain valid; partial UNIQUE allows many NULLs). Do not change those call sites' meaning.
- `store.insert` after a keyed generate is adopt-only (`ON CONFLICT (wallet_id)` + `COALESCE` key + PENDING label). Harmless if generate already wrote dest+key+label; keep it so a dest-on-mint leftover can still take a key **only when that dest has no key** — but the register generator must not dest-on-mint without the key, or we reintroduce NULL-key orphans.

`vault.seal` stays **after** COMMIT. Putting seal inside the txn is illegal: seal uses another connection and would block on an uncommitted `wallets` row (today's comment). Do **not** wrap generate+seal in `SERIALIZABLE` + `withSerializationRetry` — seal is not a DB-only body (`CONVENTIONS.md` §1.1 / §2). The accepted mechanism is the existing immediate UNIQUE (`destinations_node_idempotency_key_uidx`).

Crash residual (not Review B, do not expand): process death after COMMIT and before seal leaves **one** reserved dest whose vault row is missing. Retry `find` hits and must not mint again. Same class as today's seal-fail if compensate also crashes. Do not re-seal on `already_registered`.

### Pick: A

Smallest cut that closes both timeout and concurrent overlap. UNIQUE stays the reservation. No dest-without-wallet. No post-commit loser delete.

## 3. File-level change list (amend/rebase PR #166)

Keep as-is (AC still holds; UNIQUE stays):

- `packages/node-core/src/schema/destinations-idempotency-key.sql` — nullable `idempotency_key`, CHECK `^[!-~]{16,255}$`, partial `UNIQUE (node_id, idempotency_key) WHERE idempotency_key IS NOT NULL`
- `packages/node-core/src/schema/destinations-idempotency-key.contract.ts` + census
- `packages/node-core/src/schema/money-schema-pack.ts` append + `migration-integrity` / pack tests / schema-census report
- Bless / retire / `deriveMoveEligibility` / MOVE predicates / `destination_state`

Change:

1. `packages/node-core/src/api/insert-node-generated-wallet.ts`  
   - Dest INSERT binds optional `idempotency_key` (NULL when omitted).  
   - Document: keyed mint MUST run both statements on one txn client. Do not add a second SQL slice.

2. `packages/node-core/src/api/destination.ts`  
   - `generate(nodeId, claim?)`.  
   - `register`: find → generate with `{idempotencyKey, label}` → on typed unique-claim miss, find + `already_registered` (never insert a second mint).  
   - Export a small error type (or reuse a store-level flag) so 23505 is not a generic `service_unavailable`.

3. `packages/node-core/src/api/sql-destination-store.ts`  
   - Keep find-by-key + 23505 replay on `insert`.  
   - Do not treat 23505 as success-without-replay if the winner row is missing (already throws).  
   - No schema change.

4. `apps/generic-node/src/main.ts` `createNodeGeneratedWalletKeyGenerator`  
   - Accept claim key+label from `generate`.  
   - `BEGIN` on a checked-out client → helper(tx, {…, idempotencyKey, label}) → `COMMIT` → `vault.seal` → `onWalletMinted`.  
   - 23505: `ROLLBACK`, throw claim-miss (no `deleteNodeGeneratedWalletMint` needed; nothing committed).  
   - Seal fail: existing dest-then-wallet delete. Do not fire the push hook.  
   - Pool/funding mint sites stay key-less.

5. Tests — see §4.

6. `tasks/ztr-1310-implementer.md` — implementer updates after the code change (not this plan).

Do not touch: blessing authorizer, `destinationServiceForSql` tx rebind (bless/retire only), allocator, backfill, `UNIQUE (wallet_id)`, money-mode PATCH.

Amend/fixup on `ztr-1310-dest-idempotency` at `bb51881`. Rebase onto `origin/main` only if main has moved.

## 4. Test strategy

Keep green: store unit (parameterized INSERT includes key; find SELECT; 23505 replay); in-memory `destination.test.ts` serial idempotency; census / pack / migration-integrity; dest-on-mint production-path census (register still calls the helper).

Must add (real PG unless noted):

| Drill | Pass condition |
| --- | --- |
| **Concurrent overlapping register** | Two `register` (or the production persist function they share) start after both `find`s miss, same `(node_id, key)`, two connections / two psql sessions (`psql-harness` — node-core has no `pg` driver). Outcomes: one `created` and one `already_registered`, **or** both `already_registered` if a third writer won; **same** `destinationId` / `walletId` / `publicKey`. `count(*)` dests with that key = 1. `count(*)` wallets inserted by this drill = 1. Zero dests from this drill with `idempotency_key IS NULL`. |
| **Timeout after keyed persist, before HTTP** | Seed one wallet+dest **with** the key (first attempt committed, client gone). Second `register` does not call persist/`generate`; `already_registered`; wallet count unchanged. |
| **Mint-without-key then claim is not the register path** | Source/unit: register `generate` text / helper call includes `idempotencyKey`. A revert to dest-on-mint then `store.insert` fails this or the concurrent drill (second wallet survives). |
| **23505 rolls back the loser's wallet** | Two open txns both `INSERT` wallet then dest+same key; winner COMMIT; loser 23505 + ROLLBACK; loser's `wallet_id` absent; winner dest has the key. |
| **Serial retry (existing)** | Second `register` after success: `already_registered`, `mintCount === 1`. Keep. |
| **Cross-node same key (existing unit)** | Other `node_id` still creates. Keep. |
| **Pool/funding mint still NULL key** | Helper without key still writes dest `idempotency_key` NULL; partial UNIQUE allows a second NULL dest on another wallet. Unit on SQL params is enough. |

Concurrent drill must **fail on today's PR head** (two dest-on-mints + one keyed adopt ⇒ two wallets). That is the Review B proof.

Do not add bless/retire/MOVE cases. Do not require `SERIALIZABLE` in the new txn.

## 5. What not to do

- No bless / retire / MOVE eligibility / `destination_state` / automatic-sink changes.
- Do not drop, widen, or replace `UNIQUE (node_id, idempotency_key) WHERE idempotency_key IS NOT NULL`.
- Do not add a reservation table or an `(implementer_id, http_method, route, key)` ledger.
- Do not make `destinations.wallet_id` nullable.
- Do not delete loser mints as the primary fix (Candidate B).
- Do not `vault.seal` inside the mint txn.
- Do not `withSerializationRetry` around seal or keygen.
- Do not fire `onWalletMinted` on a rolled-back mint.
- Do not change pool scaler / funding CREATE to pass a register key.
- Do not rewrite dest-on-mint composition for key-less mints beyond optional NULL bind.
- No forbidden vocabulary (`FORBIDDEN_TERMS`).

## 6. Schema: UNIQUE stays

`destinations_node_idempotency_key_uidx` on `(node_id, idempotency_key) WHERE idempotency_key IS NOT NULL` remains the DestinationStore scope and the reservation.

- NULL keys stay legal for dest-on-mint / backfill / WORKER rows.
- CHECK form unchanged (`^[!-~]{16,255}$` when present).
- No second unique, no NOT NULL tighten, no edit of frozen `custody-eligibility.sql` `CREATE TABLE destinations`.
- Slice stays appended; `sql_sha256` of earlier pack versions unchanged.

A is a **write-order** fix against that index, not a DDL fix.

## 7. Per-AC mapping after remediations

| AC | After this change |
| --- | --- |
| Live `findByIdempotencyKey` | Unchanged (PR #166 SELECT). |
| Second register does not mint | True for serial **and** overlap: key reserved in the mint txn; loser rolls back. |
| Port scope `(node_id, key)` | Unchanged. |
| PG test | Existing serial + new concurrent / rollback / timeout-after-keyed-persist. |
| Numbered slice + contract | Unchanged. |
| Bless / retire / MOVE | Unchanged. |

## 8. Sequencing

1. Helper dest INSERT binds optional key; unit params.  
2. Register generator: pinned-client txn → helper with key → seal; 23505 → claim-miss.  
3. `register` catches claim-miss → find → `already_registered`.  
4. Concurrent + rollback PG drills that fail on `bb51881`.  
5. Wiring census: register `generate` still one construction; hook still post-seal.  
6. Implementer note + PR verify commands.
