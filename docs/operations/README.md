# Operating the generic SplitChain custody node

You are running a **self-hosted custody service**. This node holds the Ed25519 private key
of every wallet in its pool, sealed under a master key that only you have. Nobody upstream
can recover a key for you, roll back a signature, or undo a submit.

Several of this node's behaviours are deliberately counterintuitive and look like bugs
under pressure. Before you change anything at 3am, read this:

| It looks like | It is actually | Doing the "obvious" thing causes |
| --- | --- | --- |
| A wallet lease is stuck — its heartbeat expired hours ago | Correct. A heartbeat expiring is **not** a lease release (`LEASE_AGE_AUTOMATIC_RELEASE = false`) | A second signer over the same wallet — a possible double spend |
| A submit returned nothing / timed out | `INDETERMINATE`. The chain may or may not hold it | Retrying the submit can land the transaction twice |
| Shutdown hung and the process still holds the signer lock | Correct. A failed flush deliberately exits holding the lock | Force-releasing lets another instance sign into an unflushed state |
| The gateway acknowledged the submit with `status:true` | Receipt only. Settlement is asserted **only** from a fresh verified chain read | Marking the operation landed on an acknowledgement |
| The node boots clean after a restore and `/health/ready` returns 200 | `restore_hold` still held → ready is 503 (ZTR-1172); `auth_hold` still held → reporting refused even after ready | See [`restore.md`](restore.md); release via `dr markers release` (ZTR-1135) |

## The documents

| Document | Read it when |
| --- | --- |
| [`restore.md`](restore.md) | You are rebuilding this node from a backup |
| [`incidents.md`](incidents.md) | An alert fired, or something is wrong and you do not know what |
| [`attention-triage.md`](attention-triage.md) | An operation is flagged `needs_attention` |
| [`recovery-ceremony.md`](recovery-ceremony.md) | Wallets need `recovery_verified_at` stamped — at genesis, after restore, or before funding |
| [`alert-reference.md`](alert-reference.md) | You want the meaning, severity and posture of one alert signal (generated from source) |
| [`escalation-matrix.md`](escalation-matrix.md) | You need to decide who to wake (generated from source) |
| [`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml) | You are wiring Prometheus |
| [`push-action-suffix-rotation.md`](push-action-suffix-rotation.md) | Boot fails with `PushActionVocabularyRejectedError` / wallet push action-name drift |
| [`full-suite-test-runs.md`](full-suite-test-runs.md) | You need full-suite vs targeted test expectations (ZTR-1209) |
| [`auto-approve-external-sends.md`](auto-approve-external-sends.md) | Auto-approved external sends: setup (both routes), spend vs cap, three stop levers, audit, wallet pool |

## What the node is

A node that performs exactly **three** money operations and nothing else:
`RECEIVE_EXTERNAL`, `MOVE_INTERNAL`, `SEND_EXTERNAL`
(`packages/generic-node-contracts/src/operations/operations.contract.ts`). A receive may
spawn at most one `MOVE_INTERNAL` child. There is no workflow engine, no sweep, no payout —
anything shaped like a business process belongs to the implementer above this node.

There is **no sandbox mode**. Every configured gateway is a live production gateway.

## The two process entries

| Entry | Command | Custody | What it runs |
| --- | --- | --- | --- |
| `dist/main.js` | `pnpm --filter @zucoins/generic-node start` | **Yes** — unlocks the vault, holds wallet keys, signs | Full boot lane, admin API + operator SPA, money workers |
| `dist/stage1-main.js` | `pnpm --filter @zucoins/generic-node start:stage1` | No | Health server, migrations, scheduled encrypted backups. Holds the backup master key and a database URL, never a wallet key |

Stage 1 exists so a deployment can run migrations and backups without ever unlocking the
vault. It refuses a production boot without a configured backup sink.

## Configuration

`apps/generic-node/.env.example` is the authoritative catalogue — every variable, its
`[first-boot]` / `[mutable]` classification, its bounds, and what happens when it is wrong.
Read it; it is not duplicated here. The four that fail a production boot outright when left
at their placeholder literal:

```
DATABASE_URL              postgres connection string
SPLITCHAIN_GATEWAY_URLS   comma-separated; first entry primary, rest failover
PUBLIC_BASE_URL           this node's externally reachable https base URL
METRICS_SCRAPE_TOKEN      bearer token for /metrics; ABSENT means the route is not mounted at all
```

Two independent custody secrets, which boot refuses to let you make equal:

```
VAULT_MASTER_KEY    seals the wallet vault. Losing it loses every wallet secret.
BACKUP_MASTER_KEY   dedicated KEK for encrypted backups. Not the vault key, not a signing key.
```

`pnpm --filter @zucoins/generic-node generate-secrets` mints a fresh set.

`VAULT_ROOT_SALT_B64` deserves its own warning: leave it unset. A brand-new node mints its
own random salt at genesis and persists it in `vault_root_kdf_salt` beside the sealed
envelopes, so it travels with every database backup. **Back it up with your recovery pack.**
A salt is not secret, but a salt lost alongside a database you have lost is an
unrecoverable node.

## Starting it

```bash
pnpm install
pnpm --filter @zucoins/generic-node build:all     # operator SPA, then tsc -b
pnpm --filter @zucoins/generic-node start         # custody
```

Migrations are **not** a pre-step. They run inside the boot lane, after configuration
validation. `pnpm --filter @zucoins/generic-node db:migrate` exists for the Stage-1 and
maintenance cases; the custody entry does not need it.

### Reference deployments

`apps/generic-node/deploy/` carries the two shipped starting points. Both are references to
adapt, not turnkey production: neither one supplies your secret store, your durable volume or
your on-call record.

| Artifact | For |
| --- | --- |
| `deploy/deployment.yaml` | Kubernetes. Nonroot, read-only root filesystem, all capabilities dropped; custody roots by `secretKeyRef` only; `strategy: Recreate` with `replicas: 1` because the backup sink is ReadWriteOnce; separate liveness and readiness probes; a `terminationGracePeriodSeconds` larger than the graceful-stop drain so the platform never hard-kills the process mid-signature |
| `deploy/docker-compose.yml` | Local or single-VPS. Bundles Postgres |
| `deploy/smoke-image.mjs` | `pnpm --filter @zucoins/generic-node smoke:deployment-image` — typed manifest validation plus a real boot of the manifest's own field set through the config loader and boot lane. Run it after editing the manifest |

The compose path mints its own secrets rather than having you invent them:

```bash
node apps/generic-node/scripts/generate-secrets.mjs \
  --out apps/generic-node/deploy/.env.local \
  --public-base-url http://127.0.0.1:8787
cd apps/generic-node/deploy && docker compose --env-file .env.local up -d
```

The generator prints a `SETUP_URL` (`<PUBLIC_BASE_URL>/setup`). That is the operator SPA's
first-run wizard: change the initial password, enrol TOTP, enrol a device key. Until it is
finished the admin surface redirects every route back to it.

`.env.local` holds `VAULT_MASTER_KEY` and `BACKUP_MASTER_KEY` in plaintext. It is gitignored;
treat the file itself as secret-class and do not carry it to the Kubernetes path, where those
two values belong in the platform secret store.

### Boot order

Structurally enforced by `apps/generic-node/src/boot/boot-lane.ts`. A deployment manifest
or script that reorders any of this is a spec violation, not a style choice.

0. **Configuration validation** — in `main.ts`, before the lane. Fail-fast, exit 1.
1. **Migrations**, then the post-migration assertions and privilege readiness → `schema` gate opens.
2. **Vault unlock** → `vault` gate opens.
3. **Signer leadership lock** acquired → `leadership` stamped (reported, does not gate ready).
4. **Boot recovery** — classify every non-terminal operation, then resume only what that
   classification authorizes.
5. **One validated gateway read** → `gateway`/observation gate opens.
6. **Readiness** = `schema ∧ vault ∧ observation ∧ not-stopping`, with the database
   live-probed by `/health/ready`. Only then do money workers start.

Boot deliberately **does not**: delete a stale lease based on time; submit an attempt whose
call boundary is ambiguous; re-form an external partial; auto-clear attention; auto-accept a
new destination; or synthesize missing exact bytes from parsed JSON. If you find yourself
wanting boot to do one of those, you are about to cause the incident.

On a global invariant breach the lane returns early: readiness stays false, leadership is
**retained** (so a second instance cannot sign into a broken inventory), and money workers
never start. That is quarantine working, not a hang.

### Endpoints

| Path | Auth | Notes |
| --- | --- | --- |
| `GET /health` | public | Liveness |
| `GET /health/ready` | public | The readiness conjunction plus a live DB probe |
| `GET /metrics` | `Authorization: Bearer <METRICS_SCRAPE_TOKEN>` | Prometheus text exposition. Unmountable without a token — never open |
| `/admin/v1/*` | session + CSRF + TOTP on mutations | Operator API; the SPA at `PUBLIC_BASE_URL` is its client |
| `POST /admin/v1/operations/:operation_id/recovery-actions` | as above, plus fresh single-use TOTP, recovery nonce, expected row version, idempotency key | The only way to act on a flagged operation |

Scope denial answers **401 `invalid_api_key`, never 403** — the auth surface is deliberately
non-oracular. A 401 does not tell you the key was valid but under-scoped.

## Operator tooling

Everything below is built into `dist/`; run `pnpm --filter @zucoins/generic-node build`
first.

| Command | What it does |
| --- | --- |
| `pnpm --filter @zucoins/generic-node dr backup --out <file>` | Encrypted ZBKP export of `DATABASE_URL` |
| `pnpm --filter @zucoins/generic-node dr restore --in <file>` | Restore, **forcing both post-restore holds** |
| `pnpm --filter @zucoins/generic-node dr drill` | Throwaway destroy/restore drill with RPO/RTO evidence |
| `pnpm --filter @zucoins/generic-node dr verify --path <file-or-dir>` | Decrypt-verify provider artifacts without applying |
| `pnpm --filter @zucoins/generic-node dr markers check\|release --file <path>` | Continuity markers check / dual-gate release — **see [`restore.md`](restore.md)** |
| `pnpm --filter @zucoins/generic-node dr status` | RPO posture against `BACKUP_OUTPUT_DIR` |
| `node dist/ops/run-recovery-ceremony.js` | Break-glass recovery-verification ceremony ([`recovery-ceremony.md`](recovery-ceremony.md)) |
| `node dist/operations/rotate-master-key.cli.js` | **Not operational.** See "Known-blocked" below |

## Known-blocked procedures

Documented here because the alternative is an operator discovering them mid-incident.
None of these are fixed by this document; each has a ticket.

| Procedure | State | Ticket |
| --- | --- | --- |
| Releasing `restore_hold` / `auth_hold` after a restore | Shipped: `dr markers release --file <offsite-markers>` atomically clears both gates when trusted markers match the restored dump (`AUTH_HOLD_RELEASED` + restore_hold clear). See [`restore.md`](restore.md) | ZTR-1135 (shipped) |
| Continuity marker emission | Shipped on the scheduled-backup path: dump-bound snapshot via `pg_export_snapshot` + `pg_dump --snapshot`, written to `BACKUP_CONTINUITY_MARKERS_PATH` only after pair success (RPO anchors stay cold otherwise) | ZTR-1136 (shipped) |
| Master-key rotation via CLI | `rotate-master-key.cli.js` refuses with `adapters_not_wired` — the composition root does not inject the census/journal/unit-of-work ports. The node-core rotation flow underneath it is real; the binary entry is not | none — flagged with ZTR-1131 |
| Paging on any alert | Configure `OPERATOR_ALERT_WEBHOOK_URL` (https, no credentials). P1/P0 escalate to log+webhook | ZTR-1144 |

## Provenance of this documentation

ZTR-89 and its children ZTR-366 / ZTR-367 / ZTR-368 are marked Done and their artifacts are
real — they landed in the **platform** repository, not this one:

| Ticket | Artifact |
| --- | --- |
| ZTR-366 | `zupayments:docs/runbooks/deploy-rollback.md` |
| ZTR-367 | `zupayments:docs/runbooks/restore-key-incident.md` |
| ZTR-368 | `zupayments:docs/runbooks/chain-observation-incidents.md` |
| — | `zupayments:docs/runbooks/generic-node-dr.md` (DR surface overview) |

**Disposition: retained cross-repo, not imported.** They are written against the
`docs/proposals/generic-node-redesign-v2/` specification, which lives in that repository
alongside `docs/DECISIONS.md`; copying them here would fork them from their own governing
spec. ZTR-1224 tracks keeping `09-operations-recovery.md` current there.

What this directory adds, and they cannot: procedures that version with **this** code, and
an honest account of which of them currently work. Where they conflict, this directory wins
on the state of the shipped node — in particular, `restore-key-incident.md` §2 describes the
node clearing `restore_hold` and `auth_hold` after marker reconciliation, and no such code
path exists (ZTR-1135). It also references `apps/generic-node/deploy/README.md`, which is not
in this tree.

## Regenerating the generated documents

```bash
pnpm build
node scripts/gen-operator-alert-docs.mjs           # write
node scripts/gen-operator-alert-docs.mjs --check   # exit 2 on drift
```

`apps/generic-node/test/operator-docs.census.test.ts` fails if a signal or attention reason
loses its documentation, or if a generated file stops matching a fresh render.

## Push delivered-envelope shape (ZTR-1154)

Inbound Web Push is the primary external-receive detection channel. The route answers
**204 on every path** (discard semantics) — a reshape of the wallet envelope therefore
looks healthy from outside.

**Detection**

| Signal | Source | Meaning |
| --- | --- | --- |
| `gn_push_receive_total{outcome,shape}` | `createPushReceiver` via injected metrics port | Per-outcome counter. `enqueued` carries `shape` ∈ {`aps`,`data`,`send_side_fallback`}; misses use `shape="none"`. |
| `gn_push_no_transfer_code_streak` | process-local gauge | Consecutive `no_transfer_code` since the last `enqueued`. |
| log `push: ALERT push_no_transfer_code_streak` | `composePush` streak tracker | Fires once when the streak first reaches the threshold. |
| `SAFETY_ALERT_SIGNALS` `push_no_transfer_code_streak` | `composePush` → `safetyAlertEvaluator` + Prom rule | Pageable P1 (log+webhook escalation); same threshold 20. |

**Threshold:** `DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD = 20` consecutive
`no_transfer_code` with no intervening `enqueued`.

**Rationale:** a single `no_transfer_code` is normal (non-transfer notifications). Twenty
in a row on a live subscription is far above ambient noise for a funded node and short
enough that a wallet-side envelope reshape pages within one delivery burst rather than
being found by a later volume review. A consecutive count needs no clock, survives scrape
gaps, and matches the failure mode (sustained shape miss).

**Golden:** `packages/generic-node-contracts/goldens/push/delivered-envelope.data.v1.json.txt`
pins the FCM/Mozilla cleartext shape; `resolveTransferCodeFromEnvelope` is exercised
against those exact bytes. APNs was not captured — see the golden `meta.json`.

**Operator action on alert:** compare a freshly decrypted live cleartext against the
golden; if the nest moved, update `payload.ts` precedence and refresh the golden in the
same reviewed commit. Do **not** change the 204 response.

## Candidate-intake backlog (origin-relay + Web Push)

The node admits payer step-1 partials through two producer lanes into one in-memory
inbox (`createCandidateIntakeInbox`):

| Lane | Route | Trust |
| --- | --- | --- |
| `push` | `POST /v1/receivers/push/:endpoint_id` | Authenticated (ECE auth secret + endpoint id) |
| `relay` | `POST /v1/receivers/origin-relay` | Anonymous; volume-throttled per socket peer |

Both lanes are capped at `RECEIVE_QUEUE_CAP` (= `POOL_CAP_TOTAL`). The relay lane is
additionally rate-limited (~120 deposits/minute/IP). Every HTTP outcome on both routes is
**204** — throttled, full, malformed, and accepted are indistinguishable on the wire
(non-oracular). Operators watch:

- `gn_candidate_intake_backlog{source}` — current in-memory depth (approach to the cap)
- `gn_candidate_intake_refused_total{source,reason}` — cliff counts (`inbox_full`,
  `rate_limited`, decode failures, …)

### Restart durability — intentional drop, reconcile repairs

The candidate-intake inbox is **process-local**. A process restart discards any un-served
backlog. That is intentional for this ticket (ZTR-1216): there is no durable queue for
pre-intake deposits. Genuine receives that were only sitting in the inbox are re-detected
by the node's existing **reconcile / periodic-repair** path once the corresponding on-chain
evidence is visible again. Do not treat a post-restart backlog of 0 as proof that nothing
was in flight — check open `RECEIVE_EXTERNAL` operations and reconcile outcomes instead.

## Push action-name suffix rotation (ZTR-1207)

The wallet push host dispatches on **opaque per-action suffixes** transcribed from the
shipped wallet bundle. There is no client-side derivation rule. When a wallet release
rotates those suffixes, boot fails loudly via the action-vocabulary probe.

**Runbook:** [`push-action-suffix-rotation.md`](push-action-suffix-rotation.md) — probe-failure
signature, the four literal locations, manual re-transcription recovery, and the deferred
host discovery option (out of scope until the host offers it).
