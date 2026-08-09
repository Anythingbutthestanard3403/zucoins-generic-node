# Restore runbook

Rebuilding this node from an encrypted backup. Read the whole document before you start —
step 4 is currently **blocked**, and you need to know that before you destroy anything.

> **Restore is a one-way door today.** A restored node comes up holding two independent
> gates, and no shipped code path releases either one (ZTR-1135). Its money surface works;
> its reporting surface answers `reporting_auth_hold` to every implementer call, and stays
> that way. Do not restore into your only live node expecting to be back in service.

> **This runbook is unrehearsed.** It was written from the shipped code, not from a
> dry run. Steps 3 and 4 cannot be executed at all until ZTR-1135 lands, so an end-to-end
> rehearsal against a real backup is not possible today and the gaps a first reader would
> hit are therefore unknown. What *is* rehearsable now is steps 1–2 and the mechanics
> underneath them, via `dr drill` against a throwaway database (Preflight step 4). Run that
> quarterly, and record what the runbook got wrong here. When ZTR-1135 lands, the first
> full restore must be treated as the rehearsal — schedule it, do not discover it.

## What you must hold before you begin

| Thing | Without it |
| --- | --- |
| The `.zbkp` artifact | Nothing to restore |
| `BACKUP_MASTER_KEY` used to seal it | The artifact is unreadable. It is a dedicated KEK — not the vault key |
| `VAULT_MASTER_KEY` for this node | The database restores and every wallet secret stays sealed forever |
| A target Postgres database that is **empty** | See "Preflight" — the restore will roll back |
| `node_core_app` and `node_core_send` roles on the target cluster | Boot refuses at privilege readiness |

`VAULT_ROOT_SALT_B64` is **not** on that list, and you should leave it unset. The salt lives
in the `vault_root_kdf_salt` table beside the sealed envelopes, so it comes back with the
database. Setting the variable to a different value is refused; setting it to the right one
is redundant.

## Preflight

**1. Verify the artifact without applying it.**

```bash
pnpm --filter @zucoins/generic-node dr verify --path /path/to/backup.zbkp
```

This decrypts and checks GCM authentication and the SHA-256 plaintext checksum. `ok: false`
means stop — a wrong key and a corrupt file are indistinguishable at this point, and both
mean you do not have the backup you think you have.

**2. Confirm the target database is empty.**

The dump is `pg_dump --format=plain --no-owner --no-acl`: no `DROP`, no `CREATE DATABASE`.
Restore pipes it into `psql --single-transaction -v ON_ERROR_STOP=1`, so the first duplicate
object aborts the transaction and the whole restore rolls back. That is the safe failure —
it never half-applies — but it means restoring over an existing schema simply does not work.
Create a fresh database.

**3. Provision the runtime roles out-of-band.**

`--no-acl` carries no grants, and `schema_migrations` rows travel inside the dump, so the
migration runner will consider `privileges.sql` already applied and will not re-run it for
you. Create `node_core_app` and `node_core_send` on the target cluster and apply the
`GRANT`/`REVOKE` set from `packages/node-core/src/schema/privileges.sql` yourself. Boot's
`assertPrivilegeReadiness` verifies the DELETE/TRUNCATE revokes structurally and refuses the
boot if they are absent — it does not trust the migration.

**4. Practise on a throwaway first, if you have not this quarter.**

```bash
BACKUP_DRILL_TEMPLATE_URL=postgresql://... pnpm --filter @zucoins/generic-node dr drill
```

Destroy/restore against a throwaway database, with RPO/RTO evidence in the output. Targets:
**RPO 24h**, **RTO 1h** (`apps/generic-node/src/dr/policy.ts`). The drill exercises the
backup and restore mechanics; it does **not** exercise hold release or the ceremony, so a
green drill is not proof that a real restore returns you to service.

## The order

Each step depends on the one before it. **Clearing one hold alone grants nothing** — the
node admits reporting traffic only when `restore_hold` is false **and** every lifecycle head
has `auth_hold` false. That conjunction is the whole point: a restored database can be
convincing about its own state, so the release requires evidence that did not come out of it.

### 1. Restore

```bash
DATABASE_URL=postgresql://...   \
BACKUP_MASTER_KEY=...           \
NODE_ID=<this node's uuid>      \
pnpm --filter @zucoins/generic-node dr restore --in /path/to/backup.zbkp
```

On success the command prints, among other fields:

```json
{"restoreHoldApplied": true, "authHoldApplied": true, "authHoldHeadsForced": <n>}
```

Both gates are **forced after apply**, deliberately, even if the dump encoded them released.
`restoreHoldApplied: false` means the `reporting_restore_state` table was absent, not that
you are clear.

### 2. Obtain the continuity markers — from outside this database

You need three values from a **separately trusted external source**: the lifecycle epoch,
the node-wide nonce-burn high-water mark, and the terminal lifecycle-event hash. Equal
values read only from the restored database have no authority — that is the entire
anti-rollback property. If an attacker can hand you a stale database, they can hand you a
stale database that agrees with itself.

```bash
pnpm --filter @zucoins/generic-node dr markers check \
  --file /path/to/continuity-markers.json \
  --local-epoch <n> --local-high-water <n> --local-event-hash <hex>
```

Exit 0 means the trusted markers and the local snapshot agree and release is warranted.
Exit 2 prints the reject reason — `lifecycle_epoch_mismatch`,
`regression_nonce_burn_high_water`, `terminal_event_hash_mismatch` and friends. A
regression reason means the restore rolled the node backwards: **stop, and escalate**. Do
not proceed to make the markers agree.

> **Known-blocked (ZTR-1136).** `dr markers write` builds the "trusted" file **from** the
> local snapshot you pass it, so a file produced that way compares equal by construction and
> proves nothing. There is also no shipped query that derives the three `--local-*` values
> from the database. Until ZTR-1136 lands, treat `markers write` as a formatting utility
> only, and source both the trusted markers and the local values from records you keep
> outside this node.

### 3. Release `restore_hold` — **blocked**

### 4. Release `auth_hold` — **blocked**

> **Known-blocked (ZTR-1135).** The release *predicate* is implemented and tested
> (`evaluateRestoreHoldRelease`), and the statement that writes `restore_hold = false`
> exists (`buildRestoreHoldReleaseUpdate`) — nothing invokes it. `AUTH_HOLD_RELEASED` is a
> legal lifecycle event type that no code path ever appends. `dr markers check` computes the
> release decision and returns an exit code; it cannot perform the release.
>
> There is no command, endpoint or supported SQL to clear either hold. Do **not** improvise
> one: `auth_hold` is inside a hash-chained lifecycle head protected by composite foreign
> keys, epoch and nonce-evidence CHECKs and a deferred assertion, and a hand-written event
> that fails any of them leaves the head and its event chain in a state the guard trigger
> rejects. Escalate to ZTR-1135.

### 5. Re-run the recovery ceremony

`recovery_verified_at` does not survive an untrusted restore as an assurance. The stamp
means an operator proved **offline** possession of both the wallet secret and the master
key; a database that asserts the stamp is asserting something about a ceremony it did not
witness. Restore re-runs the per-wallet open probe (decrypt → derive public key → match
`wallets.public_key`) and quarantines failures.

See [`recovery-ceremony.md`](recovery-ceremony.md). Wallets without a valid stamp are not
eligible for receive assignment, so this is what actually returns the pool to service.

### 6. Verify admission

Only after 3–5. In order:

1. `GET /health/ready` returns 200 — the readiness conjunction is open.
2. `gn_readiness_ready` is 1 and `gn_signer_leadership_held` is 1 on `/metrics`.
3. `gn_available_wallets` is non-zero — wallets carry a fresh ceremony stamp.
4. An implementer call succeeds rather than returning `reporting_auth_hold`.

A 200 from `/health/ready` on its own means nothing about the holds. Readiness gates on
schema, vault, observation and the database probe; `restore_hold` is not one of the gating
checks. A held node looks healthy from the outside and refuses every implementer call.

## Backup cadence

| Setting | Default | Where |
| --- | --- | --- |
| RPO target | 24h | `BACKUP_RPO_TARGET_MS` |
| RTO target | 1h | `BACKUP_RTO_TARGET_MS` |
| Retention | 14 days (1–90) | `BACKUP_RETENTION_DAYS` |
| Schedule interval | 24h (1h–24h) | `BACKUP_SCHEDULE_INTERVAL_MS` |

```bash
pnpm --filter @zucoins/generic-node dr status    # exit 2 when the RPO is breached
```

`BACKUP_OUTPUT_DIR` must be a durable volume. Never `/tmp` — an ephemeral `emptyDir` means
you have no backups and a green status.

Alerts on this cadence: `GenericNodeBackupAge`, `GenericNodeBackupNeverSucceeded`,
`GenericNodeBackupRpoBreached` in
[`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml).

## What a restore never does

- It never re-serializes evidence. Authoritative raw gateway response bytes and exact signed
  transaction text are stored as bytes and restored as bytes.
- It never deletes an observation or anomaly row to make room. Those ledgers are permanent;
  storage pressure is a capacity problem, not a retention problem.
- It never re-submits anything. An operation whose submit boundary was ambiguous when the
  backup was taken is still ambiguous after the restore, and still must not be retried.
