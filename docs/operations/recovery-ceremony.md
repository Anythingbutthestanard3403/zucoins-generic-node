# Recovery-verification ceremony (GN-014)

The ceremony is the only thing that stamps `recovery_verified_at` on a wallet, and a wallet
without that stamp is not eligible for receive assignment. You run it at genesis, after every
restore, and before funding a new batch.

## What the stamp actually claims

That an operator proved, **offline**, possession of *both* the wallet secret **and** the
master key. A ciphertext round-trip inside the node is deliberately not sufficient — a node
that can decrypt its own vault has proved only that it is the node. The point of the ceremony
is to prove that a human, holding material that is not on the node, can open a wallet after
the node is gone.

Consequences that catch people out:

- The stamp is **per wallet**, granted **per batch**. There is no whole-vault coverage claim:
  a vault-level backup shares a failure domain with the vault and misses the window between
  minting a wallet and its first backup.
- The column has **no DEFAULT**. Nothing grandfathers a wallet in. `recovery_verified_at`
  (v2) and `export_verified_at` (v1) are separate, non-merged columns.
- A restore does not carry the assurance across. The restored database asserts the stamp; it
  did not witness the ceremony. Re-run it.

## What must never be typed into a shell

| Never | Why | Instead |
| --- | --- | --- |
| `VAULT_MASTER_KEY` as a command-line argument | Every argument is visible in `ps` to every user on the host, and lands in shell history | Environment variable, or the admin API body |
| `BACKUP_MASTER_KEY` as an argument | Same | Environment variable |
| The recovery-pack secret as an argument | Same, and the pack is designed to leave the host | Paste into the SPA prompt |
| Any of the above into a chat, ticket, log line or screenshot | The archive's confidentiality equals possession of the master key | Nowhere. It stays offline |

The CLI takes keys from the environment only, by design. If you find yourself wanting a
`--master-key` flag, that is the guard working.

Nothing prints a private key. The ceremony reports digests and counts. If you ever see key
material in output, stop and treat it as a disclosure incident.

## Two paths

### Path A — the admin API (normal)

`POST /admin/v1/recovery-ceremony/start`, then poll `GET /admin/v1/recovery-ceremony/status`.
This is what the operator SPA drives.

Gates, in order: admin session → CSRF → per-user ceremony lockout (429 when tripped) →
single-flight check (409 while one is already running) → fresh single-use TOTP, burned. The
master key enters as a request body field, never as a URL parameter, is never logged, never
written to the database or the audit trail, never returned, and is zeroed after use.

Status reports a stage — `accepted`, `exporting_archive`, `restoring_throwaway`,
`verifying_wallets`, `stamping`, `summarising`, `complete`, `failed` — plus digests and
counts: `stamped`, `failed_closed`, `skipped`.

### Path B — the CLI (break-glass)

For when the admin surface is not available.

```bash
DATABASE_URL=postgresql://... \
VAULT_MASTER_KEY=... \
NODE_ID=<uuid> \
ADMIN_TOTP_CODE=<current 6 digits> \
node dist/ops/run-recovery-ceremony.js
```

Optional: `NODE_IDENTITY_SEED` (verifies the sealed public key on the live export),
`ARCHIVE_PATH` (skip the live export and load an existing archive), `ARCHIVE_OUT`,
`ARCHIVE_EPOCH_MASTER_KEY` (a prior-epoch archive key).

The TOTP code is verified against the enrolled admin operator's active secret and burned
through the durable store — the CLI is not a way around the guarded-mutation requirement, and
the verifier identity comes from the authenticated operator, never from an argument.

## What it does

1. Export a live backup archive — vault-open plus wallet export proofs. (Or load
   `ARCHIVE_PATH`.)
2. Stand up a **throwaway** restored instance and open the restored envelopes with the master
   key.
3. Attach to the **live** database for the stamp seam only — this is the sole writer of
   `recovery_verified_at`.
4. Stamp the wallets that verified. Wallets that failed the open probe are failed closed, not
   skipped quietly.
5. Destroy the throwaway instance.

Every wallet is proved by the same open probe used at boot: decrypt the envelope → derive the
Ed25519 public key → match it against `wallets.public_key`. A mismatch is a substitution
control firing, and the wallet is quarantined rather than stamped.

## Afterwards — destroy the artifacts

The archive carries each wallet's sealed vault envelope. It is secret-class, exactly like a
wallet backup.

- `.recovery-ceremony/` and `*.archive.json` are git-ignored, and
  `apps/generic-node/test/ops/ceremony-artifacts-ignored.test.ts` fails if either pattern
  stops being ignored.
- Destroying the archive and every intermediate is a **hard step of the ceremony**, not
  cleanup you get to postpone.
- Do not copy the archive to a workstation, a bucket, or a ticket attachment on the way.

## Recovery pack

`POST /admin/v1/recovery-pack/create` produces `zp-node-recovery-pack-v2`: Argon2id →
AES-256-GCM seal of the vault master key under a **generate-only** secret. The node draws
the seal key with CSPRNG (`generateRecoverySecret()`: Crockford base32 × 26 symbols) and
returns it **once** on the live create response; the durable idempotency row never stores
it. Callers must not supply `recovery_secret` — any body field value is refused
(`caller_supplied_recovery_secret`), weak or strong. Structure guards on the generator
reject pathological CSPRNG draws; they are not a measured content-entropy floor and are
not an accept path for operator-chosen strings (ZTR-1220).

`POST /admin/v1/recovery-pack/prove` opens a pack and is subject to an online lockout.

The pack is designed to leave the host, so it must survive hostile hands. Two things follow:

- The online prove lockout governs API attempts only. It is **irrelevant** to someone holding
  a copy of the file, who attacks it offline at their leisure.
- **Every `zp-node-recovery-pack-v1` ever exported is compromised-if-leaked.** v1 sealed under
  a 4–6 digit passcode — a keyspace of at most a million, enumerable offline against the same
  Argon2id. v1 packs still open through an explicit legacy opt-in so you can migrate. Re-issue
  as v2 and destroy the v1 copy (ZTR-1126). Re-issue is also generate-only for the new seal
  secret.

Store the pack the way you would store a wallet backup, and store the vault root KDF salt
with it — see [`restore.md`](restore.md).

## Master-key rotation

**Not operational as a CLI.** `node dist/operations/rotate-master-key.cli.js` refuses with
`adapters_not_wired`: the composition root does not inject the durable vault census, journal
and unit-of-work ports it needs. The rotation flow underneath it in node-core is real,
implemented and tested — the binary entry point is not wired to it.

There is no ad hoc alternative. Regenerating key material by hand is not a rotation
procedure; the sanctioned path is the per-row round-trip-verified rotation, and until the
adapters land there is no way to invoke it from a shell. If you need a rotation, escalate.
