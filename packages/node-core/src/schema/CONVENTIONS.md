# Schema, transaction, and migration conventions

Conventions for the generic node's PostgreSQL schema. The executable form of these
conventions lives in [`../../data/migrations.ts`](../../data/migrations.ts).

The two-level isolation split and the serialization-failure retry/backoff policy below are
**derived**: the database-wide conventions fix the invariants (atomicity, byte-immutability,
one in-flight transaction per wallet), not an execution regime. The regime here is chosen to
preserve those invariants under concurrency and follows from the one-in-flight-per-wallet rule plus those
invariants.

## 1. Transaction isolation

Two isolation levels, by path class:

| Path class | Isolation | Use for |
|---|---|---|
| Money-path | `SERIALIZABLE` | moving or committing a ZKZ amount, taking/releasing a wallet lease, persisting a signature, appending to an authoritative byte ledger, and any schema migration |
| Other | `READ COMMITTED` | advisory reads, non-authoritative observation reporting, idempotent lookups |

`SERIALIZABLE` is the only PostgreSQL level equivalent to running the transactions one at
a time, which is what "one in-flight transaction per wallet" and the byte-immutability
invariants require under concurrent access. ZKZ amounts are canonical decimal `text`
 — never `real`, `double precision`, or a JavaScript-number-derived `numeric` — so the
serialization guarantee protects exact bytes, not approximations.

## 2. Serialization-failure retry

A `SERIALIZABLE` transaction can fail with SQLSTATE `40001` (`serialization_failure`) —
or `40P01` (`deadlock_detected`) — when PostgreSQL detects a concurrent-write anomaly. The
whole transaction has rolled back, so re-running it from the start is safe.

- Bounded exponential backoff with full jitter: `min(base * 2^(attempt-1), max) * jitter`,
  defaults `base=25ms`, `max=1000ms`, `maxAttempts=5`.
- **Not a blind submit retry** (the never-blind-retry rule): a serialization failure means no row
  landed, so there is nothing to double-spend. A chain submit decision is never retried by
  this policy — only rolled-back database transactions are.
- **Caller discipline, not enforced** (the never-blind-retry rule): `withSerializationRetry` re-runs its
  body on `40001`/`40P01`, which is safe only for an idempotent, DB-only body. A chain
  submit must never appear inside that body — the retry would re-submit it. The function
  cannot detect a submit inside the body; keeping submits out is the caller's responsibility.
- Any non-`40001`/`40P01` error is rethrown immediately.

## 3. Migration naming

`NNNN_description.sql` — a zero-padded four-digit version, an underscore, a lowercase
`snake_case` description, the `.sql` extension. Example: `0001_initial_schema.sql`.

- The version sequence is dense and monotonic; the runner rejects duplicates and applies
  by ascending version.
- Pattern: `^\d{4}_[a-z][a-z0-9_]*\.sql$`.
- A migration that `ALTER TABLE`s to add a foreign key must be numbered after both the
  migration that creates the referenced table and any migration that back-fills rows the
  new constraint requires; a dependency graph being acyclic does not make a given numbered
  sequence buildable — every edge must independently hold under ascending-version
  application.

## 4. Migration journal

One append-only table, `schema_migrations`, created if absent:

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
  version integer PRIMARY KEY,
  description text NOT NULL,
  sql_sha256 text NOT NULL CHECK (sql_sha256 ~ '^[0-9a-f]{64}$'),
 applied_at timestamptz NOT NULL DEFAULT now
);
```

Each migration runs in its own `SERIALIZABLE` transaction; the journal insert lands in the
same transaction as the migration body, so a crash cannot record an unapplied migration or
apply one unrecorded.

The journal is self-contained: it is created as the first statement of every run, before any
application migration, so `sql_sha256` is a plain `text` column with an inline hex CHECK
(`~ '^[0-9a-f]{64}$'`) rather than the schema's `sha256_hex` domain — that domain is created
by a later application migration and would not yet exist, failing bootstrap on a fresh DB.

`sql_sha256` is the SHA-256 of the exact migration SQL bytes, **persisted for future drift
detection**. It is not an active guarantee today: `plan`/`runMigrations` select pending files
by version only and discard the recorded hash, so an already-applied file whose bytes later
change on disk is neither re-run nor flagged. A throw-on-mismatch check is intentionally out
of scope for the bootstrap path (it could brick startup on a benign hash difference).

## 5. ZKZ amount CHECK domains (canonical ZKZ amount contract)

The canonical ZKZ amount contract is a decimal `text` value
bounded `< 100000000` (10^8, exclusive), at most 32 fractional digits, `ROUND_DOWN`, matching
`^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$`. Because v2 stores that value as `text`, the bound is
carried by two CHECK domains, declared in the base migration (`base-enums-domains.sql`)
and *referenced* by every table-bearing contract that applies on top of it. A slice contract that
is characterised as greenfield-applicable on its own (see `migration-integrity.test.ts`) may
re-declare the single domain its own columns need, exactly as it already re-declares
`sha256_hex`; combined application of those slices onto one database is the reconciliation
step that de-duplicates them. Their exact predicates are frozen in
[`../../../generic-node-contracts/src/amounts/manifest.ts`](../../../generic-node-contracts/src/amounts/manifest.ts)
(`ZKZ_AMOUNT_CHECK_DOMAINS`):

| Domain | Predicate | Accepts `"0"` / `"0.00"`? |
|---|---|---|
| `zkz_balance_text` | the regex | yes |
| `zkz_amount_positive_text` | the regex `AND VALUE::numeric > 0` | no |

**Pick the domain by column role.** The role → domain map is frozen in
[`../../../generic-node-contracts/src/amounts/db-enforcement.ts`](../../../generic-node-contracts/src/amounts/db-enforcement.ts)
(`ZKZ_CHECK_DOMAIN_BY_ROLE`) and tested in that package's `db-enforcement.test.ts`:

| Column role | Domain |
|---|---|
| a balance, a derived balance, a node head amount, a genesis amount, a node post-transfer state | `zkz_balance_text` |
| `operations.amount_zkz`, an expected-artifact amount, an approval amount | `zkz_amount_positive_text` |
| a foreign signed step amount, an observed on-chain step state | **no rejecting CHECK** — stored as evidence, flagged as an anomaly, never dropped at INSERT (the byte-exact signing rule) |
| a *typed projection* of an observed value, alongside the preserved raw bytes | the domain its role implies — e.g. `gateway_observations.b_amount` / `lineage_path_body_candidates.b_amount` are `zkz_balance_text`, frozen in [`observation/record-fields.contract.ts`](../../../generic-node-contracts/src/observation/record-fields.contract.ts) and [`observation/scalars.contract.ts`](../../../generic-node-contracts/src/observation/scalars.contract.ts) |

**Writer obligation created by that last row.** A projection column with a rejecting domain must
never be allowed to fail the INSERT that carries the evidence. `gateway_observations.b_amount` is
nullable and sits beside `raw_response_bytes`, which is the authoritative record and carries no
CHECK; an observation whose foreign amount falls outside the balance domain is written with
`b_amount` NULL and classified as an anomaly — the row still lands in full. Rejecting the whole
observation would drop gateway-accepted evidence, which is precisely what amount-bounds authority split and the byte-exact signing rule
forbid. This obligation belongs to the observation ingest path, not to the DDL.

Why the split exists: `VALUE::numeric > 0` is *numeric* positivity, not the string test
`VALUE <> '0'`. `'0.0'`, `'0.00'`, and `'0.'` followed by 32 zeros all satisfy the shared
regex and are `<> '0'` as strings while being mathematically zero. Only `VALUE::numeric > 0`
rejects them. A per-operation amount that is silently zero is a money-path defect, so the
positive-only domain is a byte-exact-signing-adjacent guardrail — not a stylistic choice.

The superseded single `zkz_amount_text` domain (unbounded, zero-permitting) is retired by
and MUST NOT be attached to a new column. Attaching the balance domain where the
positive domain is required — or the reverse — is a silent, byte-adjacent defect this
convention exists to prevent; get the role → domain mapping above right.

## 6. Column-type conventions (enforced)

Every column carries the narrowest type that preserves its authoritative bytes. By role:

| Column role | Type |
|---|---|
| identifier / primary key / foreign key | `uuid` (foreign keys are immediate unless a table explicitly states otherwise) |
| a stream position or an event sequence number | `bigint`, from a dedicated per-node counter — never `bigserial` / `GENERATED … AS IDENTITY`, which leave permanent gaps on rollback (gapless per-node event counter) |
| a timestamp | `timestamptz` in UTC; never a uniqueness or sort key |
| a ZKZ amount | `zkz_balance_text` or `zkz_amount_positive_text` per the ZKZ amount CHECK domains above — never `real`, `double precision`, `numeric`, or any JavaScript-number-derived numeric |
| an exact preimage (transfer code, inner preimage, raw target) | `text`, valid UTF-8 |
| a complete gateway request or response body | `bytea` — it may be invalid UTF-8 and is still evidence |
| a closed enumeration | a Postgres `ENUM`, never `text` + `CHECK … IN (…)`; adding a value is a contract-version change tracked through manifest/fixture registry, never a silent local migration |

Structural rules that ride on top:

- Exact-content tables are append-only; a byte-immutability trigger rejects `UPDATE` and
  `DELETE`, so a stored preimage / transaction / signature / body can never be rewritten.
- Every status transition, event append, lease change, TOTP burn, or signature persistence
  runs inside one `SERIALIZABLE` transaction.

**Enforcement.** `jsonb` (which canonicalizes at rest and destroys the signed byte layout,
byte-exact settled-tx ledger), `json`, `real`, `double precision`, and `numeric` are forbidden on any
authoritative-byte column. This half of the convention is machine-checked:
[`../../test/schema-column-types.lint.test.ts`](../../test/schema-column-types.lint.test.ts)
parses every `src/schema/*.sql` file and fails on a forbidden column type, with a negative case
that proves it fires on an injected `jsonb` column. The remaining rules above are executed
against a live database in the schema-apply phase, inventoried in each table's `*.contract.ts`.

## 7. Runtime role privileges

The runtime application role is `node_core_app` ([`privileges.sql`](./privileges.sql)). It is
granted `SELECT`/`INSERT`/`UPDATE` on public tables and has `DELETE`/`TRUNCATE` revoked by
default (present tables + `ALTER DEFAULT PRIVILEGES` for future ones). That is the structural
DB-grant enforcement frozen pool-policy/custody contracts name for — not a convention.

`CREATE ROLE` needs cluster `CREATEROLE`, which managed hosts often deny. The migration
degrades to `NOTICE` in that case (deliberate — greenfield apply must not hard-fail). Boot
**must not** trust the migration alone: inject
`assertPrivilegeReadiness` from [`../data/privilege-readiness.ts`](../data/privilege-readiness.ts)
as `assertPostMigrationReadiness` after migrations (Option c). The check fails closed
if the role is missing or any public table still grants DELETE/TRUNCATE to it. Ops may provision
the role out-of-band (Option b) to **satisfy** the check; granting `CREATEROLE` to a production
connection (Option a) is rejected.


## 8. Production money schema pack

Production apply is owned by the generic-node composition root (`apps/generic-node/src/db/migrate.ts`):

1. migration lock and classifier guards (session-mode endpoint, migrator advisory lock, overlap classifier).
2. Reporting prefix via drizzle journal tags `0000_reporting_persistence` and
   `0001_fix_lifecycle_deferred_new_fields` (historical; kept for shipped DBs).
3. Layer-1 money pack via `loadMoneySchemaMigrations({ afterReportingPrefix: true })`
   → node-core `runMigrations` into `schema_migrations` (versions ≥ 100). Order is<!-- contract-allow:order:frozen structural vocabulary -->
   `money-schema-pack.ts`. Includes `receive_codes`, `receive_arms`, and
   `receive_release_proofs` CREATE DDL for the receive barriers.
4. Both steps share the same pinned connection and lock — no dual-owner race.

**Catalog ownership:** drizzle `0000_reporting_persistence` owns the shared reference
domains (`sha256_hex`, `padded_base64url_*`), the three reporting enums, and the
reporting helper functions on the combined boot path. Pack slice `base-enums-domains`
owns the full floor (including those shared names) for a standalone money-pack deploy
that never applies the reporting prefix (`loadMoneySchemaMigrations` default).
`loadMoneySchemaMigrations` strips CREATE DOMAIN/TYPE/FUNCTION/TABLE/TRIGGER names a
prior owner already registered so combined apply cannot fail with SQLSTATE 42710.

**Multi-slice CREATE TABLE (money integrity):** name-strip alone would discard later-body
FKs. When a later slice’s CREATE TABLE is stripped, the loader diffs inline REFERENCES
against the first owner’s body and appends idempotent `ALTER TABLE … ADD CONSTRAINT`
wire-up for any missing FKs. Trigger name collisions keep the first owner’s attachment;
CREATE FUNCTION bodies that would only attach via a stripped same-name trigger are not
emitted (no orphan eligibility functions). Multi-slice tables today:

| Table | First owner | Later | Resolution |
|---|---|---|---|
| `wallet_active_leases` | custody-eligibility (`wallet_id→wallets`) | lease-foundation (`membership_id`/`lease_group_id` FKs) | strip + FK wire-up; trigger = `custody_reject_ineligible_lease` |
| `operation_expected_artifacts` | expected-artifacts (stronger FKs) | move-baseline-binding | strip later CREATE (first is FK superset); insert-only trigger from later kept |
| `operator_device_keys` | device-keys | approval-stores | strip later (bodies equivalent) |

**Journal identity (cold-first):** pack versions are `100 + index` into
`MONEY_SCHEMA_PACK_ORDER`. `runMigrations` decides pending by version integer only
(hash is stored, not enforced for drift). GO-LIVE is greenfield cold apply. Any ambient
DB that applied a **pre-** pack at the same version numbers is toxic — colliding
versions are skipped and reordered/replaced slices never re-apply. Prefer wipe + cold
apply; do not attempt content-addressed repair of an old pack journal.

Empty-DB / static proof: `test/money-schema-pack.test.ts`. Live cold-DB proof:
`apps/generic-node/test/db/migrate-guards.test.ts` (reporting + money pack; asserts the
lease FKs, eligibility trigger owner, full pack journal length). Live
migration-integrity characterisation under `TEST_DATABASE_URL` remains the
greenfield-alone gate for individual contract slices.

Excluded after reporting (already materialised by 0000): `reporting-persistence.sql`,
`node-implementer-registry.sql`. Pack includes `signing-key-registry` because
reporting 0000 does **not** create `node_signing_keys` (only `implementer_reporting_keys`);
the pack-time table strip drops the latter CREATE when `afterReportingPrefix` is set.
`verification-proofs.sql` is excluded (FK to undeclared `operation_landing_proofs`).
