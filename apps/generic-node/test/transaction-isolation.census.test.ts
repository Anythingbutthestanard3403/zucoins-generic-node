// Transaction-isolation census: every transaction-opening BEGIN in the production trees is
// classified money-path vs other, and every money-path one names the mechanism that makes it
// safe (ZTR-1155).
//
// Protected property: `packages/node-core/src/schema/CONVENTIONS.md` §1 — money-path
// transactions run under `SERIALIZABLE`, or under `READ COMMITTED` with a covering lock held
// for the whole transaction on a pinned client. Before this file the convention named only
// the isolation level, the code used row locks almost everywhere, and nothing checked either:
// twenty-seven independent judgement calls with no rule a reviewer could apply to the
// twenty-eighth.
//
// The mechanism is the repo's usual one — an exact-set census over a declared table, in the
// shape of `submit-write-path-reach.guard.test.ts` and the `*.census.test.ts` family. A new
// BEGIN lands in the computed set and reddens until it is declared with a classification; a
// scanner that stops seeing a tree empties the computed set and reddens against the non-empty
// declared side rather than passing.
//
// WHAT IS MEASURED. Every string or template literal in the production `.ts` of both trees
// whose text starts with `BEGIN`. That is deliberately wider than `client.query("BEGIN")`:
// a BEGIN parked in a `const` and issued through an indirection is still a transaction start,
// and keying on the call shape would let it through unseen. plpgsql `BEGIN` inside a
// `CREATE FUNCTION … AS $$ … $$` body does not match — those literals start with `CREATE`.
//
// DECLARED CEILINGS. This file does NOT prove:
//   * that a named lock is actually taken at runtime. It records the statement and the
//     module a reviewer can read it in; the claim is auditable, not executed here. The
//     runtime proofs live with each site (e.g. `arm-wallet-gate.test.ts` asserts the pinned
//     BEGIN → body → COMMIT, `sql-attention-retraction-store.pg.test.ts` runs the lock).
//   * that a `file:line` citation in a row resolves. Nothing here parses the prose; a stale
//     pointer is caught by review, not by the gate. (Two were, in the ZTR-1155 review.)
//   * anything about SQL issued outside these two trees, or from test files.
//   * that a `READ COMMITTED` site classified `other` is correct to be `other`. That is the
//     judgement the table records so it can be reviewed once and re-reviewed on change,
//     rather than re-derived from scratch by whoever reads the file next.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = resolve(here, "../../..");
const TREES = ["apps/generic-node/src", "packages/node-core/src"] as const;

/**
 * How a site is kept safe against the read-then-write anomalies `READ COMMITTED` permits.
 *
 * `SERIALIZABLE` — the transaction sets the level itself. It MUST then also be retried,
 * because `40001` only becomes reachable once the level is raised (`CONVENTIONS.md` §2).
 * `ROW_LOCK` — a lock taken inside the transaction on the pinned client and held to COMMIT:
 * `SELECT … FOR UPDATE`, `pg_advisory_xact_lock`, or a guarded `UPDATE … RETURNING`, whose
 * row lock and predicate re-evaluation give the same serialization for the rows it covers.
 * `CONSTRAINT` — an immediate unique/exclusion constraint that decides the race in the
 * database, so the loser aborts instead of double-applying.
 * `NONE` — permitted only for `other`, where no money-path predicate is in play.
 */
type Mechanism = "SERIALIZABLE" | "ROW_LOCK" | "CONSTRAINT" | "NONE";

interface TransactionSite {
  /** Enclosing function or factory — orientation for a reader, not asserted. */
  readonly site: string;
  /**
   * `money-path` iff the transaction moves or commits a ZKZ amount, takes or releases a
   * wallet lease, persists a signature, appends to an authoritative byte ledger, or applies
   * a schema migration (`CONVENTIONS.md` §1). Everything else is `other`.
   */
  readonly pathClass: "money-path" | "other";
  /** `SERIALIZABLE` iff the literal itself sets the level; asserted against the source. */
  readonly isolation: "READ COMMITTED" | "REPEATABLE READ" | "SERIALIZABLE";
  readonly mechanism: Mechanism;
  /** The covering statement and its target, or why none is needed. Required for money-path. */
  readonly covering: string;
  /** Evidence the transaction runs whole on one checked-out client. Required for money-path. */
  readonly pinned: string;
}

/**
 * The classification table — the ticket deliverable and the gate's declared side, keyed by
 * repo-relative path with one entry per BEGIN in source order.
 *
 * Line numbers are deliberately NOT part of the key: they rot on every unrelated edit above
 * a site, and a census that reddens for benign reasons is a census that gets rubber-stamped.
 * The per-file count below is what pins an entry to a site.
 */
const TRANSACTION_SITES: Readonly<Record<string, readonly TransactionSite[]>> = {
  "apps/generic-node/src/bootstrap/reporting-key-enrol.ts": [
    {
      site: "enrolFirstReportingKeyOnBoot",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "CONSTRAINT",
      covering:
        "reporting_key_lifecycle_heads PRIMARY KEY (node_id, implementer_id) " +
        "(schema/reporting-persistence.sql:480) — a second enrol loses the insert rather than " +
        "minting a second ACTIVE key. Enrols a reporting credential; moves no amount, takes no " +
        "lease, appends to no money ledger.",
      pinned: "one pool client, BEGIN → insertFirstKeyLifecycle → COMMIT",
    },
    {
      site: "issueReportingCredential",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "CONSTRAINT",
      covering:
        "same lifecycle-heads PRIMARY KEY. The `current_key_id` pre-read is OUTSIDE this " +
        "transaction, so the constraint — not the read — is what decides a concurrent issue.",
      pinned: "one pool client, BEGIN → insertFirstKeyLifecycle → COMMIT",
    },
  ],
  "apps/generic-node/src/db/client.ts": [
    {
      site: "withPostgresDeadline",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "NONE",
      covering:
        "the /metrics collector's deadline-bounded read wrapper: advisory reads under a " +
        "monotonic budget. Issues no money write of any kind.",
      pinned: "one client for the whole budget; released only after COMMIT/ROLLBACK settles",
    },
  ],
  "apps/generic-node/src/db/migrate.ts": [
    {
      site: "poolClientMigrationExecutor.transaction",
      pathClass: "money-path",
      // The literal is `BEGIN ISOLATION LEVEL ${isolation}`, so the level is not statically
      // provable here; it is supplied by the one caller. Declared rather than pattern-matched.
      isolation: "READ COMMITTED",
      mechanism: "SERIALIZABLE",
      covering:
        "`any schema migration` is money-path by CONVENTIONS.md §1. The level comes from " +
        "node-core `runMigrations`, which passes MONEY_PATH_ISOLATION = 'SERIALIZABLE' " +
        "(data/migrations.ts:42,286) and already wraps each migration in " +
        "withSerializationRetry (data/migrations.ts:283).",
      pinned:
        "the pinned client already holds the migrator advisory lock, so pack DDL cannot race " +
        "a peer boot's apply",
    },
  ],
  "apps/generic-node/src/dr/auth-hold.ts": [
    {
      site: "applyForceAuthHoldAfterRestore",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "appends AUTH_HOLD_SET to the append-only reporting lifecycle chain and advances the " +
        "head via `SELECT reporting_advance_lifecycle_head($1::uuid)` (auth-hold.ts:212,379), " +
        "whose body locks the head row `FOR UPDATE` " +
        "(schema/reporting-persistence.sql:935,942).",
      pinned:
        "withConnectedPgClient hands one dedicated (non-pool) client through BEGIN → COMMIT",
    },
    {
      site: "releaseDualGatesWithTrustedMarkers",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "locks reporting_restore_state, every node lifecycle head, and the node nonce-burn " +
        "counter before deriving the live continuity snapshot; then appends AUTH_HOLD_RELEASED " +
        "events, advances each canonical head, and clears restore_hold in the same transaction.",
      pinned:
        "withConnectedPgClient supplies one dedicated client for evidence derivation, all " +
        "lifecycle writes, restore-hold release, and COMMIT",
    },
    {
      site: "applyDualGateForceAfterRestore",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "same advance function under the same FOR UPDATE, for both halves of the dual gate — " +
        "restore_hold and auth_hold either both commit or neither does.",
      pinned: "withConnectedPgClient, one client for both halves",
    },
  ],
  "apps/generic-node/src/dr/encrypted-backup.ts": [
    {
      site: "exportEncryptedBackupBoundToContinuity",
      pathClass: "other",
      isolation: "REPEATABLE READ",
      mechanism: "NONE",
      covering:
        "read-only REPEATABLE READ holds one backend snapshot for deriveContinuitySnapshotOnClient " +
        "+ pg_export_snapshot + pg_dump --snapshot so marker values equal the sealed dump " +
        "(ZTR-1136 Review B D1). No money mutation; ROLLBACK ends the holder.",
      pinned:
        "withConnectedPgClient one dedicated client; dump child uses exported snapshot id " +
        "while the holder TX remains open",
    },
  ],
  "apps/generic-node/src/main.ts": [
    {
      site: "withPgTransaction (shared by the RECEIVE and MOVE admission stores)",
      pathClass: "money-path",
      // One BEGIN, two consumers, two different mechanisms. `mechanism` carries a single
      // token and holds the RECEIVE half's; the MOVE half is CONSTRAINT and is spelled out
      // below rather than generalised away (ZTR-1155 review D1).
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "TWO CONSUMERS, TWO MECHANISMS — read both before trusting the token above. " +
        "(1) RECEIVE / SqlReceiveAdmissionStore (main.ts:473-475) is ROW_LOCK: " +
        "`SELECT pg_advisory_xact_lock($1) AS locked` (receive/sql-store.ts:123 " +
        "LOCK_ADMISSION_QUEUE), issued as the first statement in the transaction " +
        "(receive/sql-store.ts:357), before the queue-cap read and the insert it decides. An " +
        "xact lock is released at COMMIT, never earlier. " +
        "(2) MOVE / SqlMoveCreateStore.insertAdmitted (main.ts:476-479, " +
        "move/sql-store.ts:311-367) is CONSTRAINT, NOT a lock: that half takes no row lock " +
        "and no advisory lock anywhere in the module. Its arbiter is the immediate unique " +
        "index on operations (implementer_id, kind, idempotency_key), reached as " +
        "`ON CONFLICT … DO NOTHING RETURNING` (move/sql-store.ts:86) — the loser gets zero " +
        "rows and returns IDEMPOTENCY_CONFLICT — plus the guarded `UPDATE lease_groups … " +
        "WHERE id = $1 AND child_disposition = 'PENDING'` (MARK_CHILD_JOINED, " +
        "move/sql-store.ts:98-100) for the receive-child group flip. " +
        "RULED, NOT PAPERED: the one-in-flight pre-check hasActiveLease " +
        "(move/sql-store.ts:303) reads wallet_active_leases on the POOL, outside this " +
        "transaction (move/create.ts:408,415), so the MOVE read-then-write straddles the " +
        "boundary. That is safe because the read is not the arbiter of anything: it exists " +
        "to return 409 wallet_busy on the public path (move/create.ts:405-421) and admission " +
        "writes NO row to wallet_active_leases. One-active-lease is decided structurally by " +
        "`wallet_active_leases.wallet_id PRIMARY KEY` (schema/lease-foundation.sql:172) at " +
        "lease ACQUISITION, under LOCK_WALLET `FOR UPDATE` + SELECT_ACTIVE_FOR_UPDATE " +
        "(leases/repository.ts:111,372) inside the move-internal-worker.ts transaction — a " +
        "different site, classified below. Two racers that both pass the pre-check are both " +
        "admitted CREATED; the second loses at acquisition, never by double-leasing. Pulling " +
        "the read inside this transaction would not change that: READ COMMITTED with no lock " +
        "on wallet_active_leases has the same interleaving.",
      pinned: "pool.connect() → BEGIN → fn(tx) → COMMIT; every statement on that one client",
    },
    {
      site: "runBootRecovery withTx (ensureActiveNodeSigningKey)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SELECT pg_advisory_xact_lock($1::integer, $2::integer)` per (node, purpose) " +
        "(signing-keys/ensure.ts:121), taken before the active-row read that decides whether " +
        "to mint. Persists signing keys — money-path by the `persisting a signature` clause.",
      pinned: "pool.connect() → BEGIN → work(sql) → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/money-workers/genesis-t0-observer.ts": [
    {
      site: "captureGenesisObservation",
      pathClass: "money-path",
      isolation: "SERIALIZABLE",
      mechanism: "SERIALIZABLE",
      covering:
        "ZTR-1155: the one money-path site with no covering lock — an unlocked " +
        "`max(wallet_seq)` read-then-INSERT. Raised to SERIALIZABLE and wrapped in " +
        "withSerializationRetry under DEFAULT_SERIALIZATION_RETRY_POLICY. Body is DB-only and " +
        "re-runnable: no gateway call, no chain submit, every id minted inside.",
      pinned: "pool.connect() → BEGIN → … → COMMIT, one client per attempt",
    },
  ],
  "apps/generic-node/src/money-workers/move-advanced-ports.ts": [
    {
      site: "MOVE landing persist (CAS + event append + settled ledger)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`lockNextEventSeq` (move-advanced-ports.ts:209-215) takes node_event_seq_counters " +
        "`FOR UPDATE OF c` via LOCK_EVENT_SEQ_COUNTER_SQL (move-advanced-ports.ts:190-196) " +
        "for the whole transaction — this module mirrors event-log/pg-event-store.ts's " +
        "counter SQL but deliberately does not import it (its own note at :179), so the lock " +
        "to read is the local one. persistMoveOutcome " +
        "lands under a `row_version` CAS on operations. Deliberately NOT wrapped in a retry: " +
        "signWithNodeIdentity runs inside this body, so the row-lock arm is the right one.",
      pinned: "pool.connect() → BEGIN; createSqlQueryFn(client) carries every later statement",
    },
  ],
  "apps/generic-node/src/money-workers/move-internal-worker.ts": [
    {
      site: "withTransaction (acquireMoveLeases)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SELECT id AS wallet_id, state FROM wallets WHERE id = $1 FOR UPDATE` " +
        "(leases/statements.ts:5 LOCK_WALLET) plus the group / membership / active-row " +
        "FOR UPDATE statements in the same file — takes a wallet lease, so money-path.",
      pinned: "pool.connect() → BEGIN → fn(tx) → COMMIT; the MoveLeaseTxFn wraps this factory",
    },
  ],
  "apps/generic-node/src/money-workers/receive-child-handoff-step.ts": [
    {
      site: "withTransaction (createChildMoveWithContinuousSourceTransfer)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "CONSTRAINT",
      covering:
        "`operations_one_spawn_per_parent_uidx` is the sole arbiter of concurrent spawn " +
        "races, reached as `ON CONFLICT (spawned_from_operation_id) … DO NOTHING RETURNING` " +
        "(move/child-create-sql.ts:65, and its stated rule at move/child-create.ts:112). The " +
        "source-lease transfer runs on the SAME tx under the lease statements' FOR UPDATE, so " +
        "child insert and lease move roll back together.",
      pinned:
        "pool.connect() → BEGIN → fn(client) → COMMIT; the nested store re-enters with " +
        "`withTransaction: async (body) => body(tx)` rather than opening a second BEGIN",
    },
  ],
  "apps/generic-node/src/money-workers/receive-landing-step.ts": [
    {
      site: "setAttentionForIndeterminate",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "atomic CTE CAS `operations.attention_required false→true` with closed-set reason " +
        "plus insert into receive_expiry_attention_events; concurrent loser matches zero " +
        "rows (idempotent). dual-chain operation.needs_attention appends on the same client " +
        "when the CAS wins (ZTR-1146).",
      pinned:
        "pool.connect() → BEGIN → CAS+mirror → appendDurableDualChainEvent → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/money-workers/send-completion-lander.ts": [
    {
      site: "parkSendOnHeadAnomaly",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION` is a guarded " +
        "`UPDATE … WHERE status = 'AWAITING_REDEMPTION' … RETURNING`: the UPDATE takes the " +
        "row lock and re-evaluates its predicate against the committed row, so a concurrent " +
        "loser returns zero rows and this path ROLLBACKs. The operations mirror sync runs in " +
        "the same transaction.",
      pinned:
        "pool.connect() → BEGIN → CAS → mirror → appendDurableDualChainEvent → COMMIT on one " +
        "client (ZTR-1146 park dual-chain)",
    },
  ],
  "apps/generic-node/src/money-workers/send-signer-deps.ts": [
    {
      site: "createSqlSignUnderLeaseTransaction",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SELECT … FROM wallet_active_leases WHERE wallet_id = $1::uuid … FOR UPDATE` " +
        "(send-signer-deps.ts SELECT_ACTIVE_LEASE_FOR_UPDATE) — held open across " +
        "vaultSigner.sign and signer_audit SIGNED append inside signUnderLease " +
        "(signer-boundary.ts). Persists a signature under a wallet lease, hence money-path. " +
        "ROW_LOCK (not SERIALIZABLE): the vault unseal is non-DB work, so " +
        "withSerializationRetry is forbidden (CONVENTIONS.md §1.1 / §2). ZTR-1160.",
      pinned:
        "pool.connect() → BEGIN → applyMoneyPathStatementTimeout → body(txPorts) → COMMIT; " +
        "leaseReader + auditLog both route through the same PoolClient",
    },
  ],
  "apps/generic-node/src/money-workers/send-sql-ports.ts": [
    {
      site: "withPoolTransaction (claim / source lease / sign intent / partial)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`CLAIM_AND_OBSERVE_SQL.CLAIM_APPROVED_SEND_OPERATION` carries `FOR UPDATE OF o` " +
        "(send/claim-and-observe.ts:392) so the APPROVED claim serialises on the operations " +
        "row; the source-lease port runs the leases/statements.ts FOR UPDATE set on the same " +
        "transaction.",
      pinned: "pool.connect() → BEGIN → fn(tx) → COMMIT; all four ports share this one factory",
    },
    {
      site: "createSqlExternalSendLandingStore.commitLanding",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "node-core's SqlExternalSendLandingStore runs its guarded status CAS and event " +
        "append on this client (pass-through withTransaction, never a nested BEGIN); the " +
        "event-seq allocation holds node_event_seq_counters FOR UPDATE. The settled-ledger " +
        "row, lineage path and access window all land in the same transaction.",
      pinned:
        "pool.connect() → BEGIN; the inner store is constructed with a withTransaction that " +
        "hands back this client verbatim",
    },
  ],
  "apps/generic-node/src/money-workers/sql-observation-persistence.ts": [
    {
      site: "persistSqlObservation",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "same serialized stream writer path as gateway-t0-observer — observation row, " +
        "paired anomaly, quarantine/attention plan and cursor commit share one client; " +
        "advisory/row locks taken by the stream writer are held to COMMIT.",
      pinned:
        "pool.connect() → BEGIN → applyMoneyPathStatementTimeout → effects → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/money-workers/sql-landing-store.ts": [
    {
      site: "createSqlReceiveLandingStore.commitLanding",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "node-core's SqlReceiveLandingStore runs its guarded status CAS, proof-header insert " +
        "and ordered path inserts on this client; the deferred completeness triggers fire at " +
        "THIS COMMIT. Event-seq allocation holds node_event_seq_counters FOR UPDATE.",
      pinned:
        "pool.connect() → BEGIN; the inner store's withTransaction is a pass-through, so its " +
        "`one transaction` contract is satisfied by this client",
    },
  ],
  "apps/generic-node/src/money-workers/start-money-workers.ts": [
    {
      site: "withTransaction (scale-up / assign / commitReceiveReady / queue expiry)",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "FOUR CALLERS, each with its own cover (ZTR-1155 review D2 — the earlier text cited " +
        "pool-allocator.ts:221 LOCK_ADMISSION_QUEUE, which only admitReceive takes and which " +
        "no caller of THIS factory reaches). " +
        "(1) runPoolScaleUp (:1020): `pg_advisory_xact_lock` LOCK_SCALE_UP " +
        "(receive/pool-scaler.ts:98), taken before every count it reads. " +
        "(2) assignReceiveWallet (:1045): `FOR UPDATE SKIP LOCKED` / `FOR UPDATE` on the " +
        "candidate wallet (receive/pool-allocator.ts:130,150). " +
        "(3) commitReceiveReady (:597): the guarded CAS_CREATED_TO_READY " +
        "`UPDATE operations … WHERE status = 'CREATED' AND row_version = $2 AND EXISTS " +
        "(wallet_active_leases … lease_epoch = $3) … RETURNING` " +
        "(receive/code-ready-commit.ts:80-98) — zero rows for a concurrent loser. " +
        "(4) expireQueueAgedReceives (:1065): the guarded EXPIRE_QUEUE_AGED_RECEIVE " +
        "`UPDATE operations … WHERE status = 'CREATED' … ` (receive/pool-scaler.ts:212), " +
        "which restates the queued predicate so an assigner that already won matches zero " +
        "rows (receive/pool-scaler.ts:446-448).",
      pinned:
        "pool.connect() → BEGIN → fn(tx) → COMMIT on one client per call. emitExpired " +
        "(start-money-workers.ts) now routes the receive_operations mirror UPDATE and " +
        "appendDurableDualChainEvent through the same `db` TX client handed by " +
        "expireQueueAgedReceives (ZTR-1146) — no second-pool autocommit tear.",
    },
    {
      site: "runReceiveExpiryReleaseStep (SqlReceiveExpiryReleaseService)",
      pathClass: "money-path",
      isolation: "SERIALIZABLE",
      mechanism: "SERIALIZABLE",
      covering:
        "releases a wallet lease and mints a release proof. Already SERIALIZABLE; ZTR-1155 " +
        "added the missing withSerializationRetry — 40001 is only reachable once the level is " +
        "raised, and it was surfacing as a tick error. The retried body is DB-only: the " +
        "gateway fresh-head read (ZTR-1251) runs before expire() and passes an observation " +
        "id in; no gateway read and no chain submit occur inside the SERIALIZABLE body " +
        "(sql-recovery-store RELEASE_EXPIRED_RECEIVE uses the same pre-BEGIN pattern).",
      pinned: "pool.connect() → BEGIN → fn(tx) → COMMIT inside each retry attempt",
    },
  ],
  "apps/generic-node/src/operations/arm-wallet-gate.ts": [
    {
      site: "createPoolArmTxFactory",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`FROM wallets WHERE id = $1::uuid FOR UPDATE` (receive/arm-sql.ts:60) and " +
        "`WHERE o.id = $1::uuid FOR UPDATE OF o, c` (receive/arm-sql.ts:75) — the receiver " +
        "wallet row is held across the standing recheck and the RECEIVE_WINDOW lease insert.",
      pinned:
        "documented in-source at arm-wallet-gate.ts:29-30 and asserted by " +
        "arm-wallet-gate.test.ts, which proves BEGIN → body → COMMIT on one pinned client",
    },
  ],
  "apps/generic-node/src/operations/sql-operator-park-store.ts": [
    {
      site: "createSqlOperatorParkStore.commitPark",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SQL_LOCK … FOR UPDATE` on operations, taken as the FIRST statement so " +
        "not-found / already-flagged / conflict are all decided under the lock. Appends to " +
        "audit_log, an append-only authoritative table, hence money-path.",
      pinned: "pool.connect() → BEGIN → lock → CAS park → audit insert → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/operations/sql-attention-retraction-store.ts": [
    {
      site: "createSqlAttentionRetractionStore.commit",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SQL_LOCK_OPERATION … FOR UPDATE` on operations, taken as the FIRST statement so " +
        "not-found / not-flagged / conflict are all decided under the lock. Appends to " +
        "audit_log, an append-only authoritative table, hence money-path.",
      pinned: "pool.connect() → BEGIN → lock → CAS → audit insert → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/operations/sql-recovery-store.ts": [
    {
      site: "issueRecoveryNonce",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "CONSTRAINT",
      covering:
        "issues a single-use recovery nonce: no ZKZ amount, no lease, no signature, no byte " +
        "ledger. The immediate non-deferrable partial unique index on " +
        "recovery_nonces (operation_id) WHERE status = 'ISSUED' decides concurrent issues; " +
        "the supersede-then-insert ordering inside the one transaction is what that index " +
        "requires.",
      pinned: "pool.connect() → BEGIN → supersede → insert → COMMIT on one client",
    },
    {
      site: "applyRecoveryAction (withSerializationRetry)",
      pathClass: "money-path",
      isolation: "SERIALIZABLE",
      mechanism: "SERIALIZABLE",
      covering:
        "the pre-existing reference implementation: SERIALIZABLE inside " +
        "withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY). Route A keeps the " +
        "confirm-read (a gateway call) pre-BEGIN so the retried body stays DB-only.",
      pinned: "pool.connect() → BEGIN inside the retried body; one client per attempt",
    },
  ],
  "apps/generic-node/src/operations/verification-complete-store.ts": [
    {
      site: "createPoolVerificationCompleteTxFactory",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SELECT child_disposition FROM lease_groups WHERE id = $1 FOR UPDATE` " +
        "(verification/acknowledgement-sql.ts:139) plus the lease-release FOR UPDATE " +
        "statements — releases a wallet lease, hence money-path.",
      pinned:
        "documented in-source at verification-complete-store.ts:315-318; the factory preserves " +
        "rowCount because releaseLease fails closed without it",
    },
  ],
  "apps/generic-node/src/ops/atomic-admin-mutation.ts": [
    {
      site: "createAtomicAdminMutationExecutor",
      pathClass: "money-path",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))` keyed on " +
        "(node, route, idempotency key), taken as the first statement after BEGIN, so a " +
        "same-key loser waits and re-checks before auth/TOTP rather than running the effect " +
        "twice.",
      pinned:
        "one client owns the lock, the route child effect and the exact response row; the " +
        "xact lock releases only at COMMIT",
    },
  ],
  "apps/generic-node/src/ops/sql-restored-instance.ts": [
    {
      site: "restore (throwaway DR instance)",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "NONE",
      covering:
        "loads a backup archive into a throwaway database that is dropped on destroy — not " +
        "the live money path. The recovery ceremony is single-writer by construction and " +
        "aborts on any restore failure, and every insert is ON CONFLICT DO NOTHING.",
      pinned: "one client for the all-or-nothing load",
    },
  ],
  "apps/generic-node/src/reporting/durable-security-ports.ts": [
    {
      site: "createPoolSqlTransactionRunner (SqlProofBodyStore)",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "ROW_LOCK",
      covering:
        "SqlProofBodyStore persists CANDIDATE evidence and is explicitly non-authority " +
        "(proof-body/sql-store.ts): no statement sets a verdict, records a landing, or " +
        "releases a lease. Inside the TX, persistProofBody → lockPathProofId issues " +
        "`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))` keyed on " +
        "path_proof_id (STATEMENTS.ADVISORY_LOCK_PATH_PROOF) before cap-read / insert / " +
        "increment, serializing concurrent same-path_proof_id persists (ZTR-1211). " +
        "Per-tenant / idempotency-tuple residuals remain documented soft bounds.",
      pinned: "pool.connect() → BEGIN → body(sql) → COMMIT on one client",
    },
  ],
  "apps/generic-node/src/reporting/durable-store.ts": [
    {
      site: "createPoolReportingClient.transact",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "CONSTRAINT",
      covering:
        "reporting request idempotency / nonce burn. " +
        "reporting_mutation_idempotency.reporting_nonce_id and .child_record_id are both " +
        "UNIQUE (schema/reporting-persistence.sql:829-830); the store rethrows the benign " +
        "CONFLICT as a sentinel so this runner ROLLBACKs. Non-authoritative reporting, not " +
        "the money path.",
      pinned: "pool.connect() → BEGIN → body(q) → COMMIT; the driver error is propagated verbatim",
    },
  ],
  "apps/generic-node/src/reporting/live-reporting-reads.ts": [
    {
      site: "poolTx (list / stream / snapshot reads)",
      pathClass: "other",
      isolation: "READ COMMITTED",
      mechanism: "NONE",
      covering:
        "read-only reporting engines — a consistent read snapshot, no write. `Other` by the " +
        "convention's own `advisory reads, non-authoritative observation reporting` row.",
      pinned: "pool.connect() → BEGIN → body(query) → COMMIT on one client",
    },
  ],
};

interface MeasuredSite {
  readonly file: string;
  readonly line: number;
  readonly text: string;
}

function listProductionTsFiles(): string[] {
  const files: string[] = [];
  for (const tree of TREES) {
    const dir = resolve(repoRoot, tree);
    for (const entry of readdirSync(dir, { recursive: true }) as string[]) {
      const file = join(dir, entry);
      if (extname(file) !== ".ts" || !statSync(file).isFile()) continue;
      if (file.endsWith(".test.ts")) continue;
      files.push(file);
    }
  }
  return files.sort();
}

/** The exact literal that raises the level; the retry obligation keys off this string. */
const SERIALIZABLE_BEGIN = "BEGIN ISOLATION LEVEL SERIALIZABLE";

/**
 * Both SQL spellings of a transaction start, CASE-SENSITIVE on purpose.
 *
 * PostgreSQL also accepts lowercase `begin`, and matching it would be a strictly wider net —
 * except that `admin-readiness.ts:130` carries the redaction literal `"begin private"`, which
 * a case-insensitive matcher turns into a phantom census site. Neither tree contains a
 * lowercase or mixed-case SQL opener (verified by both ZTR-1155 reviewers across five trees),
 * so the case-sensitive form is exact here; if one ever lands, this is the line that must
 * widen and exclude that literal.
 */
const TRANSACTION_OPENER = /^(BEGIN|START\s+TRANSACTION)\b/;

/**
 * Every transaction-start literal in one source: any string or template literal whose text
 * starts with `BEGIN`. PARSED rather than regex-matched over raw source, for the reason the
 * sibling reach census gives — a regex has anchors that a comment or a newline slips past,
 * and a silently dropped site is exactly how this gate would go vacuous.
 */
export function beginLiterals(source: string, fileLabel = "<inline>"): readonly MeasuredSite[] {
  const parsed = ts.createSourceFile(fileLabel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const found: MeasuredSite[] = [];
  const record = (node: ts.Node, text: string): void => {
    if (!TRANSACTION_OPENER.test(text)) return;
    found.push({
      file: fileLabel,
      line: parsed.getLineAndCharacterOfPosition(node.getStart(parsed)).line + 1,
      text,
    });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node)) {
      record(node, node.text);
    } else if (ts.isTemplateExpression(node)) {
      // `BEGIN ISOLATION LEVEL ${isolation}` — the level is not statically known, so the raw
      // text is carried through and the entry must declare what the caller supplies.
      record(node, node.getText(parsed).slice(1, -1));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(parsed, visit);
  return found;
}

/**
 * Real `withSerializationRetry(<policy>, …)` CALL sites in one source.
 *
 * AST, not `String.includes`. The substring form this replaces was satisfied by a comment
 * mentioning the identifier while the actual call and both imports were deleted — proven by
 * mutation in the ZTR-1155 review (Probe D), with census, eslint and tsc all green. A
 * `CallExpression` cannot be written in a comment.
 *
 * `policy` pins the first argument to one identifier (`CONVENTIONS.md` §2: one fixed policy,
 * not a second one). Pass `null` where the policy is a parameter, as it is in node-core's
 * `runMigrations`.
 */
export function serializationRetryCalls(
  source: string,
  fileLabel = "<inline>",
  policy: string | null = "DEFAULT_SERIALIZATION_RETRY_POLICY",
): number {
  const parsed = ts.createSourceFile(fileLabel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let calls = 0;
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "withSerializationRetry" &&
      node.arguments.length >= 2
    ) {
      const first = node.arguments[0];
      if (policy === null || (first !== undefined && ts.isIdentifier(first) && first.text === policy)) {
        calls += 1;
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(parsed, visit);
  return calls;
}

function measureSites(): readonly MeasuredSite[] {
  const sites: MeasuredSite[] = [];
  for (const file of listProductionTsFiles()) {
    const source = readFileSync(file, "utf8");
    if (!source.includes("BEGIN")) continue;
    sites.push(
      ...beginLiterals(source, relative(repoRoot, file)).map((site) => ({
        ...site,
        file: relative(repoRoot, file),
      })),
    );
  }
  return sites;
}

describe("transaction isolation census (CONVENTIONS.md §1)", () => {
  const measured = measureSites();
  const byFile = new Map<string, MeasuredSite[]>();
  for (const site of measured) {
    const list = byFile.get(site.file);
    if (list === undefined) byFile.set(site.file, [site]);
    else list.push(site);
  }

  it("every module opening a transaction is declared (census)", () => {
    // The load-bearing assertion. A new BEGIN in an undeclared module enters the computed
    // side and reddens; a scanner that stops seeing a tree empties it and reddens too.
    expect(
      [...byFile.keys()].sort(),
      "a module opens a transaction without an isolation classification — add it to TRANSACTION_SITES",
    ).toEqual(Object.keys(TRANSACTION_SITES).sort());
  });

  it("every transaction in a declared module is itself declared, in source order", () => {
    for (const [file, sites] of byFile) {
      const declared = TRANSACTION_SITES[file] ?? [];
      expect(
        sites.length,
        `${file} opens ${sites.length} transaction(s) but declares ${declared.length}: ` +
          sites.map((s) => `${s.line}:${s.text}`).join(", "),
      ).toBe(declared.length);
    }
  });

  it("a declared SERIALIZABLE matches the source, and an undeclared one is caught", () => {
    // Both directions. Claiming SERIALIZABLE without setting it is the failure that would
    // make every other row in the table untrustworthy.
    for (const [file, sites] of byFile) {
      const declared = TRANSACTION_SITES[file] ?? [];
      sites.forEach((site, index) => {
        const entry = declared[index];
        if (entry === undefined) return; // count assertion above already reddened
        const setsSerializable = site.text === "BEGIN ISOLATION LEVEL SERIALIZABLE";
        const setsRepeatableRead = /\bREPEATABLE\s+READ\b/i.test(site.text);
        expect(
          entry.isolation === "SERIALIZABLE",
          `${file}:${site.line} declares isolation=${entry.isolation} but the source says ${site.text}`,
        ).toBe(setsSerializable);
        if (setsRepeatableRead) {
          expect(
            entry.isolation,
            `${file}:${site.line} source sets REPEATABLE READ but declares ${entry.isolation}`,
          ).toBe("REPEATABLE READ");
        }
        if (entry.isolation === "REPEATABLE READ") {
          expect(
            setsRepeatableRead,
            `${file}:${site.line} declares REPEATABLE READ but source is ${site.text}`,
          ).toBe(true);
        }
      });
    }
  });

  it("every money-path transaction names a mechanism, a covering statement and its pinning", () => {
    // The substance of CONVENTIONS.md §1: SERIALIZABLE, or a lock held for the whole
    // transaction on a pinned client. `NONE` is reserved for `other`.
    for (const [file, entries] of Object.entries(TRANSACTION_SITES)) {
      entries.forEach((entry, index) => {
        if (entry.pathClass !== "money-path") return;
        const where = `${file} [${index}] ${entry.site}`;
        expect(entry.mechanism, `${where}: a money-path transaction cannot have mechanism NONE`).not.toBe("NONE");
        expect(entry.covering.length, `${where}: money-path needs a covering statement`).toBeGreaterThan(40);
        expect(entry.pinned.length, `${where}: money-path needs pinned-client evidence`).toBeGreaterThan(10);
      });
    }
  });

  it("a source-level SERIALIZABLE carries the retry, whatever mechanism its row declares", () => {
    // `CONVENTIONS.md` §2: raising the level makes 40001 reachable, so the retry is not
    // optional.
    //
    // The requirement is keyed off the MEASURED SOURCE, never off `entry.mechanism`. Keying it
    // on the declared field made the rule opt-in: a site could open
    // `BEGIN ISOLATION LEVEL SERIALIZABLE`, declare `mechanism: "ROW_LOCK"`, carry no retry,
    // and pass — which is exactly the defect this gate exists to catch (ZTR-1155 review,
    // Probe C).
    const RETRIED_BY_CALLER = "apps/generic-node/src/db/migrate.ts";
    const opensSerializable = [
      ...new Set(measured.filter((s) => s.text === SERIALIZABLE_BEGIN).map((s) => s.file)),
    ].sort();
    // Non-vacuity: if the scanner ever stops seeing SERIALIZABLE literals the loop below
    // becomes a no-op, so the set is floored before it is walked.
    expect(opensSerializable.length, "no source-level SERIALIZABLE site found — scanner broken?").toBeGreaterThanOrEqual(3);
    for (const file of opensSerializable) {
      const text = readFileSync(resolve(repoRoot, file), "utf8");
      expect(
        serializationRetryCalls(text, file),
        `${file} opens ${SERIALIZABLE_BEGIN} but issues no ` +
          `withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, …) call`,
      ).toBeGreaterThan(0);
    }
    // The declared side, both directions: `mechanism: "SERIALIZABLE"` is claimable only where
    // the source raises the level, or in migrate.ts where the level is a parameter and the
    // one caller (node-core runMigrations) supplies both the level and the retry.
    const declaredSerializable = Object.entries(TRANSACTION_SITES)
      .filter(([, entries]) => entries.some((entry) => entry.mechanism === "SERIALIZABLE"))
      .map(([file]) => file)
      .sort();
    expect(declaredSerializable).toEqual([...opensSerializable, RETRIED_BY_CALLER].sort());
    // migrate.ts passes the level through; runMigrations supplies SERIALIZABLE and the retry.
    const migrations = readFileSync(
      resolve(repoRoot, "packages/node-core/src/data/migrations.ts"),
      "utf8",
    );
    expect(
      serializationRetryCalls(migrations, "packages/node-core/src/data/migrations.ts", null),
      "runMigrations is migrate.ts's retry — it must be a real call, not a mention",
    ).toBeGreaterThan(0);
    expect(migrations).toContain('MONEY_PATH_ISOLATION: TransactionIsolationLevel = "SERIALIZABLE"');
    expect(migrations).toContain("executor.transaction(MONEY_PATH_ISOLATION");
    expect(readFileSync(resolve(repoRoot, RETRIED_BY_CALLER), "utf8")).toContain(
      "BEGIN ISOLATION LEVEL ${isolation}",
    );
    // The frozen policy values themselves.
    expect(migrations).toContain("maxAttempts: 5");
    expect(migrations).toContain("baseDelayMs: 25");
    expect(migrations).toContain("maxDelayMs: 1000");
  });

  it("the census is not vacuous: both trees scanned, and the known site count holds", () => {
    const files = listProductionTsFiles();
    expect(files.filter((f) => f.includes("apps/generic-node/src")).length).toBeGreaterThan(40);
    expect(files.filter((f) => f.includes("packages/node-core/src")).length).toBeGreaterThan(300);
    // 30 when ZTR-1155 measured it. A floor, so an added-and-declared site does not redden
    // this line as well as the census above.
    expect(measured.length).toBeGreaterThanOrEqual(30);
    expect(measured.filter((s) => s.text === "BEGIN ISOLATION LEVEL SERIALIZABLE").length).toBeGreaterThanOrEqual(3);
    expect(Object.values(TRANSACTION_SITES).flat().filter((e) => e.pathClass === "money-path").length)
      .toBeGreaterThanOrEqual(20);
  });

  it("predicate proof: a new BEGIN is found however it is spelled, and DDL BEGIN is not", () => {
    // Unreachable on a healthy tree, so a mutation weakening the extractor would survive
    // every assertion above. Driven on synthetic sources instead.
    expect(beginLiterals('await client.query("BEGIN");').map((s) => s.text)).toEqual(["BEGIN"]);
    expect(beginLiterals("await client.query(`BEGIN`);").map((s) => s.text)).toEqual(["BEGIN"]);
    expect(beginLiterals('await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");').map((s) => s.text)).toEqual([
      "BEGIN ISOLATION LEVEL SERIALIZABLE",
    ]);
    // Parked in a constant and issued through an indirection — a call-shape-keyed check
    // would miss this entirely, which is why the literal is what is measured.
    expect(beginLiterals('const START = "BEGIN"; await run(START);').map((s) => s.text)).toEqual(["BEGIN"]);
    expect(beginLiterals("await client.query(`BEGIN ISOLATION LEVEL ${level}`);").map((s) => s.text)).toEqual([
      "BEGIN ISOLATION LEVEL ${level}",
    ]);
    // plpgsql: the literal starts with CREATE, so the function body's BEGIN is not a
    // transaction start and must not be demanded a classification.
    expect(beginLiterals('const f = "CREATE FUNCTION f() AS $$\\nBEGIN\\n  RETURN 1;\\nEND\\n$$;";')).toEqual([]);
    // A comment mentioning BEGIN is not a site.
    expect(beginLiterals("// we BEGIN here\nconst x = 1;")).toEqual([]);
    // Nor is a word that merely starts with the same letters.
    expect(beginLiterals('const x = "BEGINNING";')).toEqual([]);
    // The other SQL spelling. Neither tree uses it today; the matcher covers it so landing
    // one does not open an unclassified transaction.
    expect(beginLiterals('await client.query("START TRANSACTION ISOLATION LEVEL SERIALIZABLE");').map((s) => s.text)).toEqual([
      "START TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    ]);
    // Case-sensitive by design: admin-readiness.ts's `"begin private"` redaction literal must
    // not become a phantom site. Documented at TRANSACTION_OPENER.
    expect(beginLiterals('const x = "begin private";')).toEqual([]);
  });

  it("predicate proof: the retry check sees a call and not a comment naming it", () => {
    // The rule that stops Probe D — a comment mentioning the identifier used to satisfy the
    // old `String.includes` check with the real call and both imports deleted.
    const call = "await withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, async () => run());";
    expect(serializationRetryCalls(call)).toBe(1);
    expect(
      serializationRetryCalls("// was: withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, ...) — refactored away\nawait run();"),
    ).toBe(0);
    expect(serializationRetryCalls('const doc = "withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, x)";')).toBe(0);
    // A second, non-frozen policy is not the §2 policy.
    expect(serializationRetryCalls("await withSerializationRetry(MY_OWN_POLICY, async () => run());")).toBe(0);
    // …unless the caller is the one where the policy is a parameter (runMigrations).
    expect(serializationRetryCalls("await withSerializationRetry(policy, async () => run());", "<inline>", null)).toBe(1);
  });

  it("predicate proof: the money-path rule rejects a mechanism-less money-path entry", () => {
    // The rule the fourth test applies, driven on a synthetic table so it is a live rule
    // rather than a restatement of today's data.
    const check = (entry: TransactionSite): boolean =>
      entry.pathClass !== "money-path" || (entry.mechanism !== "NONE" && entry.covering.length > 40);
    const base = {
      site: "synthetic",
      isolation: "READ COMMITTED",
      pinned: "one pinned client",
    } as const;
    expect(check({ ...base, pathClass: "money-path", mechanism: "NONE", covering: "x".repeat(50) })).toBe(false);
    expect(check({ ...base, pathClass: "money-path", mechanism: "ROW_LOCK", covering: "too short" })).toBe(false);
    expect(check({ ...base, pathClass: "money-path", mechanism: "ROW_LOCK", covering: "x".repeat(50) })).toBe(true);
    expect(check({ ...base, pathClass: "other", mechanism: "NONE", covering: "" })).toBe(true);
  });
});
