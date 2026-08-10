// Stores over the three frozen transaction-material tables. Frozen DDL:
// src/schema/transaction-material.sql; inventory: src/schema/transaction-material.contract.ts.
// These hold the exact SplitChain transaction material: artifacts are one per operation,
// this material is per attempt. The byte-exact signing rule (byte-exact JSON.stringify signing, never
// reformat) and 4 (never blind-retry) bind here.
//
// Engine-level BEFORE UPDATE/DELETE/TRUNCATE guards ship in
// transaction-material-byte-immutability.sql (pack append). This module still shapes every
// statement so each regime is a property of the statement set rather than of caller discipline:
//
// * external_send_sign_intents — insert-only. This module emits exactly one statement against
// it, an INSERT. There is no UPDATE or DELETE to call.
// * operation_transactions — insert, then one-way completion. Every advance carries
// `AND <target column> IS NULL` and `AND attempt_phase = <the immediately prior phase>` in
// its WHERE, so an overwrite of a persisted value matches zero rows and raises instead of
// silently rewriting a signed byte. Phase advance and its new columns commit in one UPDATE.
// * external_send_partials — byte-immutable except delivery. The single UPDATE's SET list is
// exactly the three delivery columns the frozen regime marks updatable; no statement here
// can reach transfer_code_text, step_1_signature, inner_sha256, transfer_code_sha256 or
// persisted_at after insert. test/transaction-material-store.test.ts asserts that against
// TRANSACTION_MATERIAL_MUTABILITY_REGIMES rather than against a hand-copied column list.
//
// Byte columns cross the driver seam as text and are bound as parameters, never interpolated
// and never parsed: nothing here calls JSON.parse or re-stringifies a preimage, so a stored
// preimage is the exact bytes the signer saw (the byte-exact signing rule). No database driver is linked (the
// package carries none, and the network guard forbids in-process sockets under test) —
// statements are handed to an injected SqlQueryFn, as submit-decision-claim-store.ts does.

import {
  ATTEMPT_PHASE_LADDER,
  type AttemptPhase,
  type TransactionMaterialFacts,
} from "./execution-phase.js";
import type { SqlQueryFn } from "./sql-query-fn.js";

/** `attempt_no integer NOT NULL CHECK (attempt_no = 1)` — structurally one attempt, ever. */
export const ONLY_ATTEMPT_NO = 1;

// ── external_send_sign_intents (insert-only) ────────────────────────────────────────────────

/**
 * `external_send_sign_intents` is insert-only and is created only after approval and
 * lease acquisition. It binds the consumed approval, both fresh T0 observations, lease
 * group/epoch, and exact preimage before the signer is called. The signer must present the same
 * lease group and epoch.
 */
export interface SignIntentRow {
  readonly operationId: string;
  readonly approvalId: string;
  readonly sourceWalletId: string;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: number;
  /** The exact bytes the signer will be handed. Stored verbatim; never parsed or re-serialized. */
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  /**
   * SEND_EXTERNAL expiry single-source: the derived, non-authoritative whole-second projection of the signed inner
   * `expiry__unix_time_secs`, parsed once at formation from the signed text. Set exactly once at
   * insert; the table is insert-only so no UPDATE path exists for it.
   */
  readonly redemptionExpiryAt: string;
  readonly preparedAt: string;
}

const SIGN_INTENT_INSERT = `INSERT INTO external_send_sign_intents
  (operation_id, approval_id, source_wallet_id, source_t0_observation_id,
   destination_t0_observation_id, lease_group_id, lease_epoch,
   inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz)
  RETURNING operation_id`;

/**
 * Persists the sign intent. A second intent for the same operation violates the primary key and
 * a second intent against the same approval violates `approval_id UNIQUE` — both raise, and
 * neither is retried here: there is no same-operation rebuild contract.
 */
export async function insertSignIntent(query: SqlQueryFn, row: SignIntentRow): Promise<void> {
  await query(SIGN_INTENT_INSERT, [
    row.operationId,
    row.approvalId,
    row.sourceWalletId,
    row.sourceT0ObservationId,
    row.destinationT0ObservationId,
    row.leaseGroupId,
    row.leaseEpoch,
    row.innerPreimageText,
    row.innerSha256,
    row.redemptionExpiryAt,
    row.preparedAt,
  ]);
}

// ── operation_transactions (insert, then one-way completion) ────────────────────────────────

/**
 * The columns each phase advance adds, read off the frozen phase CHECKs: each biconditional
 * pins one column to NULL up to a phase and to NOT NULL from it on. `INNER_PREIMAGE_PERSISTED`
 * is absent because it is an insert, not an advance. The union of these lists is asserted equal
 * to the frozen regime's `updatableColumns` in test/transaction-material-store.test.ts, so a
 * column added to the one-way set without a phase here is a red test rather than a column no
 * statement can ever fill.
 */
export const PHASE_ADDITIONS = {
  STEP1_SIGNATURE_PERSISTED: ["step_1_signature"],
  STEP2_PREIMAGE_PERSISTED: ["step_2_preimage_text", "step_2_preimage_sha256"],
  STEP2_SIGNATURE_PERSISTED: [
    "step_2_signature",
    "completed_transaction_text",
    "completed_transaction_sha256",
  ],
  SETTLED_BODY_PERSISTED: ["settled_at"],
} as const;

export type AdvancePhase = keyof typeof PHASE_ADDITIONS;

/** The value for each column the target phase adds, keyed by its exact column name. */
export type PhaseAdditionValues<P extends AdvancePhase> = {
  readonly [K in (typeof PHASE_ADDITIONS)[P][number]]: string;
};

// timestamptz columns need an explicit cast because values cross the seam as ISO-8601 text.
const TIMESTAMP_COLUMNS: readonly string[] = ["settled_at"];

const bindOf = (column: string, position: number): string =>
  TIMESTAMP_COLUMNS.includes(column) ? `$${position}::timestamptz` : `$${position}`;

/**
 * A RECEIVE attempt may be inserted at `STEP1_SIGNATURE_PERSISTED` with the payer's
 * step-1 signature already durable; a MOVE attempt starts at `INNER_PREIMAGE_PERSISTED` and
 * advances through all four formation phases in sequence.
 */
export interface AttemptInsertRow {
  readonly operationId: string;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly formedAt: string;
  /**
   * Present only for the RECEIVE insert-at-step-1 case. When null the row is inserted at
   * `INNER_PREIMAGE_PERSISTED`; when set, at `STEP1_SIGNATURE_PERSISTED`. The frozen
   * biconditional `(attempt_phase = 'INNER_PREIMAGE_PERSISTED') = (step_1_signature IS NULL)`
   * makes any other pairing a database rejection.
   */
  readonly payerStep1Signature?: string;
}

const ATTEMPT_INSERT = `INSERT INTO operation_transactions
  (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
   step_1_signature, formed_at)
  VALUES ($1, ${ONLY_ATTEMPT_NO}, $2, $3, $4, $5, $6::timestamptz)
  RETURNING operation_id, attempt_no, attempt_phase`;

/**
 * Persists the one transaction attempt. A second attempt for the same operation violates the
 * composite primary key and any `attempt_no <> 1` violates its CHECK, so
 * "exactly one attempt" is the database's verdict, not a check performed here.
 */
export async function insertTransactionAttempt(
  query: SqlQueryFn,
  row: AttemptInsertRow,
): Promise<AttemptPhase> {
  const payerStep1 = row.payerStep1Signature ?? null;
  const phase: AttemptPhase =
    payerStep1 === null ? "INNER_PREIMAGE_PERSISTED" : "STEP1_SIGNATURE_PERSISTED";
  await query(ATTEMPT_INSERT, [
    row.operationId,
    phase,
    row.innerPreimageText,
    row.innerSha256,
    payerStep1,
    row.formedAt,
  ]);
  return phase;
}

/**
 * The lease capability an advance that persists a signature must STILL hold as it commits
 * (the one-in-flight-per-wallet rule).
 *
 * The signer boundary already validated this exact tuple before the vault was opened, but that
 * read and this write are two statements on an autocommit seam: a proof-backed release
 * (leases/repository.ts `releaseLease`, or receive/expiry-release.ts) can commit in between, and
 * the signature would land under a lease the node no longer holds. Passing the tuple here
 * re-checks it under a row lock in the same statement that makes the signature durable, so the
 * release and the advance serialize — the release either blocks until this statement commits, or
 * wins outright and this advance matches zero rows and throws.
 *
 * `FOR SHARE` is load-bearing, not decorative: a plain `EXISTS` reads the pre-release snapshot
 * under READ COMMITTED and admits the very write this guard exists to refuse.
 */
export interface AttemptLeaseGuard {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
}

/**
 * Advances the one attempt to `toPhase`, filling exactly the columns that phase adds, in one
 * UPDATE: phase advancement and its newly populated columns commit atomically.
 *
 * The WHERE clause is the one-way guard. It requires the immediately prior ladder phase and
 * requires every target column to still be NULL, so a replay, a re-sign, or an out-of-sequence
 * advance updates zero rows and throws rather than overwriting a persisted signature or
 * preimage — rows are immutable after insertion except for the one-way additions, and
 * existing values can never be overwritten.
 *
 * `leaseGuard` extends that same all-or-nothing WHERE to the lease the signature was produced
 * under — see {@link AttemptLeaseGuard}. It is opt-in because only signature-bearing advances
 * need it: a preimage advance signs nothing, so it has no lease to lose.
 */
export async function advanceAttemptPhase<P extends AdvancePhase>(
  query: SqlQueryFn,
  operationId: string,
  toPhase: P,
  values: PhaseAdditionValues<P>,
  leaseGuard?: AttemptLeaseGuard,
): Promise<void> {
  const columns: readonly string[] = PHASE_ADDITIONS[toPhase];
  const priorPhase = ATTEMPT_PHASE_LADDER[ATTEMPT_PHASE_LADDER.indexOf(toPhase) - 1];
  // Positions 1..2 are the key and the prior phase; the added columns bind from 3 on.
  const sets = columns.map((column, index) => `${column} = ${bindOf(column, index + 3)}`);
  const stillNull = columns.map((column) => `${column} IS NULL`);
  // The lease tuple binds after the added columns. MATERIALIZED keeps the CTE from being
  // inlined into the UPDATE's WHERE, so the row lock is taken once, up front, rather than
  // wherever the planner happened to fold the EXISTS.
  const guardBind = columns.length + 3;
  const lockLease =
    leaseGuard === undefined
      ? ""
      : `WITH held_lease AS MATERIALIZED (
       SELECT 1 FROM wallet_active_leases
        WHERE wallet_id = $${guardBind}::uuid
          AND operation_id = $${guardBind + 1}::uuid
          AND lease_epoch = $${guardBind + 2}::bigint
        FOR SHARE
     )
     `;
  const leaseStillHeld = leaseGuard === undefined ? "" : "\n       AND EXISTS (SELECT 1 FROM held_lease)";
  const statement = `${lockLease}UPDATE operation_transactions
     SET attempt_phase = '${toPhase}', ${sets.join(", ")}
     WHERE operation_id = $1 AND attempt_no = ${ONLY_ATTEMPT_NO}
       AND attempt_phase = $2 AND ${stillNull.join(" AND ")}${leaseStillHeld}
     RETURNING attempt_phase`;

  const updated = await query(statement, [
    operationId,
    priorPhase,
    ...columns.map((column) => (values as Record<string, string>)[column]),
    ...(leaseGuard === undefined
      ? []
      : [leaseGuard.walletId, leaseGuard.operationId, leaseGuard.leaseEpoch.toString()]),
  ]);
  if (updated[0] === undefined) {
    // Fail closed. Either the attempt is not at `priorPhase`, or a target column already holds a
    // value, or (when guarded) the lease that authorised the signature is no longer held; all
    // mean the durable record disagrees with the caller, and re-reading to guess which would be
    // the blind retry the never-blind-retry rule forbids.
    throw new Error(
      `operation ${operationId} did not advance to ${toPhase}: the attempt is not at ${priorPhase} with ${columns.join(", ")} unset, and a persisted value is never overwritten${
        leaseGuard === undefined
          ? ""
          : `; the advance also requires wallet ${leaseGuard.walletId} to still hold this operation's lease at epoch ${leaseGuard.leaseEpoch}`
      }`,
    );
  }
}

// ── external_send_partials (byte-immutable except delivery) ─────────────────────────────────

/**
 * `external_send_partials` is also byte-immutable; recovery may update only delivery
 * timestamps/count. Delivery is forbidden until the partial row commits.
 */
export interface PartialRow {
  readonly operationId: string;
  readonly approvalId: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  /** The exact transfer-code text handed to the recipient. Stored verbatim. */
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly persistedAt: string;
}

const PARTIAL_INSERT = `INSERT INTO external_send_partials
  (operation_id, approval_id, inner_sha256, step_1_signature,
   transfer_code_text, transfer_code_sha256, persisted_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)
  RETURNING operation_id`;

/**
 * Exactly the three delivery columns the frozen regime marks updatable for this table, and
 * exactly the SET list of the one UPDATE below.
 *
 * Declared here rather than read from TRANSACTION_MATERIAL_MUTABILITY_REGIMES for the fence
 * reason given on ATTEMPT_PHASE_LADDER in ./execution-phase.ts — `core` may not import
 * `schema`. test/transaction-material-store.test.ts asserts this equal to that frozen
 * regime's `updatableColumns`, so a column added to or removed from the contract without a
 * matching change here is a red test.
 */
const PARTIAL_DELIVERY_COLUMNS: readonly string[] = [
  "first_delivered_at",
  "last_redelivered_at",
  "redelivery_count",
];

/**
 * First delivery stamps `first_delivered_at` and leaves the count at 0; every later delivery
 * stamps `last_redelivered_at` and increments. Both branches are one statement over the three
 * delivery columns — the byte columns are not in the SET list, so no sequence of calls can
 * touch a signed byte. `redelivery_count` only ever increases, honouring
 * `CHECK (redelivery_count >= 0)` without this code checking it.
 */
const PARTIAL_DELIVERY_UPDATE = `UPDATE external_send_partials SET
     first_delivered_at = coalesce(first_delivered_at, $2::timestamptz),
     last_redelivered_at =
       CASE WHEN first_delivered_at IS NULL THEN last_redelivered_at ELSE $2::timestamptz END,
     redelivery_count = redelivery_count + CASE WHEN first_delivered_at IS NULL THEN 0 ELSE 1 END
   WHERE operation_id = $1
   RETURNING redelivery_count`;

/**
 * Persists the partial. A second partial for the same operation violates the primary key and a
 * second partial against the same approval violates `approval_id UNIQUE` — a
 * persisted partial cannot be replaced, even after expiry or crash.
 */
export async function insertPartial(query: SqlQueryFn, row: PartialRow): Promise<void> {
  await query(PARTIAL_INSERT, [
    row.operationId,
    row.approvalId,
    row.innerSha256,
    row.step1Signature,
    row.transferCodeText,
    row.transferCodeSha256,
    row.persistedAt,
  ]);
}

/**
 * Records that the persisted partial was handed out, and returns the resulting redelivery count.
 * Raises when no partial row exists, because delivery is forbidden before the row commits.
 */
export async function recordPartialDelivery(
  query: SqlQueryFn,
  operationId: string,
  deliveredAt: string,
): Promise<number> {
  const updated = await query(PARTIAL_DELIVERY_UPDATE, [operationId, deliveredAt]);
  const row = updated[0];
  if (row === undefined) {
    throw new Error(
      `no persisted partial for operation ${operationId}: delivery is forbidden until the partial row commits`,
    );
  }
  return Number(row.redelivery_count);
}

/** The SET-list columns of the only UPDATE this module runs against the partial store. */
export const PARTIAL_UPDATABLE_COLUMNS = PARTIAL_DELIVERY_COLUMNS;

/** Every statement this module can execute, for the statement-surface assertions in the tests. */
export const TRANSACTION_MATERIAL_STATEMENTS = {
  SIGN_INTENT_INSERT,
  ATTEMPT_INSERT,
  PARTIAL_INSERT,
  PARTIAL_DELIVERY_UPDATE,
} as const;

// ── read-time facts ────────────────────────────────────────────────────────────────────────

/**
 * The tested read-time query behind the `execution_phase` derivation: the mapping is
 * derived at read time or by a tested database view; it is never an independently mutable
 * status column. One statement, three EXISTS/scalar subqueries over exactly the tables this
 * slice owns. The submit and verification facts the derivation also reads belong to other
 * schema slices and are supplied by the caller (see SubmitAndVerificationFacts).
 *
 * `LEFT JOIN`-free and row-shape-free on purpose: the result is one row of booleans and one
 * nullable phase, so the read never depends on an operation row existing.
 */
const FACTS_SELECT = `SELECT
    (SELECT attempt_phase FROM operation_transactions
       WHERE operation_id = $1 AND attempt_no = ${ONLY_ATTEMPT_NO}) AS attempt_phase,
    EXISTS (SELECT 1 FROM external_send_sign_intents WHERE operation_id = $1) AS sign_intent_persisted,
    EXISTS (SELECT 1 FROM external_send_partials WHERE operation_id = $1) AS partial_persisted,
    EXISTS (SELECT 1 FROM external_send_partials
       WHERE operation_id = $1 AND first_delivered_at IS NOT NULL) AS partial_first_delivered`;

export async function readTransactionMaterialFacts(
  query: SqlQueryFn,
  operationId: string,
): Promise<TransactionMaterialFacts> {
  const rows = await query(FACTS_SELECT, [operationId]);
  const row = rows[0];
  if (row === undefined) {
    throw new Error(`transaction-material facts query returned no row for operation ${operationId}`);
  }
  const attemptPhase = row.attempt_phase;
  return {
    attemptPhase: attemptPhase === null || attemptPhase === undefined ? null : (attemptPhase as AttemptPhase),
    signIntentPersisted: row.sign_intent_persisted === true,
    partialPersisted: row.partial_persisted === true,
    partialFirstDelivered: row.partial_first_delivered === true,
  };
}
