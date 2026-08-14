// The CREATED→READY DB-TX.
//
// Writes receive_codes, returns the 201 body, and appends the receive.ready event;
// the byte-exact signing rule (response body bytes are the idempotency result — never reshaped on replay).
//
// Rechecks operation / lease epoch / destination eligibility / expiry, persists the code,
// attaches T0 evidence already bound, transitions CREATED→READY, appends receive.ready,
// completes the idempotency result with 201, and commits.
//
// INDEPENDENT (default): code_status=AWAITING_ARM — transfer_code plaintext is durable but
// withheld from every non-arm surface (201 body, point GET, subscription, event, callback,
// log, audit) until a successful armed.
//
// NODE_VERIFIED (ZTR-1302): code_status=RELEASED in the same TX as READY. There is no
// consumer verifier, so holding the code for arm would strand the receive. Point GET
// surfaces transfer_code once RELEASED. The arm-time standing recheck is intentionally
// NOT replicated here — this TX already runs under the operation's wallet lease.
// receive.ready event payload shape is mode-invariant (AC4): still transfer_code:null /
// code_status:"AWAITING_ARM" vocabulary on the event (code bytes never on the event bus).

import { createHash } from "node:crypto";

import type { VerificationMode } from "@zucoins/generic-node-contracts/operations";

import type { FormedReceiveCode } from "./code-formation.js";

/** Narrow SQL surface; composition root injects a transaction-scoped executor. */
export interface SqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[]; readonly rowCount?: number | null }>;
}

export const RECEIVE_READY_STATEMENTS = {
  /**
   * Step 8 recheck: operation still CREATED, lease still held at the capture epoch.
   * Returns one row only when every conjunct holds.
   */
  RECHECK_CREATED_AND_LEASE: `
SELECT o.id::text AS operation_id,
       o.row_version::int AS row_version,
       o.amount_zkz,
       o.created_at,
       o.updated_at,
       o.verification_mode::text AS verification_mode
  FROM operations o
  JOIN wallet_active_leases l
    ON l.operation_id = o.id
   AND l.wallet_id = $2
   AND l.lease_role = 'RECEIVE_WINDOW'
   AND l.lease_epoch = $3
 WHERE o.id = $1
   AND o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'`
    .replace(/\s+/g, " ")
    .trim(),

  RECHECK_DESTINATION_ELIGIBLE: `
SELECT d.id::text AS destination_id
  FROM destinations d
  JOIN wallets w ON w.id = d.wallet_id
 WHERE d.id = $1
   AND d.state = 'BLESSED'
   AND w.recovery_verified_at IS NOT NULL
   AND w.state IN ('AVAILABLE', 'PINNED')`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Code row. $10 = code_status, $11 = ready_at, $12 = released_at.
   * INDEPENDENT inserts AWAITING_ARM / NULL released_at.
   * NODE_VERIFIED inserts RELEASED / readyAt as released_at (ZTR-1302) — atomic with READY.
   * Arm-time wallet standing recheck is NOT replicated here: ready-commit already holds the
   * operation's RECEIVE_WINDOW lease on this wallet.
   */
  INSERT_RECEIVE_CODE: `
INSERT INTO receive_codes (
  operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
  discriminator, anchor, expiry_unix_time_secs,
  transfer_code_text, transfer_code_sha256, code_status, ready_at, released_at
) VALUES (
  $1, $2, $3, $4,
  $5, $6, $7,
  $8, $9, $10, $11, $12
)`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Crash-recovery / completeReadyFromDurableCode: if a prior insert left AWAITING_ARM on a
   * NODE_VERIFIED op, promote to RELEASED under the same ready TX (idempotent).
   */
  ENSURE_CODE_RELEASED: `
UPDATE receive_codes
   SET code_status = 'RELEASED',
       released_at = COALESCE(released_at, $2::timestamptz)
 WHERE operation_id = $1
   AND code_status = 'AWAITING_ARM'
RETURNING operation_id::text AS operation_id`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * CREATED→READY under the same recheck predicates. Also freezes expiry + T0 on the
   * operation row (assigned-receive triple).
   */
  CAS_CREATED_TO_READY: `
UPDATE operations
   SET status = 'READY',
       row_version = row_version + 1,
       updated_at = $4,
       expiry_unix_time_secs = $5,
       t0_observation_id = $6,
       receiver_wallet_id = $7
 WHERE id = $1
   AND status = 'CREATED'
   AND row_version = $2
   AND EXISTS (
         SELECT 1 FROM wallet_active_leases l
          WHERE l.operation_id = $1
            AND l.wallet_id = $7
            AND l.lease_role = 'RECEIVE_WINDOW'
            AND l.lease_epoch = $3
       )
RETURNING id::text AS operation_id, row_version::int AS row_version, updated_at`
    .replace(/\s+/g, " ")
    .trim(),

  COMPLETE_IDEMPOTENCY_201: `
UPDATE operations
   SET response_status = 201,
       response_body = $2
 WHERE id = $1
   AND response_body IS NULL
RETURNING id::text AS operation_id`
    .replace(/\s+/g, " ")
    .trim(),

  SELECT_RECEIVE_CODE: `
SELECT operation_id::text AS operation_id
  FROM receive_codes
 WHERE operation_id = $1`
    .replace(/\s+/g, " ")
    .trim(),
} as const;

export interface ReceiveReadyEventAppender {
  /**
   * Append `receive.ready` inside the caller's transaction. Must not embed transfer_code
   * plaintext in event data (secrecy guarantee).
   */
  appendReceiveReady(input: {
    readonly operationId: string;
    readonly walletId: string;
    readonly dataText: string;
    readonly dataSha256: string;
  }): Promise<void>;
}

export interface CommitReceiveReadyInput {
  readonly formed: FormedReceiveCode;
  readonly receiverWalletId: string;
  readonly leaseEpoch: bigint;
  /** ISO-8601 ready_at / updated_at stamp. */
  readonly readyAt: string;
  /**
   * Destination id when after_landing is INTERNAL_MOVE; null for HOLD. Rechecked inside
   * the TX when non-null.
   */
  readonly destinationId: string | null;
  readonly sql: SqlExecutor;
  readonly events: ReceiveReadyEventAppender;
  /**
   * Optional override for the 201 body. Default builds the shape with
   * transfer_code:null / code_status:AWAITING_ARM (INDEPENDENT) or
   * RELEASED + transfer_code plaintext (NODE_VERIFIED).
   */
  readonly buildResponseBody?: (input: {
    readonly formed: FormedReceiveCode;
    readonly rowVersion: number;
    readonly createdAt: string;
    readonly updatedAt: string;
    readonly subscriptionHandle: string;
    readonly codeStatus?: CommitReceiveReadyCodeStatus;
  }) => string;
  /**
   * Create-time `sh_…` plaintext (required, min length 1). Must match the handle
   * minted at admit and frozen into the 202 body — READY never mints and never
   * accepts null (frozen ReceiveExternalReadyResponseSchema).
   */
  readonly subscriptionHandle: string;
  /** ISO created_at from the operations row when known; falls back to readyAt. */
  readonly createdAt?: string;
}

export type CommitReceiveReadyRejectionReason =
  | "operation_not_created"
  | "lease_lost"
  | "destination_not_eligible"
  | "expiry_passed"
  | "cas_lost"
  | "code_already_present"
  | "idempotency_already_completed"
  /** Create-time `sh_…` plaintext missing/empty — refuse READY rather than emit schema-illegal null. */
  | "subscription_handle_missing";

export type CommitReceiveReadyCodeStatus = "AWAITING_ARM" | "RELEASED";

export type CommitReceiveReadyResult =
  | {
      readonly ok: true;
      readonly operationId: string;
      readonly rowVersion: number;
      readonly responseStatus: 201;
      readonly responseBody: string;
      /** Durable receive_codes.code_status after this TX (NODE_VERIFIED → RELEASED). */
      readonly codeStatus: CommitReceiveReadyCodeStatus;
    }
  | {
      readonly ok: false;
      readonly reason: CommitReceiveReadyRejectionReason;
      readonly detail: string;
    };

function asVerificationMode(value: string | null | undefined): VerificationMode {
  return value === "NODE_VERIFIED" ? "NODE_VERIFIED" : "INDEPENDENT";
}

/** Durable code_status written at ready-commit for the operation's verification_mode. */
export function readyCommitCodeStatus(mode: VerificationMode): CommitReceiveReadyCodeStatus {
  return mode === "NODE_VERIFIED" ? "RELEASED" : "AWAITING_ARM";
}

const SQLSTATE_UNIQUE_VIOLATION = "23505";

function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === SQLSTATE_UNIQUE_VIOLATION;
}

function toIso(value: string | Date): string {
  return typeof value === "string" ? value : new Date(value).toISOString();
}

/**
 * True when `handle` is a non-empty string suitable for the frozen READY/QUEUED
 * `subscription_handle` field (z.string().min(1) / OpenAPI minLength:1).
 */
export function isNonEmptySubscriptionHandle(handle: unknown): handle is string {
  return typeof handle === "string" && handle.length > 0;
}

/**
 * Synchronous-assignment 201 body. Explicit key insertion sequence (the byte-exact signing rule):
 * these bytes are the idempotency result and are replayed verbatim.
 *
 * Secrecy (INDEPENDENT): `transfer_code` is the JSON null literal — never the withheld
 * plaintext, never omitted, never the empty string. `code_status` is exactly `"AWAITING_ARM"`.
 *
 * NODE_VERIFIED (ZTR-1302): `code_status` is `"RELEASED"` and `transfer_code` carries the
 * plaintext (auto-released at ready-commit). Create/idempotency replay of this body is the
 * only non-GET surface that embeds plaintext; events still withhold it (see
 * buildReceiveReadyEventData).
 *
 * `subscription_handle` is the create-time `sh_…` plaintext (required, min length 1) —
 * never null, never empty (frozen ReceiveExternalReadyResponseSchema for INDEPENDENT;
 * NODE_VERIFIED READY body is the same shape with RELEASED + code bytes).
 */
export function buildReceiveReady201Body(input: {
  readonly formed: FormedReceiveCode;
  readonly rowVersion: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly subscriptionHandle: string;
  /** Defaults INDEPENDENT. NODE_VERIFIED embeds RELEASED + transfer_code plaintext. */
  readonly codeStatus?: CommitReceiveReadyCodeStatus;
}): string {
  if (!isNonEmptySubscriptionHandle(input.subscriptionHandle)) {
    throw new Error(
      "buildReceiveReady201Body: subscriptionHandle must be a non-empty string (frozen READY schema)",
    );
  }
  const { formed } = input;
  const codeStatus = input.codeStatus ?? "AWAITING_ARM";
  const expiresAt = new Date(Number(formed.expiryUnixTimeSecs) * 1000).toISOString();
  return JSON.stringify({
    operation: {
      operation_id: formed.discriminator,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      amount_zkz: formed.amountZkz,
      row_version: input.rowVersion,
      attention_required: false,
      attention_reason: null,
      created_at: input.createdAt,
      updated_at: input.updatedAt,
      terminal_at: null,
      verification_material_available_until: null,
    },
    receiver_pubkey: formed.receiverPubkey,
    discriminator: formed.discriminator,
    expires_at: expiresAt,
    after_landing: formed.afterLanding,
    code_status: codeStatus,
    transfer_code:
      codeStatus === "RELEASED" ? formed.transferCode.transferCodeText : null,
    expected_artifact: {
      key_id: formed.artifact.envelope.key_id,
      preimage_text: formed.artifact.envelope.preimage_text,
      preimage_sha256: formed.artifact.envelope.preimage_sha256,
      signature: formed.artifact.envelope.signature,
    },
    t0: {
      observation_id: formed.t0.observationId,
      projection: {
        s: formed.t0.s0,
        p: formed.t0.p0,
        b_zkz: formed.t0.b0,
      },
    },
    subscription_handle: input.subscriptionHandle,
  });
}

/**
 * receive.ready event data — deliberately excludes transfer_code plaintext for both modes
 * (AC4: event vocabulary/shape is mode-invariant). Hash of these exact bytes becomes
 * data_sha256 on the event row. `code_status` on the event remains the literal
 * `"AWAITING_ARM"` token for both modes so dual-chain append stays byte-identical in shape.
 */
export function buildReceiveReadyEventData(
  formed: FormedReceiveCode,
  receiverWalletId: string,
): string {
  return JSON.stringify({
    operation_id: formed.discriminator,
    receiver_wallet_id: receiverWalletId,
    code_status: "AWAITING_ARM",
    transfer_code: null,
    expected_artifact_id: formed.artifact.id,
    t0_observation_id: formed.t0.observationId,
    expiry_unix_time_secs: formed.expiryUnixTimeSecs,
    transfer_code_sha256: formed.transferCode.transferCodeSha256,
  });
}

/**
 * Structural secrecy check: the withheld transfer-code plaintext must not appear in any
 * string that leaves the READY commit when the code is still AWAITING_ARM (201 body for
 * INDEPENDENT, and receive.ready event data for both modes). Used by tests and as a
 * last-line guard inside the commit path.
 */
export function assertWithheldTransferCode(
  surface: string,
  transferCodeText: string,
): void {
  if (transferCodeText.length > 0 && surface.includes(transferCodeText)) {
    throw new Error(
      "receive code secrecy breach: withheld transfer_code_text present on a non-arm surface",
    );
  }
}

async function finishReadyTransition(
  input: CommitReceiveReadyInput,
  op: {
    readonly row_version: number;
    readonly created_at: string | Date;
    readonly verification_mode?: string | null;
  },
  codeStatus: CommitReceiveReadyCodeStatus,
): Promise<CommitReceiveReadyResult> {
  const { formed, sql } = input;

  // Fail closed before any CAS / code write: inventing null would launder a
  // schema-illegal body into the durable idempotency carrier (ZTR-1142).
  if (!isNonEmptySubscriptionHandle(input.subscriptionHandle)) {
    return {
      ok: false,
      reason: "subscription_handle_missing",
      detail: `create-time subscription_handle missing for ${formed.discriminator}; refuse READY`,
    };
  }
  const subscriptionHandle = input.subscriptionHandle;

  const cas = await sql.query<{
    operation_id: string;
    row_version: number;
    updated_at: string | Date;
  }>(RECEIVE_READY_STATEMENTS.CAS_CREATED_TO_READY, [
    formed.discriminator,
    op.row_version,
    input.leaseEpoch.toString(),
    input.readyAt,
    formed.expiryUnixTimeSecs,
    formed.t0.observationId,
    input.receiverWalletId,
  ]);
  const ready = cas.rows[0];
  if (ready === undefined) {
    return {
      ok: false,
      reason: "cas_lost",
      detail: `CREATED→READY CAS missed for ${formed.discriminator} at row_version ${op.row_version}`,
    };
  }

  const createdAt = input.createdAt ?? toIso(op.created_at);
  const updatedAt = toIso(ready.updated_at);
  const buildBody = input.buildResponseBody ?? buildReceiveReady201Body;
  const responseBody = buildBody({
    formed,
    rowVersion: ready.row_version,
    createdAt,
    updatedAt,
    subscriptionHandle,
    codeStatus,
  });
  // INDEPENDENT 201 body and both-mode event data must never embed plaintext.
  // NODE_VERIFIED 201 body intentionally carries transfer_code once RELEASED.
  if (codeStatus === "AWAITING_ARM") {
    assertWithheldTransferCode(responseBody, formed.transferCode.transferCodeText);
  }

  const eventData = buildReceiveReadyEventData(formed, input.receiverWalletId);
  assertWithheldTransferCode(eventData, formed.transferCode.transferCodeText);
  const dataSha256 = createHash("sha256").update(eventData, "utf8").digest("hex");

  await input.events.appendReceiveReady({
    operationId: formed.discriminator,
    walletId: input.receiverWalletId,
    dataText: eventData,
    dataSha256,
  });

  const completed = await sql.query<{ operation_id: string }>(
    RECEIVE_READY_STATEMENTS.COMPLETE_IDEMPOTENCY_201,
    [formed.discriminator, responseBody],
  );
  if (completed.rows[0] === undefined) {
    return {
      ok: false,
      reason: "idempotency_already_completed",
      detail: `operations.response_body already set for ${formed.discriminator}`,
    };
  }

  return {
    ok: true,
    operationId: formed.discriminator,
    rowVersion: ready.row_version,
    responseStatus: 201,
    responseBody,
    codeStatus,
  };
}

/**
 * Step 8. Caller holds the SERIALIZABLE (or equivalent) transaction on `sql`.
 * On ok:true the TX is ready to commit; the caller owns commit/rollback.
 */
export async function commitReceiveReady(
  input: CommitReceiveReadyInput,
): Promise<CommitReceiveReadyResult> {
  const { formed, sql } = input;

  // Fail closed up front so we never insert a code row then discover the handle is missing.
  if (!isNonEmptySubscriptionHandle(input.subscriptionHandle)) {
    return {
      ok: false,
      reason: "subscription_handle_missing",
      detail: `create-time subscription_handle missing for ${formed.discriminator}; refuse READY`,
    };
  }

  // Expiry recheck: refuse to READY a code whose frozen expiry is already past readyAt.
  const readyAtUnixSecs = Math.floor(Date.parse(input.readyAt) / 1000);
  if (
    Number.isFinite(readyAtUnixSecs) &&
    Number(formed.expiryUnixTimeSecs) <= readyAtUnixSecs
  ) {
    return {
      ok: false,
      reason: "expiry_passed",
      detail: `frozen expiry ${formed.expiryUnixTimeSecs} is not after readyAt ${input.readyAt}`,
    };
  }

  const held = await sql.query<{
    operation_id: string;
    row_version: number;
    amount_zkz: string;
    created_at: string | Date;
    updated_at: string | Date;
    verification_mode: string | null;
  }>(RECEIVE_READY_STATEMENTS.RECHECK_CREATED_AND_LEASE, [
    formed.discriminator,
    input.receiverWalletId,
    input.leaseEpoch.toString(),
  ]);
  const op = held.rows[0];
  if (op === undefined) {
    return {
      ok: false,
      reason: "lease_lost",
      detail: `operation ${formed.discriminator} is not CREATED under lease epoch ${input.leaseEpoch}`,
    };
  }

  if (input.destinationId !== null) {
    const dest = await sql.query<{ destination_id: string }>(
      RECEIVE_READY_STATEMENTS.RECHECK_DESTINATION_ELIGIBLE,
      [input.destinationId],
    );
    if (dest.rows[0] === undefined) {
      return {
        ok: false,
        reason: "destination_not_eligible",
        detail: `destination ${input.destinationId} failed eligibility recheck`,
      };
    }
  }

  // Branch on the operation's frozen verification_mode inside this TX (not the worker
  // step) so RELEASED is atomic with READY for NODE_VERIFIED (ZTR-1302).
  const codeStatus = readyCommitCodeStatus(asVerificationMode(op.verification_mode));
  const releasedAt = codeStatus === "RELEASED" ? input.readyAt : null;

  try {
    await sql.query(RECEIVE_READY_STATEMENTS.INSERT_RECEIVE_CODE, [
      formed.discriminator,
      input.receiverWalletId,
      formed.t0.observationId,
      formed.artifact.id,
      formed.discriminator,
      formed.anchor,
      formed.expiryUnixTimeSecs,
      formed.transferCode.transferCodeText,
      formed.transferCode.transferCodeSha256,
      codeStatus,
      input.readyAt,
      releasedAt,
    ]);
  } catch (error) {
    if (isUniqueViolation(error)) {
      return {
        ok: false,
        reason: "code_already_present",
        detail: `receive_codes already exists for ${formed.discriminator}`,
      };
    }
    throw error;
  }

  return finishReadyTransition(input, op, codeStatus);
}

/**
 * artifact/code records complete but CREATED→READY did not commit.
 * Guardedly completes the transition without regenerating bytes. The formed view must be
 * loaded from durable rows by the caller (never rebuilt from request inputs alone when
 * durable code bytes exist).
 */
export async function completeReadyFromDurableCode(
  input: CommitReceiveReadyInput,
): Promise<CommitReceiveReadyResult> {
  const { formed, sql } = input;

  if (!isNonEmptySubscriptionHandle(input.subscriptionHandle)) {
    return {
      ok: false,
      reason: "subscription_handle_missing",
      detail: `create-time subscription_handle missing for ${formed.discriminator}; refuse READY`,
    };
  }

  const held = await sql.query<{
    operation_id: string;
    row_version: number;
    amount_zkz: string;
    created_at: string | Date;
    updated_at: string | Date;
    verification_mode: string | null;
  }>(RECEIVE_READY_STATEMENTS.RECHECK_CREATED_AND_LEASE, [
    formed.discriminator,
    input.receiverWalletId,
    input.leaseEpoch.toString(),
  ]);
  const op = held.rows[0];
  if (op === undefined) {
    return {
      ok: false,
      reason: "operation_not_created",
      detail: `operation ${formed.discriminator} is not CREATED under the held lease`,
    };
  }

  const existingCode = await sql.query<{ operation_id: string }>(
    RECEIVE_READY_STATEMENTS.SELECT_RECEIVE_CODE,
    [formed.discriminator],
  );
  if (existingCode.rows[0] === undefined) {
    // No durable code yet — first formation.
    return commitReceiveReady(input);
  }

  const codeStatus = readyCommitCodeStatus(asVerificationMode(op.verification_mode));
  // NODE_VERIFIED crash recovery: a prior insert may have left AWAITING_ARM before the
  // mode branch landed — promote under the same ready TX (idempotent).
  if (codeStatus === "RELEASED") {
    await sql.query(RECEIVE_READY_STATEMENTS.ENSURE_CODE_RELEASED, [
      formed.discriminator,
      input.readyAt,
    ]);
  }

  // Code already durable: only CAS + event + idempotency (do not regenerate / re-insert).
  return finishReadyTransition(input, op, codeStatus);
}
