// Production composition for
// `POST /v1/operations/:operation_id/verification-complete`.
//
// Implements the frozen verification-complete request/response contract and its
// atomicity freeze (the verification-complete barrier).
//
// The transport (node-core api/routes/action-routes.ts handleVerificationComplete) has
// existed since the action-route slice and declares `ActionRouteStore.verificationComplete`. Until this
// module the only implementations were test fakes. This is the real one.
//
// Why it lives here and not in node-core/src/verification: the acknowledgement service
// decides release but must never perform it (the one-in-flight-per-wallet rule), and node-core's own boundary
// test gives the verification module a reporting-only dependency edge — it has no edge to
// the lease module at all. Joining the two is a composition-root job, so it belongs in the
// app, next to the sibling arm composition (arm-wallet-gate.ts / arm-commit.ts).
//
// The atomicity freeze: the endpoint "atomically commits its acknowledgement, any lease release, and a
// completed idempotency row with exact status and response-body bytes." That is one DB
// transaction: `withTransaction` opens it, the acknowledgement insert, every
// `mintReleaseProof` and every `releaseLease` run on that same pinned executor, and nothing
// commits unless all of it does. A throw anywhere rolls back the proof rows together with the
// membership close and the active-row DELETE — a minted-but-unconsumed proof surviving a
// failed release would be standing release authority for a lease that was never released.
//
// Boundary: apps/generic-node may import only `@zucoins/node-core` (no subpaths).

import { createHash, randomUUID } from "node:crypto";

import {
  AcknowledgementError,
  IdempotencyConflictError,
  OperationVersionConflictError,
  ProtocolPredicateFailedError,
  createAcknowledgementService,
  LANDED_PROOF_KIND_BY_OPERATION_KIND,
  createSqlAcknowledgementStore,
  mintReleaseProof,
  releaseLease,
  type AckOpenMembership,
  type AckWalletEvidenceInput,
  type AcknowledgementStore,
  type ActionRouteStore,
  type VerificationCompleteInput,
  type VerificationCompleteSuccessResponse,
} from "@zucoins/node-core";
import type { Pool, PoolClient } from "pg";

import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";
import { applyMoneyPathStatementTimeout } from "../db/client.js";

/**
 * One pinned connection for the whole unit of work. Structurally satisfies both node-core
 * SQL surfaces this module drives (`AckSqlExecutor` and the leases `SqlExecutor`), so the
 * acknowledgement insert and the lease release provably share a transaction rather than
 * merely being called in sequence. `rowCount` is carried because `releaseLease` refuses on
 * any close/consume/DELETE that does not affect exactly one row.
 */
export interface VerificationCompleteTx {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[]; rowCount?: number | null }>;
}

/** BEGIN → body(tx) → COMMIT; ROLLBACK on throw. */
export interface VerificationCompleteTxFactory {
  withTransaction<T>(fn: (tx: VerificationCompleteTx) => Promise<T>): Promise<T>;
}

/**
 * Acknowledgement identity the wire body does not carry: the verified reporting credential's
 * tenant and nonce binding, the exact signed bytes (the byte-exact signing rule — never re-derived here),
 * this node instance's lease-owner identity, and the wallet evidence resolved to durable
 * observation ids and chain public keys.
 *
 * Supplied by the reporting request pipeline, which is the only layer that has verified the
 * signature and therefore the only layer entitled to assert these.
 */
export interface VerificationCompleteEnvelope {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly reportingNonceId: string;
  readonly mutationIdempotencyId: string;
  /** `raw_target` — the opaque exact target bytes, never reconstructed. */
  readonly rawTarget: string;
  readonly requestBodySha256: string;
  readonly requestPreimageText: string;
  readonly requestSignature: string;
  /** Owner instance holding the leases; `releaseLease` refuses a foreign owner. */
  readonly ownerInstanceId: string;
  /** `wallet_evidence[]` in the caller's sequence — never re-sequenced (the byte-exact signing rule). */
  readonly walletEvidence: readonly AckWalletEvidenceInput[];
}

export interface VerificationCompleteStoreDeps {
  readonly txFactory: VerificationCompleteTxFactory;
  readonly envelopeFor: (
    operationId: string,
    input: VerificationCompleteInput,
  ) => Promise<VerificationCompleteEnvelope>;
  /** Defaults to `createSqlAcknowledgementStore()`. */
  readonly ackStore?: AcknowledgementStore<VerificationCompleteTx>;
  /**
   * The freeze: the endpoint "atomically commits its acknowledgement, any lease release, and a
   * completed idempotency row with exact status and response-body bytes." The idempotency
   * row belongs to the reporting runtime, so the freeze is a hook — but it is called on
   * this transaction, because bytes frozen after COMMIT could disagree with what committed.
   *
   * Without it a matching replay cannot read the first response back and
   * `replayBodyFromStored` falls to its conservative non-RELEASED reconstruction, which is
   * safe but is not the frozen first response the contract promises. Production wires it.
   */
  readonly freezeResponse?: (
    tx: VerificationCompleteTx,
    operationId: string,
    body: VerificationCompleteSuccessResponse,
  ) => Promise<void>;
  readonly newAcknowledgementId?: () => string;
  readonly newProofId?: () => string;
  readonly nowIso?: () => string;
  /** Seams for fault injection in tests; production leaves both at the node-core defaults. */
  readonly mintProof?: typeof mintReleaseProof;
  readonly release?: typeof releaseLease;
}

/**
 * `wallet_lease_memberships.release_reason` for a lease closed by a VERIFIED verification
 * acknowledgement. The forensic trail records *why* the lease closed; `proof_kind` records
 * what landed.
 */
export const VERIFICATION_COMPLETE_RELEASE_REASON = "VERIFICATION_COMPLETE";


/**
 * `lease_release_proofs.proof_digest` (sha256_hex NOT NULL). Canon fixes the column but
 * freezes no encoding, so this binds the proof to the exact acknowledgement and lease tuple
 * that authorised it: byte-length-prefixed fields, the same injection-safe shape as
 * `computeEvidenceSetSha256` — no field value can forge a boundary. A digest lifted from one
 * membership therefore does not describe another.
 */
export function computeReleaseProofDigest(fields: {
  readonly acknowledgementId: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly verdict: string;
}): string {
  const field = (value: string): string =>
    `${new TextEncoder().encode(value).length}:${value}`;
  const text =
    field(fields.acknowledgementId) +
    field(fields.operationId) +
    field(fields.walletId) +
    field(fields.membershipId) +
    field(fields.leaseGroupId) +
    field(fields.leaseEpoch.toString()) +
    field(fields.verdict);
  return createHash("sha256").update(`vcproof1:${text}`, "utf8").digest("hex");
}

/**
 * Map the acknowledgement service's typed failures onto the frozen action-route error
 * taxonomy. Only the transport knows HTTP status codes, so this stays at the error-class
 * level. Every reason is enumerated: an unmapped one must not fall through to a release.
 */
function mapAcknowledgementError(err: unknown): unknown {
  if (!(err instanceof AcknowledgementError)) return err;
  switch (err.reason) {
    case "OPERATION_VERSION_CONFLICT":
      return new OperationVersionConflictError();
    case "CONFLICTING_REPLAY":
      // A replay whose bound fields differ is rejected, never reconciled.
      return new IdempotencyConflictError();
    case "OPERATION_NOT_FOUND":
    case "TENANT_MISMATCH":
    case "VERDICT_NOT_ACKNOWLEDGEABLE":
    case "EVIDENCE_SET_INVALID":
    case "OPERATION_HAS_NO_LEASE_GROUP":
    case "OPERATION_WALLETS_INCOMPLETE":
      return new ProtocolPredicateFailedError(err.reason);
  }
  return err;
}

/**
 * Deterministic release sequence: ascending wallet id, the same total sequence
 * `sortWalletIdsAscending` imposes on acquisition. Two concurrent group releases therefore
 * take wallet row locks in one direction and cannot deadlock against each other.
 */
function inWalletSequence(
  memberships: readonly AckOpenMembership[],
): readonly AckOpenMembership[] {
  return [...memberships].sort((a, b) => (a.walletId < b.walletId ? -1 : a.walletId > b.walletId ? 1 : 0));
}

/**
 * The real `ActionRouteStore.verificationComplete`: record the VERIFIED / REJECTED /
 * INDETERMINATE acknowledgement, evaluate group release, and — when and only when the
 * acknowledgement authorises it — mint a terminal-positive proof and release each named
 * membership, all inside the one transaction.
 *
 * The one-in-flight-per-wallet rule is preserved end to end: the acknowledgement service names the releasable
 * memberships and this root releases exactly those, each against a proof minted for that
 * exact tuple. A membership the service did not name is never touched.
 */
export function createSqlVerificationCompleteStore(
  deps: VerificationCompleteStoreDeps,
): Pick<ActionRouteStore, "verificationComplete"> {
  const ackStore = deps.ackStore ?? createSqlAcknowledgementStore();
  const newProofId = deps.newProofId ?? (() => randomUUID());
  const mint = deps.mintProof ?? mintReleaseProof;
  const release = deps.release ?? releaseLease;
  const service = createAcknowledgementService<VerificationCompleteTx>({
    store: ackStore,
    newAcknowledgementId: deps.newAcknowledgementId ?? (() => randomUUID()),
    nowIso: deps.nowIso ?? (() => new Date().toISOString()),
  });

  return {
    async verificationComplete(operationId, input) {
      const envelope = await deps.envelopeFor(operationId, input);

      return deps.txFactory.withTransaction(async (tx) => {
        let outcome;
        try {
          outcome = await service.acknowledge(tx, operationId, {
            expectedRowVersion: input.expected_row_version,
            consumedCursor: BigInt(input.consumed_cursor),
            verdict: input.verdict,
            walletEvidence: envelope.walletEvidence,
            nodeId: envelope.nodeId,
            implementerId: envelope.implementerId,
            reportingNonceId: envelope.reportingNonceId,
            mutationIdempotencyId: envelope.mutationIdempotencyId,
            rawTarget: envelope.rawTarget,
            requestBodySha256: envelope.requestBodySha256,
            requestPreimageText: envelope.requestPreimageText,
            requestSignature: envelope.requestSignature,
          });
        } catch (err) {
          throw mapAcknowledgementError(err);
        }

        // A replay returns the frozen first-response fields; the first response already
        // performed whatever release it authorised, and the proof it consumed is spent. Only
        // a first write may release, so replays never re-enter this branch.
        if (!outcome.idempotentReplay && outcome.releasableMemberships.length > 0) {
          const operation = await ackStore.readOperation(tx, operationId);
          if (operation === null) {
            // Unreachable — acknowledge() already read it on this transaction. Refusing
            // rather than guessing a proof_kind keeps an unattributable proof out of the DB.
            throw new ProtocolPredicateFailedError("OPERATION_NOT_FOUND");
          }
          // Ceiling: the kind of the acknowledged operation labels every proof in the group.
          // proof_kind is a forensic label — `releaseLease` authorises on issuer + exact
          // tuple + unconsumed, never on the kind — so a mixed-kind group (receive with an
          // automatic child move) gets one accurate-for-the-acknowledged-leg label rather
          // than a per-membership operation lookup that would buy nothing today.
          const proofKind = LANDED_PROOF_KIND_BY_OPERATION_KIND[operation.kind];

          for (const membership of inWalletSequence(outcome.releasableMemberships)) {
            const proofId = newProofId();
            await mint(tx, {
              proofId,
              walletId: membership.walletId,
              operationId: membership.operationId,
              membershipId: membership.membershipId,
              leaseGroupId: membership.leaseGroupId,
              leaseEpoch: membership.leaseEpoch,
              proofKind,
              proofDigest: computeReleaseProofDigest({
                acknowledgementId: outcome.body.acknowledgement_id,
                operationId: membership.operationId,
                walletId: membership.walletId,
                membershipId: membership.membershipId,
                leaseGroupId: membership.leaseGroupId,
                leaseEpoch: membership.leaseEpoch,
                verdict: outcome.body.verdict,
              }),
            });
            // Same tx: closes the membership, consumes the proof, DELETEs the exclusive
            // active row and flips the wallet PINNED → AVAILABLE. A throw here rolls the
            // proof minted immediately above back with it.
            await release(tx, {
              walletId: membership.walletId,
              ownerInstanceId: envelope.ownerInstanceId,
              operationId: membership.operationId,
              membershipId: membership.membershipId,
              leaseGroupId: membership.leaseGroupId,
              leaseEpoch: membership.leaseEpoch,
              releaseProofId: proofId,
              releaseReason: VERIFICATION_COMPLETE_RELEASE_REASON,
            });
          }
        }

        const body: VerificationCompleteSuccessResponse = {
          operation_id: outcome.body.operation_id,
          acknowledgement_id: outcome.body.acknowledgement_id,
          verdict: outcome.body.verdict,
          lease_release_status: outcome.body.lease_release_status,
          acknowledged_at: outcome.body.acknowledged_at,
        };
        // Freeze on the first write only: a replay must return the bytes already frozen, not
        // overwrite them with a second reconstruction.
        if (!outcome.idempotentReplay) {
          await deps.freezeResponse?.(tx, operationId, body);
        }
        return { status: 200 as const, body, idempotentReplay: outcome.idempotentReplay };
      });
    },
  };
}

/**
 * Adapt a node-postgres Pool into the tx factory. One client is pinned for the whole
 * critical section, so every FOR UPDATE the acknowledgement and the release take is held
 * until COMMIT. Mirrors `createPoolArmTxFactory`, but preserves `rowCount` — `releaseLease`
 * fails closed without it.
 */
export function createPoolVerificationCompleteTxFactory(
  pool: Pool,
  options: { readonly statementTimeoutMs?: number } = {},
): VerificationCompleteTxFactory {
  const statementTimeoutMs =
    options.statementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  return {
    async withTransaction<T>(fn: (tx: VerificationCompleteTx) => Promise<T>): Promise<T> {
      const client: PoolClient = await pool.connect();
      try {
        await client.query("BEGIN");
        await applyMoneyPathStatementTimeout(client, statementTimeoutMs);
        const tx: VerificationCompleteTx = {
          async query<R>(text: string, params?: readonly unknown[]) {
            const result = await client.query(text, params as unknown[] | undefined);
            return { rows: result.rows as R[], rowCount: result.rowCount };
          },
        };
        const value = await fn(tx);
        await client.query("COMMIT");
        return value;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // surface the original error
        }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
