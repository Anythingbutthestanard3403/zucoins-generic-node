// The composition-root `ReceiveLandingStore` for the receive landing commit.
//
// node-core owns the statements (packages/node-core/src/receive/landing-sql-store.ts:
// guarded status CAS → proof header → ordered path → receive.landed → lease presence check)
// and links no driver. This file is the only layer that touches a socket: it opens ONE
// pg transaction, runs those statements on it, and adds the one thing the landing commit
// requires that is not in node-core's slice — the transaction-record advance to
// `SETTLED_BODY_PERSISTED` — inside the same transaction, so the settled body's phase and the
// READY → RECEIVE_LANDED transition commit together or not at all.
//
// Ordering is load-bearing. The CAS runs FIRST, so a replay of an already-landed operation
// returns ALREADY_LANDED instead of throwing on a one-way phase advance that has already been
// made. `advanceAttemptPhase` is itself one-way (its WHERE requires the prior phase and NULL
// target columns), so it cannot overwrite a persisted value even if it were reached twice.
//
// No statement here DELETEs, UPDATEs or re-INSERTs wallet_active_leases: the receiver lease is
// byte-identical across the transition. Release belongs to the release/expiry flows.

import type { Pool } from "pg";

import {
  RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
  SqlReceiveLandingStore,
  advanceAttemptPhase,
  classifyReceiveLandingError,
  promoteReceiveLandingPathToLineage,
  recordWalletSettledLedger,
  type CommitReceiveLandingCommand,
  type NodeEventSigner,
  type ReceiveLandingConflictReason,
  type ReceiveLandingStore,
} from "@zucoins/node-core";

import { issueLandedAccessWindow } from "./issue-landed-access-window.js";

/**
 * The signer stand-in used when no EVENT_SIGNING key was supplied.
 *
 * It throws instead of signing, which aborts the landing transaction. That is deliberate and
 * is the Byte-exact rule, not a defensive nicety: a landing appends `receive.landed` to the signed
 * node/implementer chains in the same transaction as the status CAS, so a node that cannot
 * sign must not be able to record a landing at all. Failing loudly here is strictly better
 * than the earlier behaviour, which committed the landed status and silently produced no
 * authoritative event.
 */
const UNAVAILABLE_EVENT_SIGNER: NodeEventSigner = {
  signingKeyId: "00000000-0000-0000-0000-000000000000",
  sign(): string {
    throw new Error(
      "receive landing requires an EVENT_SIGNING signer: the landed status and its signed " +
        "node_events/implementer_events rows commit together (Byte-exact). Pass the node's " +
        "event signer to createSqlReceiveLandingStore.",
    );
  },
};

export interface CommitLandingResult {
  readonly applied: boolean;
  readonly reason?: ReceiveLandingConflictReason;
  readonly receiverLeaseStillHeld: boolean;
}

/**
 * Adapt a node-postgres Pool into the landing DB-TX.
 *
 * The deferred completeness triggers in receive-external-landing.sql fire at COMMIT — which is
 * this function's COMMIT, not node-core's — so a short, gapped or mis-anchored path raises
 * here and is classified with node-core's own marker list rather than escaping as an
 * unclassified crash.
 */
export function createSqlReceiveLandingStore(
  pool: Pool,
  eventSigner: NodeEventSigner | null,
): ReceiveLandingStore {
  return {
    async commitLanding(command: CommitReceiveLandingCommand): Promise<CommitLandingResult> {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const inner = new SqlReceiveLandingStore(
          {
            // Pass-through: node-core's statements run on the transaction opened above, so its
            // "one transaction" contract is satisfied by this client, not by a nested BEGIN.
            withTransaction: async (fn) =>
              fn({
                query: async <R>(text: string, params: readonly unknown[]) => {
                  const result = await client.query(text, params as never[]);
                  return { rows: result.rows as R[] };
                },
              }),
          },
          eventSigner ?? UNAVAILABLE_EVENT_SIGNER,
        );

        const result = await inner.commitLanding(command);
        if (!result.applied) {
          await client.query("ROLLBACK");
          return result;
        }

        // The transaction record reaches SETTLED_BODY_PERSISTED in this same
        // DB-TX. `settled_at` is the proof's landed_at, so the phase and the proof header
        // cite one instant.
        const txQuery = async (text: string, values: readonly unknown[]) => {
          const advanced = await client.query(text, values as never[]);
          return advanced.rows as readonly Record<string, unknown>[];
        };
        await advanceAttemptPhase(
          txQuery,
          command.operationId,
          RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
          { settled_at: new Date(command.proof.landedAtMs).toISOString() },
        );

        // Derived wallet_settled_ledger row (RECEIVER). Same TX as the land
        // so a land without a ledger row cannot commit. Idempotent under ALREADY_LANDED
        // replays that somehow re-enter (CAS usually short-circuits first).
        const settled = await recordWalletSettledLedger(txQuery, {
          operationId: command.operationId,
          landingVerdict: command.proof.verdict,
          pathDepth: command.proof.pathDepth,
          t0ObservationId: command.proof.t0ObservationId,
          terminalObservationId: command.proof.terminalObservationId,
          requiredPathCount: 1,
          verifiedAtIso: new Date(command.proof.landedAtMs).toISOString(),
        });

        // Promote the kind-local receive path into the lineage tables so
        // verification-material source-sql can assemble ancestor_proofs.
        const walletRows = await txQuery(
          `SELECT receiver_wallet_id::text AS id FROM operations WHERE id = $1::uuid`,
          [command.operationId],
        );
        const receiverWalletId =
          (walletRows[0] as { id: string | null } | undefined)?.id ?? null;
        await promoteReceiveLandingPathToLineage(txQuery, {
          operationId: command.operationId,
          landingProofId: settled.landingProofId,
          walletId: receiverWalletId,
          createdAtIso: new Date(command.proof.landedAtMs).toISOString(),
        });

        // Open the proof-access window so GET verification-material is 200.
        await issueLandedAccessWindow(
          txQuery,
          command.operationId,
          command.proof.landedAtMs,
        );

        await client.query("COMMIT");
        return result;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* keep the original failure */
        }
        const classified = classifyReceiveLandingError(err);
        if (classified !== null) {
          return { applied: false, reason: classified, receiverLeaseStillHeld: true };
        }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
