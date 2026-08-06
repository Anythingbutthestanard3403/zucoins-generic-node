// production `RetainedPathBodySource` (ancestry-walker.ts) against the already-
// durable observation ledger (gateway_observations).
//
// Covers buried SEND completion landing and the landing-path oracle any-depth complete-path landing
// oracle, retained-body forward walk); landing-path oracle.
//
// Both probes are single indexed lookups — gateway_observations_successor_by_backlink_idx
// and gateway_observations_completed_tx_digest_idx (gateway-observation-successor-
// indexes.sql) — so a walk of depth N costs O(N) probes here, never a full-table scan
// (the RetainedPathBodySource contract's own anti-scan requirement).
//
// Read-only, and structurally so: this file issues exactly two SELECTs and no write.
// `walkAncestryPath`'s own `readFreshHead` port remains the only path that can land a new
// observation row (the never-blind-retry rule — no blind resubmission is even reachable from here).
//
// Every field this adapter returns is re-derived and cross-checked from
// `completed_transaction_text` inside `walkAncestryPath`'s own `verifyHop` — a supplied
// column here is provenance, never authority ("source_kind records provenance only
// and grants no authority").

import { createHash } from "node:crypto";

import type {
  LineagePathBodySourceKind,
  RetainedPathBody,
  RetainedPathBodySource,
  SuccessorResolution,
} from "./ancestry-walker.js";

/** Minimal query port — the same shape `createSqlStreamWriterEffects` already accepts. */
export interface SqlQueryPort {
  query<R extends Record<string, unknown>>(
    text: string,
    params: readonly unknown[],
  ): Promise<{ rows: readonly R[] }>;
}

export interface SqlRetainedPathBodySourceDeps {
  readonly sql: SqlQueryPort;
}

interface SuccessorRow extends Record<string, unknown> {
  readonly observation_id: string;
  readonly wallet_public_key: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly wallet_role: "sender" | "receiver";
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly inner_preimage_text: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly semantic_fingerprint: string;
}

function toRetainedPathBody(
  row: SuccessorRow,
  sourceKind: LineagePathBodySourceKind,
): RetainedPathBody {
  return {
    source_kind: sourceKind,
    observation_id: row.observation_id,
    wallet_public_key: row.wallet_public_key,
    completed_transaction_text: row.completed_transaction_text,
    completed_transaction_sha256: row.completed_transaction_sha256,
    completed_transaction_octets: Buffer.byteLength(row.completed_transaction_text, "utf8"),
    wallet_role: row.wallet_role,
    s_signature: row.s_signature,
    p_signature: row.p_signature,
    b_amount: row.b_amount,
    inner_preimage_text: row.inner_preimage_text,
    // Not a stored column (there is no inner_sha256); computed the same way every other
    // RetainedPathBody producer in this package does, over the retained inner preimage text.
    inner_sha256: createHash("sha256").update(row.inner_preimage_text, "utf8").digest("hex"),
    step_1_signature: row.step_1_signature,
    step_2_signature: row.step_2_signature,
    semantic_fingerprint: row.semantic_fingerprint,
  };
}

/**
 * Build the production `RetainedPathBodySource`. `resolveSuccessorByBacklink` mirrors
 * `InMemoryRetainedPathBodySource`'s test semantics exactly: candidates are grouped by
 * wallet + backlink, de-duplicated by EXACT completed_transaction_text, then classified
 * NONE / FOUND / AMBIGUOUS — never a silent pick among conflicting bodies (a fork, not a
 * choice). `countDistinctBodiesWithDigest` is global, matching the in-memory fixture.
 */
export function createSqlRetainedPathBodySource(
  deps: SqlRetainedPathBodySourceDeps,
): RetainedPathBodySource {
  return {
    async resolveSuccessorByBacklink(
      walletPublicKey: string,
      previousStateSignature: string,
    ): Promise<SuccessorResolution> {
      const { rows } = await deps.sql.query<SuccessorRow>(
        `SELECT id::text AS observation_id, wallet_public_key, completed_transaction_text,
                completed_transaction_sha256, wallet_role, s_signature, p_signature,
                b_amount, inner_preimage_text, step_1_signature, step_2_signature,
                semantic_fingerprint
           FROM gateway_observations
          WHERE wallet_public_key = $1
            AND p_signature = $2
            AND parse_result = 'VERIFIED_HEAD'`,
        [walletPublicKey, previousStateSignature],
      );

      const distinct = new Map<string, SuccessorRow>();
      for (const row of rows) {
        if (!distinct.has(row.completed_transaction_text)) {
          distinct.set(row.completed_transaction_text, row);
        }
      }
      if (distinct.size === 0) return { kind: "NONE" };
      if (distinct.size > 1) return { kind: "AMBIGUOUS" };
      const [only] = distinct.values();
      return { kind: "FOUND", body: toRetainedPathBody(only!, "FRESH_GATEWAY_HEAD") };
    },

    async countDistinctBodiesWithDigest(bodySha256: string): Promise<number> {
      const { rows } = await deps.sql.query<{ count: string }>(
        `SELECT COUNT(DISTINCT completed_transaction_text) AS count
           FROM gateway_observations
          WHERE completed_transaction_sha256 = $1`,
        [bodySha256],
      );
      return Number(rows[0]?.count ?? 0);
    },
  };
}

const SUCCESSOR_ROW_COLUMNS = `id::text AS observation_id, wallet_public_key, completed_transaction_text,
                completed_transaction_sha256, wallet_role, s_signature, p_signature,
                b_amount, inner_preimage_text, step_1_signature, step_2_signature,
                semantic_fingerprint`;

/**
 * fetch T0's own retained body by its `gateway_observations.id` primary key, for
 * `PathBaseline.HEAD.body` when a buried SEND's T0 observation carried a completed body
 * (`sourceT0BodyText !== null`). Tagged `CANONICAL_LEDGER` (this is the wallet's
 * already-durable T0 record, never the operation's own expected body and never a freshly
 * read head) — the tag is provenance only; `verifyHop` re-derives everything from the bytes.
 * A primary-key lookup can return at most one row, so there is no ambiguity branch.
 */
export async function fetchRetainedBodyByObservationId(
  deps: SqlRetainedPathBodySourceDeps,
  observationId: string,
): Promise<RetainedPathBody | null> {
  const { rows } = await deps.sql.query<SuccessorRow>(
    `SELECT ${SUCCESSOR_ROW_COLUMNS}
       FROM gateway_observations
      WHERE id = $1::uuid`,
    [observationId],
  );
  const [row] = rows;
  return row === undefined ? null : toRetainedPathBody(row, "CANONICAL_LEDGER");
}

/**
 * find OUR OWN send's completed body wherever it currently sits (buried or at
 * head), by the one thing that identifies it independent of chain position: the wallet's
 * public key plus the step-1 signature the node signed in advance. This is the buried
 * walk's `AncestryWalkInput.expectedBody` — the node never learns step-2 from its own
 * records (only from independent observation), so this lookup is the only source for it.
 * Tagged `EXPECTED_OPERATION` — `walkAncestryPath` requires exactly that tag at path_index
 * 0 and fails closed (`ANOMALOUS_OR_CONTRADICTORY`) otherwise.
 *
 * Two or more distinct completed bodies sharing the same step-1 signature is a fork, not a
 * choice: `AMBIGUOUS`, never a silent pick (mirrors `resolveSuccessorByBacklink`).
 */
export async function fetchRetainedBodyByStepOneSignature(
  deps: SqlRetainedPathBodySourceDeps,
  walletPublicKey: string,
  step1Signature: string,
): Promise<SuccessorResolution> {
  const { rows } = await deps.sql.query<SuccessorRow>(
    `SELECT ${SUCCESSOR_ROW_COLUMNS}
       FROM gateway_observations
      WHERE wallet_public_key = $1
        AND step_1_signature = $2
        AND parse_result = 'VERIFIED_HEAD'`,
    [walletPublicKey, step1Signature],
  );

  const distinct = new Map<string, SuccessorRow>();
  for (const row of rows) {
    if (!distinct.has(row.completed_transaction_text)) {
      distinct.set(row.completed_transaction_text, row);
    }
  }
  if (distinct.size === 0) return { kind: "NONE" };
  if (distinct.size > 1) return { kind: "AMBIGUOUS" };
  const [only] = distinct.values();
  return { kind: "FOUND", body: toRetainedPathBody(only!, "EXPECTED_OPERATION") };
}
