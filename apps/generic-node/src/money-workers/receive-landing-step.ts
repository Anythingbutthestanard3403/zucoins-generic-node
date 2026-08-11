// The landing walk (steps 1–4) for RECEIVE_EXTERNAL, wired end to end.
//
// A receive whose single submit attempt has been signed and sent parks at attempt phase
// `STEP2_SIGNATURE_PERSISTED` with the receiver lease held. This step is what un-parks it:
//
//   1. OBSERVE(receiver_pubkey, RECEIVE_TERMINAL_CHECK) — the durable confirm-read
//      (sql-fresh-head-reader.ts). Its observation-ledger row is the terminal observation.
// 2/3. Any-depth successor bodies are assembled from retained storage via
//      `walkAncestryPath` + `createSqlRetainedPathBodySource` (same path SEND uses). The
//      landing-proof oracle (`proveReceiveLanding` via `verifyAndCommitReceiveLanding`)
//      then reverifies every body from exact signed text, applies the current-exact-head
//      rule by reading the head twice, and re-runs the receive economic predicate against
//      a re-derived T0 — never a cached balance column.
//   4. The landing DB-TX (sql-landing-store.ts).
//
// Closing rule: nothing here mints a landing from a bare head match, and no
// outcome — fault, conflict or crash — rebuilds, resubmits, or releases the receiver lease.
// Every non-APPLIED result is INDETERMINATE: the row stays exactly as it was found, so the
// next tick retries the OBSERVATION, never the transaction.
//
// Crash resume is a property of the shape, not of a recovery routine: the candidate query is
// the resume point (a landed operation no longer matches it), and the DB-TX is the only
// writer. A process death anywhere before COMMIT leaves the parked row untouched.
//
// `readFreshHead` and `store` are injected ports so the whole flow runs offline against a real
// PostgreSQL with a scripted gateway exchange (test/receive-landing-step.pg.test.ts).

import { createHash, randomUUID } from "node:crypto";

import type { Pool } from "pg";

import {
  appendDurableDualChainEvent,
  ATTEMPT_PHASE_LADDER,
  createSqlRetainedPathBodySource,
  DEFAULT_MAX_PATH_DEPTH,
  fetchRetainedBodyByObservationId,
  InMemoryLineagePathProofStore,
  parseGatewayEnvelope,
  RECEIVE_READY_STATUS,
  RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
  verifyAndCommitReceiveLanding,
  verifySettledTransaction,
  walkAncestryPath,
  type CommitReceiveLandingOutcome,
  type DualChainEventQuota,
  type MetricsHooks,
  type NodeEventSigner,
  type ParsedSettledTransaction,
  type PathBaseline,
  type ReadFreshHead,
  type ReceiveLandingStore,
  type RetainedPathBody,
  type RetainedPathBodySource,
  toAttentionReason,
} from "@zucoins/node-core";

/**
 * The phase a signed-and-submitted receive parks at: the frozen attempt-ladder rung immediately
 * before the one this step advances to. Derived rather than spelled so a ladder change is a
 * compile/derivation change here, not silent drift.
 */
export const PARKED_ATTEMPT_PHASE =
  ATTEMPT_PHASE_LADDER[ATTEMPT_PHASE_LADDER.indexOf(RECEIVE_SETTLED_BODY_PERSISTED_PHASE) - 1]!;

export const DEFAULT_LANDING_BATCH = 25;

/**
 * `operation_kind` is a database enum; its label is inlined here for the same reason
 * arm-live.ts inlines its Appendix B vocabulary — @zucoins/generic-node-contracts is a dev
 * dependency of apps/generic-node and is absent from the shipped runtime, so a value import of
 * OPERATION_KINDS would not resolve in production.
 */
const RECEIVE_EXTERNAL_KIND = "RECEIVE_EXTERNAL";

/**
 * Candidates for the landing commit: READY receives whose one attempt is signed and durable,
 * whose receiver lease is still held (One-in-flight), and which have not already landed.
 *
 * `receive_landing_proofs` is the exclusion, not the operation status: it is written by the
 * same DB-TX that flips the status, so the two can never disagree, and reading the proof table
 * keeps this query honest even if a status is repaired by hand.
 */
export const RECEIVE_LANDING_CANDIDATE_SQL = `
  SELECT o.id::text                        AS operation_id,
         o.row_version::text               AS row_version,
         o.amount_zkz                      AS amount_zkz,
         o.t0_observation_id::text         AS t0_observation_id,
         w.public_key                      AS receiver_public_key,
         ot.completed_transaction_text     AS expected_body_text,
         t0.completed_transaction_text     AS t0_body_text
    FROM operations o
    JOIN wallets w
      ON w.id = o.receiver_wallet_id
    JOIN operation_transactions ot
      ON ot.operation_id = o.id AND ot.attempt_no = 1 AND ot.attempt_phase = $3
    JOIN wallet_active_leases l
      ON l.operation_id = o.id AND l.wallet_id = o.receiver_wallet_id
    LEFT JOIN gateway_observations t0
      ON t0.id = o.t0_observation_id
   WHERE o.kind = $1::operation_kind
     AND o.status = $2::operation_status
     AND o.node_id = $5::uuid
     AND ot.completed_transaction_text IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM receive_landing_proofs p WHERE p.operation_id = o.id)
   ORDER BY o.created_at ASC, o.id ASC -- contract-allow:order:frozen structural vocabulary
   LIMIT $4`;

export interface ReceiveLandingCandidate {
  readonly operationId: string;
  readonly rowVersion: number;
  readonly amountZkz: string;
  readonly t0ObservationId: string;
  readonly receiverPublicKey: string;
  readonly expectedBodyText: string;
  /** null when receiver T0 was genesis — the oracle then baselines on GENESIS_PROJECTION. */
  readonly t0BodyText: string | null;
}

export interface ReceiveLandingStepLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface ReceiveLandingStepDeps {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly logger: ReceiveLandingStepLogger;
  /** Step 1 — the durable RECEIVE_TERMINAL_CHECK read (sql-fresh-head-reader.ts). */
  readonly readFreshHead: ReadFreshHead;
  /** Step 4 — the landing DB-TX (sql-landing-store.ts). */
  readonly store: ReceiveLandingStore;
  /** Lifecycle metrics fire only after the landing DB-TX returns APPLIED. */
  readonly metricsHooks?: MetricsHooks;
  readonly batchSize?: number;
  /** Sealed EVENT_SIGNING signer for dual-chain operation.needs_attention (ZTR-1146). */
  readonly eventSigner?: NodeEventSigner | null;
  readonly eventQuota?: DualChainEventQuota;
}

/**
 * Idempotent guarded attention transition for an indeterminate outcome (closing
 * rule: INDETERMINATE parks + sets attention; one event per attention episode).
 *
 * Uses ONE atomic CTE to: (1) CAS attention_required false→true with a closed-set reason +
 * detail, (2) insert the operation.needs_attention event with the next episode number. The
 * schema CHECK `attention_required = (attention_reason IS NOT NULL)` requires both to be set
 * in the same statement. The receiver lease is never touched.
 */

/**
 * Map a non-APPLIED receive-landing outcome onto the frozen attention_reason vocabulary
 * via the single reconcile mapper (ZTR-1147). Free-text detail stays in attention_detail.
 */
function attentionReasonForLandingOutcome(
  outcome: CommitReceiveLandingOutcome,
): ReturnType<typeof toAttentionReason> {
  if (outcome.outcome === "APPLIED") {
    // Caller never parks APPLIED.
    return toAttentionReason({ source: "NO_SUCCESSOR_OBSERVED" });
  }
  if (outcome.outcome === "CONFLICT") {
    switch (outcome.reason) {
      case "STATUS_GUARD_MISMATCH":
      case "ALREADY_LANDED":
        return toAttentionReason({ source: "PATH_DISAGREEMENT" });
      case "LEASE_MISSING":
        return toAttentionReason({ source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" });
      case "PATH_INCOMPLETE":
        return toAttentionReason({
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "GAP",
        });
    }
  }
  if (outcome.outcome === "REJECTED") {
    switch (outcome.reason) {
      case "PROOF_NOT_POSITIVE":
        return toAttentionReason({
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "GAP",
        });
      case "PATH_BODY_UNVERIFIED":
        return toAttentionReason({
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "MALFORMED_BODY",
        });
      case "WALLET_MISMATCH":
        return toAttentionReason({ source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" });
      case "PATH_DEPTH_MISMATCH":
      case "PATH_EXPECTED_ANCHOR_MISMATCH":
      case "PATH_HEAD_ANCHOR_MISMATCH":
      case "PATH_BACKLINK_BROKEN":
        return toAttentionReason({
          source: "LANDING_PROOF_INCOMPLETE",
          fault: "ANOMALOUS_OR_CONTRADICTORY",
        });
    }
  }
  return toAttentionReason({
    source: "LANDING_PROOF_INCOMPLETE",
    fault: "ANOMALOUS_OR_CONTRADICTORY",
  });
}

async function setAttentionForIndeterminate(
  pool: Pool,
  operationId: string,
  reason: ReturnType<typeof toAttentionReason>,
  detail: string,
  dualChain?: {
    readonly nodeId: string;
    readonly eventSigner: NodeEventSigner | null;
    readonly eventQuota?: DualChainEventQuota;
  },
): Promise<void> {
  const dataText = JSON.stringify({
    attention_reason: reason,
    detail,
    at: new Date().toISOString(),
  });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const inserted = await client.query(
      `WITH updated AS (
         UPDATE operations
            SET attention_required = true,
                attention_reason = $2,
                attention_detail = $3
          WHERE id = $1::uuid AND attention_required = false
        RETURNING id
       )
       INSERT INTO receive_expiry_attention_events
         (operation_id, event_type, attention_reason, attention_episode, data_text)
       SELECT $1::uuid, 'operation.needs_attention', $2,
              COALESCE((SELECT MAX(attention_episode)
                          FROM receive_expiry_attention_events
                         WHERE operation_id = $1::uuid), 0) + 1,
              $3
         FROM updated
       WHERE EXISTS (SELECT 1 FROM updated)
       RETURNING operation_id`,
      [operationId, reason, dataText],
    );
    // rowCount = 0 means already attention-flagged (same episode) — idempotent no-op.
    if ((inserted.rowCount ?? 0) > 0 && dualChain !== undefined) {
      const signer = dualChain.eventSigner;
      if (signer === null) {
        throw new Error(
          `receive-landing: operation.needs_attention NOT appended op=${operationId} — EVENT_SIGNING signer unavailable; refusing attention park (Byte-exact)`,
        );
      }
      const owner = await client.query<{
        implementer_id: string;
        receiver_wallet_id: string | null;
      }>(
        `SELECT implementer_id::text AS implementer_id,
                wallet_id::text AS receiver_wallet_id
           FROM receive_operations
          WHERE operation_id = $1::uuid`,
        [operationId],
      );
      const row = owner.rows[0];
      if (row === undefined) {
        throw new Error(
          `receive-landing: operation.needs_attention NOT appended op=${operationId} — receive_operations row missing`,
        );
      }
      await appendDurableDualChainEvent(
        async (text, values) => {
          const result = await client.query(text, values as never);
          return result.rows as Record<string, unknown>[];
        },
        {
          nodeId: dualChain.nodeId,
          implementerId: row.implementer_id,
          operationId,
          walletId: row.receiver_wallet_id,
          eventType: "operation.needs_attention",
          dataText,
          createdAt: new Date().toISOString(),
          signer,
          ...(dualChain.eventQuota !== undefined ? { quota: dualChain.eventQuota } : {}),
        },
      );
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}


export interface ReceiveLandingStepResult {
  readonly landed: readonly string[];
  /** Everything that did not land. indeterminate, never a proven non-landing. */
  readonly indeterminate: readonly { readonly operationId: string; readonly detail: string }[];
}

/**
 * Re-read a durably persisted `completed_transaction_text` as a parsed settled transaction,
 * through the exact observation envelope stage the gateway path uses — same key-sequence and
 * scalar exactness, no bespoke parser and no JSON.parse here.
 *
 * The round trip is then byte-compared (the byte-exact signing rule): if re-serializing the
 * parse does not reproduce the stored bytes, the stored body has been normalized and is
 * refused rather than landed.
 */
export function parseStoredSettledBody(text: string): ParsedSettledTransaction | null {
  const envelope = parseGatewayEnvelope(
    Buffer.from(`{"status":true,"code":"ok","message":"","data":[${text}]}`, "utf8"),
  );
  if (envelope.classification !== "HEAD") return null;
  return JSON.stringify(envelope.parsed) === text ? envelope.parsed : null;
}

export async function loadReceiveLandingCandidates(
  pool: Pool,
  nodeId: string,
  batchSize: number,
): Promise<readonly ReceiveLandingCandidate[]> {
  const result = await pool.query<{
    operation_id: string;
    row_version: string;
    amount_zkz: string;
    t0_observation_id: string;
    receiver_public_key: string;
    expected_body_text: string;
    t0_body_text: string | null;
  }>(RECEIVE_LANDING_CANDIDATE_SQL, [
    RECEIVE_EXTERNAL_KIND,
    RECEIVE_READY_STATUS,
    PARKED_ATTEMPT_PHASE,
    batchSize,
    nodeId,
  ]);
  return result.rows.map((row) => ({
    operationId: row.operation_id,
    rowVersion: Number(row.row_version),
    amountZkz: row.amount_zkz,
    t0ObservationId: row.t0_observation_id,
    receiverPublicKey: row.receiver_public_key,
    expectedBodyText: row.expected_body_text,
    t0BodyText: row.t0_body_text,
  }));
}

/**
 * Build an EXPECTED_OPERATION retained body from the attempt's exact settled bytes.
 * Columns are re-derived via verifySettledTransaction so verifyHop's column binding holds.
 * observation_id is a synthetic locator — the walk never probes it as a ledger key.
 */
export function retainedExpectedBodyFromSettledText(
  expectedBodyText: string,
  walletPublicKey: string,
): RetainedPathBody | null {
  const parsed = parseStoredSettledBody(expectedBodyText);
  if (parsed === null) return null;
  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict !== "VERIFIED") return null;
  const { role, S, P, B } = verdict.projection;
  if (role !== "sender" && role !== "receiver") return null;
  return {
    source_kind: "EXPECTED_OPERATION",
    observation_id: randomUUID(),
    wallet_public_key: walletPublicKey,
    completed_transaction_text: expectedBodyText,
    completed_transaction_sha256: verdict.completedTransactionSha256,
    completed_transaction_octets: Buffer.byteLength(expectedBodyText, "utf8"),
    wallet_role: role,
    s_signature: S,
    p_signature: P,
    b_amount: B,
    inner_preimage_text: verdict.innerPreimageText,
    inner_sha256: createHash("sha256").update(verdict.innerPreimageText, "utf8").digest("hex"),
    step_1_signature: parsed.step_1_signature,
    step_2_signature: parsed.step_2_signature,
    semantic_fingerprint: verdict.semanticFingerprint,
  };
}

export interface ResolveReceiveSuccessorsDeps {
  readonly readFreshHead: ReadFreshHead;
  /** Production: createSqlRetainedPathBodySource({ sql: pool }). Tests inject InMemory. */
  readonly retainedSource: RetainedPathBodySource;
  /**
   * SQL port for T0 observation lookup when baseline is not injected. Production always
   * passes the pool; unit tests may omit it and inject `baseline` instead.
   */
  readonly sql?: {
    query<R extends Record<string, unknown>>(
      text: string,
      params: readonly unknown[],
    ): Promise<{ rows: readonly R[] }>;
  };
  /** Optional override when T0 is not on the observation ledger (unit tests). */
  readonly baseline?: PathBaseline;
}

/**
 * Resolve the ordered successor body list T_expected+1 … T_head via the retained-path
 * walk (same engine SEND uses). Finite depth budget is explicit (DEFAULT_MAX_PATH_DEPTH).
 *
 * - Depth 0 (expected is the fresh head): returns [].
 * - Depth ≥ 1: returns the verified successor ParsedSettledTransaction bodies.
 * - Unprovable path (missing body, gap, anomaly, moved head, budget): null → INDETERMINATE.
 */
export async function resolveReceiveSuccessorBodies(
  candidate: ReceiveLandingCandidate,
  deps: ResolveReceiveSuccessorsDeps,
  maxPathDepth: number = DEFAULT_MAX_PATH_DEPTH,
): Promise<readonly ParsedSettledTransaction[] | null> {
  const retainedExpected = retainedExpectedBodyFromSettledText(
    candidate.expectedBodyText,
    candidate.receiverPublicKey,
  );
  if (retainedExpected === null) return null;

  let baseline: PathBaseline;
  if (deps.baseline !== undefined) {
    baseline = deps.baseline;
  } else if (candidate.t0BodyText === null) {
    baseline = { kind: "GENESIS", observation_id: candidate.t0ObservationId };
  } else if (deps.sql !== undefined) {
    const t0Retained = await fetchRetainedBodyByObservationId(
      { sql: deps.sql },
      candidate.t0ObservationId,
    );
    if (t0Retained === null) {
      // Retention miss on T0: rebuild from the candidate's retained text (same bytes).
      const t0Body = retainedExpectedBodyFromSettledText(
        candidate.t0BodyText,
        candidate.receiverPublicKey,
      );
      if (t0Body === null) return null;
      baseline = {
        kind: "HEAD",
        body: {
          ...t0Body,
          source_kind: "CANONICAL_LEDGER",
          observation_id: candidate.t0ObservationId,
        },
      };
    } else {
      baseline = { kind: "HEAD", body: t0Retained };
    }
  } else {
    const t0Body = retainedExpectedBodyFromSettledText(
      candidate.t0BodyText,
      candidate.receiverPublicKey,
    );
    if (t0Body === null) return null;
    baseline = {
      kind: "HEAD",
      body: {
        ...t0Body,
        source_kind: "CANONICAL_LEDGER",
        observation_id: candidate.t0ObservationId,
      },
    };
  }

  try {
    const walkOutcome = await walkAncestryPath(
      {
        pathProofId: randomUUID(),
        landingProofId: randomUUID(),
        walletId: null,
        walletPublicKey: candidate.receiverPublicKey,
        operation: {
          kind: "RECEIVE_EXTERNAL",
          amountZkz: candidate.amountZkz,
          receiverPubkey: candidate.receiverPublicKey,
        },
        expectedBody: retainedExpected,
        baseline,
        maxPathDepth,
      },
      deps.retainedSource,
      deps.readFreshHead,
      new InMemoryLineagePathProofStore(),
    );
    if (walkOutcome.kind !== "PATH_PROVEN") {
      return null;
    }
    const successors: ParsedSettledTransaction[] = [];
    for (const row of walkOutcome.bodies.slice(1)) {
      const parsed = parseStoredSettledBody(row.completed_transaction_text);
      if (parsed === null) return null;
      successors.push(parsed);
    }
    return successors;
  } catch {
    return null;
  }
}

/**
 * The landing walk for one candidate. Returns the node-core outcome verbatim; every non-APPLIED
 * result leaves the durable row exactly as it was found.
 */
export async function landOneReceive(
  candidate: ReceiveLandingCandidate,
  deps: Pick<ReceiveLandingStepDeps, "pool" | "readFreshHead" | "store">,
  options?: {
    readonly maxPathDepth?: number;
    /** Test seam — production always uses createSqlRetainedPathBodySource({ sql: pool }). */
    readonly retainedSource?: RetainedPathBodySource;
    readonly baseline?: PathBaseline;
  },
): Promise<CommitReceiveLandingOutcome> {
  const expectedBody = parseStoredSettledBody(candidate.expectedBodyText);
  if (expectedBody === null) {
    return {
      outcome: "REJECTED",
      reason: "PATH_BODY_UNVERIFIED",
      detail: "persisted completed transaction did not re-read as its exact signed bytes",
    };
  }
  const t0Body =
    candidate.t0BodyText === null ? null : parseStoredSettledBody(candidate.t0BodyText);
  if (candidate.t0BodyText !== null && t0Body === null) {
    return {
      outcome: "REJECTED",
      reason: "PATH_BODY_UNVERIFIED",
      detail: "persisted receiver T0 body did not re-read as its exact signed bytes",
    };
  }

  const maxPathDepth = options?.maxPathDepth ?? DEFAULT_MAX_PATH_DEPTH;
  const retainedSource =
    options?.retainedSource ?? createSqlRetainedPathBodySource({ sql: deps.pool });

  // Any-depth successors from retained storage (Q6). Depth 0 → []. Fail-closed null →
  // INDETERMINATE (no rebuild, no resubmit, lease untouched).
  const successors = await resolveReceiveSuccessorBodies(
    candidate,
    {
      readFreshHead: deps.readFreshHead,
      retainedSource,
      sql: deps.pool,
      baseline: options?.baseline,
    },
    maxPathDepth,
  );
  if (successors === null) {
    return {
      outcome: "REJECTED",
      reason: "PROOF_NOT_POSITIVE",
      detail: "receive landing path unprovable from retained bodies (INDETERMINATE)",
    };
  }

  // Steps 2–4. The landing-proof rule oracle (proveReceiveLanding, driven through
  // verifyAndCommitReceiveLanding) does its OWN durable confirm-read via readFreshHead and
  // binds the terminal observation to that read's observation ID. A preliminary read is NOT
  // needed — it would produce a different observation ID on a byte-changed wrapper
  // and cause a PATH_HEAD_ANCHOR_MISMATCH. The oracle's own freshHeadObservationId is the
  // authoritative terminal observation (review P1 fix).
  return verifyAndCommitReceiveLanding(
    {
      walletPubkeyBase64Urlsafe: candidate.receiverPublicKey,
      t0Body,
      expectedBody,
      successorBodies: successors,
      operation: {
        amountZkz: candidate.amountZkz,
        receiverPubkey: candidate.receiverPublicKey,
      },
      maxDepth: maxPathDepth,
    },
    {
      operationId: candidate.operationId,
      expectedRowVersion: candidate.rowVersion,
      t0ObservationId: candidate.t0ObservationId,
      // Placeholder — verifyAndCommitReceiveLanding overrides this with the oracle's
      // own freshHeadObservationId after the confirm-read.
      terminalObservationId: "",
    },
    deps.readFreshHead,
    deps.store,
  );
}

/** One tick of the landing step over every parked candidate. */
export async function runReceiveLandingStep(
  deps: ReceiveLandingStepDeps,
): Promise<ReceiveLandingStepResult> {
  const candidates = await loadReceiveLandingCandidates(
    deps.pool,
    deps.nodeId,
    deps.batchSize ?? DEFAULT_LANDING_BATCH,
  );
  const landed: string[] = [];
  const indeterminate: { operationId: string; detail: string }[] = [];

  for (const candidate of candidates) {
    let outcome: CommitReceiveLandingOutcome;
    try {
      outcome = await landOneReceive(candidate, deps);
    } catch (err) {
      // A read or persist failure decides nothing. Log and leave the row parked.
      deps.logger.error(`receive-landing: op=${candidate.operationId} INDETERMINATE`, err);
      indeterminate.push({
        operationId: candidate.operationId,
        detail: err instanceof Error ? err.message : "landing attempt failed",
      });
      // Set attention for the thrown error too (INDETERMINATE parks).
      try {
        await setAttentionForIndeterminate(
          deps.pool,
          candidate.operationId,
          toAttentionReason({
            source: "LANDING_PROOF_INCOMPLETE",
            fault: "ANOMALOUS_OR_CONTRADICTORY",
          }),
          `INDETERMINATE: ${err instanceof Error ? err.message : "landing attempt failed"}`,
          {
            nodeId: deps.nodeId,
            eventSigner: deps.eventSigner ?? null,
            ...(deps.eventQuota !== undefined ? { eventQuota: deps.eventQuota } : {}),
          },
        );
      } catch {
        // An attention-set failure never causes a landing or resubmit. Log only.
        deps.logger.error(
          `receive-landing: op=${candidate.operationId} attention-set failed (thrown)`,
          err,
        );
      }
      continue;
    }

    if (outcome.outcome === "APPLIED") {
      landed.push(candidate.operationId);
      deps.metricsHooks?.onOperationCompleted("RECEIVE_EXTERNAL");
      deps.logger.info(
        `receive-landing: op=${candidate.operationId} ${outcome.status} ` +
          `verdict=${outcome.proof.verdict} depth=${outcome.proof.pathDepth} ` +
          `terminal_observation=${outcome.proof.terminalObservationId} (receiver lease still held)`,
      );
      continue;
    }

    indeterminate.push({
      operationId: candidate.operationId,
      detail: `${outcome.outcome}/${outcome.reason}: ${outcome.detail}`,
    });
    deps.logger.info(
      `receive-landing: op=${candidate.operationId} not landed — ${outcome.outcome}/${outcome.reason} ` +
        `(no rebuild, no resubmit, lease untouched)`,
    );
    // Closing rule: a gap, malformed response, or incompatible head sets attention and
    // emits operation.needs_attention (one event per attention episode; INDETERMINATE
    // parks + retains leases). Idempotent: only the first indeterminate observation opens a
    // new episode; subsequent ones in the same episode are no-ops.
    try {
      await setAttentionForIndeterminate(
        deps.pool,
        candidate.operationId,
        attentionReasonForLandingOutcome(outcome),
        `${outcome.outcome}/${outcome.reason}: ${outcome.detail}`,
        {
          nodeId: deps.nodeId,
          eventSigner: deps.eventSigner ?? null,
          ...(deps.eventQuota !== undefined ? { eventQuota: deps.eventQuota } : {}),
        },
      );
    } catch (attentionErr) {
      // An attention-set failure never causes a landing, resubmit, or lease release. Log only.
      deps.logger.error(
        `receive-landing: op=${candidate.operationId} attention-set failed`,
        attentionErr,
      );
    }
  }

  return { landed, indeterminate };
}
