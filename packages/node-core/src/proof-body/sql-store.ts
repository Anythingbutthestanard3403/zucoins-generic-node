import type {
  ProofBodySighting,
  ProofBodyStore,
  StoredProofBody,
  TransactionalProofBodyStore,
} from "./persist.js";
import type { ProofBodyWalletRole } from "./types.js";

// durable Postgres-backed ProofBodyStore.
//
// Implements the lineage_path_bodies body shape and the consecutive_repeat_count counter
// model, with idempotency, non-authority, and the sighting counter, under the
// landing-path oracle. Schema contract: src/schema/proof-body-store.sql (+ .contract.ts,
// censused by test/proof-body-store.census.test.ts).
//
// This is the REAL store implementing the FROZEN ProofBodyStore port from persist.ts. It
// is DRIVER-AGNOSTIC: it never imports `pg`. node-core is network-contained and
// deliberately depends on no database driver; the pg Pool is injected at the composition
// root (apps/node), which is the only layer that touches a socket. The store issues exactly
// the parameterized statements catalogued in STATEMENTS against three tables:
// - proof_channel_candidate_bodies : the body shape + intake bookkeeping; its
// (tenant_id, operation_id, idempotency_key) UNIQUE is the durable idempotency ledger.
// - proof_body_slot_sighting_counters / proof_body_tenant_sighting_counters : the bounded
// sighting COUNTERs (not an append-ledger) that back countSightingsBySlot / ByTenant.
//
// non-authority: the store persists candidate evidence only. It has no method and
// issues no statement that sets a verdict, records a landing, or releases a lease.
//
// Cross-call atomicity: the frozen port exposes no transaction seam, so serializability of
// the persist.ts cap-read / insert / increment sequence is the composition root's
// responsibility (one transaction per persistProofBody under a per-(path_proof_id) advisory
// lock; see the proof-body-store.contract.ts obligations). The store faithfully issues the
// statements; it does not open transactions it cannot see the boundaries of.

// The narrow node-postgres-shaped query surface the store depends on. `pg.Pool` and
// `pg.PoolClient` both satisfy it structurally; a test double implements it in-process.
export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

export interface SqlTransactionRunner {
  transaction<T>(body: (sql: SqlExecutor) => Promise<T>): Promise<T>;
}

// The exact column sequence the candidate table stores and this store selects. Kept as one
// constant so the INSERT column list, the SELECT projection, and the row mapper cannot
// drift apart.
export const CANDIDATE_COLUMNS = [
  "path_proof_id",
  "path_index",
  "source_kind",
  "completed_transaction_text",
  "completed_transaction_sha256",
  "completed_transaction_octets",
  "wallet_role",
  "s_signature",
  "p_signature",
  "b_amount",
  "inner_preimage_text",
  "inner_sha256",
  "step_1_signature",
  "step_2_signature",
  "verification_manifest_text",
  "verification_manifest_sha256",
  "raw_bytes_sha256",
  "tenant_id",
  "operation_id",
  "idempotency_key",
  "persisted_at",
] as const;

const CANDIDATE_SELECT = CANDIDATE_COLUMNS.join(", ");
const CANDIDATE_INSERT_PLACEHOLDERS = CANDIDATE_COLUMNS.map((_, i) => `$${i + 1}`).join(", ");

// Statement catalogue. The in-process test executor matches on these exact strings, so any
// statement change here that the executor does not model fails the suite loudly rather than
// drifting silently.
export const STATEMENTS = {
  INSERT_CANDIDATE: `INSERT INTO proof_channel_candidate_bodies (${CANDIDATE_COLUMNS.join(
    ", ",
  )}) VALUES (${CANDIDATE_INSERT_PLACEHOLDERS})`,
  SELECT_BY_SLOT: `SELECT ${CANDIDATE_SELECT} FROM proof_channel_candidate_bodies WHERE path_proof_id = $1 AND path_index = $2`,
  SELECT_BY_PATH: `SELECT ${CANDIDATE_SELECT} FROM proof_channel_candidate_bodies WHERE path_proof_id = $1 ORDER BY path_index ASC`, // contract-allow:order:frozen-sql-text
  SELECT_BY_OPERATION_PATH: `SELECT ${CANDIDATE_SELECT} FROM proof_channel_candidate_bodies WHERE operation_id = $1 AND path_index = $2`,
  SELECT_BY_DIGEST: `SELECT ${CANDIDATE_SELECT} FROM proof_channel_candidate_bodies WHERE raw_bytes_sha256 = $1`,
  SELECT_BY_IDEMPOTENCY: `SELECT ${CANDIDATE_SELECT} FROM proof_channel_candidate_bodies WHERE tenant_id = $1 AND operation_id = $2 AND idempotency_key = $3`,
  COUNT_BY_TENANT: `SELECT count(*)::bigint AS n FROM proof_channel_candidate_bodies WHERE tenant_id = $1`,
  COUNT_BY_OPERATION: `SELECT count(*)::bigint AS n FROM proof_channel_candidate_bodies WHERE operation_id = $1`,
  COUNT_BY_ROLE: `SELECT count(*)::bigint AS n FROM proof_channel_candidate_bodies WHERE tenant_id = $1 AND wallet_role = $2`,
  SUM_BYTES_BY_TENANT: `SELECT coalesce(sum(completed_transaction_octets), 0)::bigint AS n FROM proof_channel_candidate_bodies WHERE tenant_id = $1`,
  UPSERT_SLOT_COUNTER: `INSERT INTO proof_body_slot_sighting_counters (path_proof_id, path_index, sighting_count) VALUES ($1, $2, 1) ON CONFLICT (path_proof_id, path_index) DO UPDATE SET sighting_count = proof_body_slot_sighting_counters.sighting_count + 1`,
  UPSERT_TENANT_COUNTER: `INSERT INTO proof_body_tenant_sighting_counters (tenant_id, sighting_count) VALUES ($1, 1) ON CONFLICT (tenant_id) DO UPDATE SET sighting_count = proof_body_tenant_sighting_counters.sighting_count + 1`,
  SELECT_SLOT_COUNTER: `SELECT sighting_count FROM proof_body_slot_sighting_counters WHERE path_proof_id = $1 AND path_index = $2`,
  SELECT_TENANT_COUNTER: `SELECT sighting_count FROM proof_body_tenant_sighting_counters WHERE tenant_id = $1`,
} as const;

// A candidate row as it comes back from the driver: bigint columns arrive as strings
// (node-postgres default), timestamps as strings; everything else as text.
interface CandidateRow {
  readonly path_proof_id: string;
  readonly path_index: string;
  readonly source_kind: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: string;
  readonly wallet_role: string;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly verification_manifest_text: string;
  readonly verification_manifest_sha256: string;
  readonly raw_bytes_sha256: string;
  readonly tenant_id: string;
  readonly operation_id: string;
  readonly idempotency_key: string;
  readonly persisted_at: string;
}

interface CountRow {
  readonly n: string;
}

interface CounterRow {
  readonly sighting_count: string;
}

function toStoredProofBody(row: CandidateRow): StoredProofBody {
  return {
    path_proof_id: row.path_proof_id,
    path_index: Number(row.path_index),
    // Guaranteed by the candidate table's source_kind CHECK.
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: row.completed_transaction_text,
    completed_transaction_sha256: row.completed_transaction_sha256,
    completed_transaction_octets: Number(row.completed_transaction_octets),
    // Guaranteed by the wallet_role CHECK.
    wallet_role: row.wallet_role as ProofBodyWalletRole,
    s_signature: row.s_signature,
    p_signature: row.p_signature,
    b_amount: row.b_amount,
    inner_preimage_text: row.inner_preimage_text,
    inner_sha256: row.inner_sha256,
    step_1_signature: row.step_1_signature,
    step_2_signature: row.step_2_signature,
    verification_manifest_text: row.verification_manifest_text,
    verification_manifest_sha256: row.verification_manifest_sha256,
    raw_bytes_sha256: row.raw_bytes_sha256,
    tenant_id: row.tenant_id,
    operation_id: row.operation_id,
    idempotency_key: row.idempotency_key,
    persisted_at: row.persisted_at,
  };
}

export class SqlProofBodyStore implements ProofBodyStore {
  readonly transaction?: TransactionalProofBodyStore["transaction"];

  constructor(
    private readonly sql: SqlExecutor,
    transactionRunner?: SqlTransactionRunner,
  ) {
    if (transactionRunner !== undefined) {
      this.transaction = (body) =>
        transactionRunner.transaction((txSql) => body(new SqlProofBodyStore(txSql)));
    }
  }

  async findByPathProofAndIndex(
    pathProofId: string,
    pathIndex: number,
  ): Promise<StoredProofBody | null> {
    const { rows } = await this.sql.query<CandidateRow>(STATEMENTS.SELECT_BY_SLOT, [
      pathProofId,
      pathIndex,
    ]);
    return rows[0] !== undefined ? toStoredProofBody(rows[0]) : null;
  }

  async findByPathProof(pathProofId: string): Promise<StoredProofBody[]> {
    const { rows } = await this.sql.query<CandidateRow>(STATEMENTS.SELECT_BY_PATH, [pathProofId]);
    return rows.map(toStoredProofBody);
  }

  async findByOperationAndPathIndex(
    operationId: string,
    pathIndex: number,
  ): Promise<StoredProofBody[]> {
    const { rows } = await this.sql.query<CandidateRow>(STATEMENTS.SELECT_BY_OPERATION_PATH, [
      operationId,
      pathIndex,
    ]);
    return rows.map(toStoredProofBody);
  }

  async findByBodyDigest(digest: string): Promise<StoredProofBody[]> {
    const { rows } = await this.sql.query<CandidateRow>(STATEMENTS.SELECT_BY_DIGEST, [digest]);
    return rows.map(toStoredProofBody);
  }

  // Lets any driver error (including a 23505 unique_violation) propagate: persist.ts owns
  // the try/catch that maps a unique_violation to DIGEST_COLLISION on the TOCTOU race.
  async insert(row: StoredProofBody): Promise<void> {
    await this.sql.query(STATEMENTS.INSERT_CANDIDATE, [
      row.path_proof_id,
      row.path_index,
      row.source_kind,
      row.completed_transaction_text,
      row.completed_transaction_sha256,
      row.completed_transaction_octets,
      row.wallet_role,
      row.s_signature,
      row.p_signature,
      row.b_amount,
      row.inner_preimage_text,
      row.inner_sha256,
      row.step_1_signature,
      row.step_2_signature,
      row.verification_manifest_text,
      row.verification_manifest_sha256,
      row.raw_bytes_sha256,
      row.tenant_id,
      row.operation_id,
      row.idempotency_key,
      row.persisted_at,
    ]);
  }

  // One sighting = one +1 UPSERT on the slot counter AND one on the tenant counter. Both
  // must land inside the same composition-root transaction (a schema obligation); the store
  // issues them slot-counter first, then tenant-counter.
  async insertSighting(sighting: ProofBodySighting): Promise<void> {
    await this.sql.query(STATEMENTS.UPSERT_SLOT_COUNTER, [
      sighting.path_proof_id,
      sighting.path_index,
    ]);
    await this.sql.query(STATEMENTS.UPSERT_TENANT_COUNTER, [sighting.tenant_id]);
  }

  async countSightingsBySlot(pathProofId: string, pathIndex: number): Promise<number> {
    const { rows } = await this.sql.query<CounterRow>(STATEMENTS.SELECT_SLOT_COUNTER, [
      pathProofId,
      pathIndex,
    ]);
    return rows[0] !== undefined ? Number(rows[0].sighting_count) : 0;
  }

  async countSightingsByTenant(tenantId: string): Promise<number> {
    const { rows } = await this.sql.query<CounterRow>(STATEMENTS.SELECT_TENANT_COUNTER, [
      tenantId,
    ]);
    return rows[0] !== undefined ? Number(rows[0].sighting_count) : 0;
  }

  async countByTenant(tenantId: string): Promise<number> {
    const { rows } = await this.sql.query<CountRow>(STATEMENTS.COUNT_BY_TENANT, [tenantId]);
    return rows[0] !== undefined ? Number(rows[0].n) : 0;
  }

  async countByOperation(operationId: string): Promise<number> {
    const { rows } = await this.sql.query<CountRow>(STATEMENTS.COUNT_BY_OPERATION, [operationId]);
    return rows[0] !== undefined ? Number(rows[0].n) : 0;
  }

  async countByRole(tenantId: string, role: string): Promise<number> {
    const { rows } = await this.sql.query<CountRow>(STATEMENTS.COUNT_BY_ROLE, [tenantId, role]);
    return rows[0] !== undefined ? Number(rows[0].n) : 0;
  }

  async totalBytesByTenant(tenantId: string): Promise<number> {
    const { rows } = await this.sql.query<CountRow>(STATEMENTS.SUM_BYTES_BY_TENANT, [tenantId]);
    return rows[0] !== undefined ? Number(rows[0].n) : 0;
  }

  async findByIdempotencyKey(
    tenantId: string,
    operationId: string,
    key: string,
  ): Promise<StoredProofBody | null> {
    const { rows } = await this.sql.query<CandidateRow>(STATEMENTS.SELECT_BY_IDEMPOTENCY, [
      tenantId,
      operationId,
      key,
    ]);
    return rows[0] !== undefined ? toStoredProofBody(rows[0]) : null;
  }
}
