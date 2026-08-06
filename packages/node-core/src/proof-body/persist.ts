import type {
  AuthenticatedRequestIdentity,
  ProofBodyAccepted,
  ProofBodyWalletRole,
} from "./types.js";

// authenticated bounded proof-body persistence LOGIC.
//
// Idempotency semantics, non-authority, and the dedup / sighting counter all bind here,
// under the landing-path oracle.
//
// SCOPE — persistence-logic only; the durable schema is deferred.
// This module implements the persistence ALGORITHM — idempotency, deduplication,
// digest-collision quarantine, role-mapping-conflict rejection, and bounded quotas —
// over the abstract `ProofBodyStore` port. It is NOT the durable store and asserts NO
// durability: the only implementation today is an in-memory test double, so any
// "no body dropped across restart" property belongs to the durable store and is
// neither implemented nor asserted here.
//
// `StoredProofBody` and `ProofBodySighting` are this logic's WORKING shapes, NOT the
// frozen `lineage_path_bodies` row (PK (path_proof_id, path_index); 17 columns, no
// tenant / operation / idempotency / sighting columns). They fold in request-scoped
// bookkeeping (tenant_id, operation_id, idempotency_key, persisted_at, raw_bytes_sha256)
// and a dedup-observability sighting record the schema does not model. The durable store owns
// the reconciliation: the exact `lineage_path_bodies` table plus SEPARATE idempotency-key
// and dedup bookkeeping. Appending once and incrementing a sighting counter, and
// `wallet_observation_cursors.consecutive_repeat_count`, indicate the durable store should model
// dedup observability as a bounded COUNTER, not the append-ledger used here; until then
// the append-ledger is DoS-bounded by the sighting caps below (per-slot AND per-tenant).
//
// Non-authority invariant (landing-path oracle): this module NEVER sets a verdict, releases a lease,
// or authorizes a retry/resubmit. It only stores candidate evidence. Verification and
// promotion to authoritative chain state is responsibility.

// --- Quota constants (all fail closed) ---

export const MAX_BODIES_PER_TENANT = 10_000;
export const MAX_BODIES_PER_OPERATION = 100;
export const MAX_BODIES_PER_ROLE = 50;
export const MAX_TOTAL_BYTES_PER_TENANT = 100 * 1024 * 1024; // 100 MiB
export const MAX_PATH_DEPTH = 1000;

// Sighting-ledger caps — bound the dedup / collision / role-conflict observability
// append-ledger so it cannot be driven to unbounded growth (the DoS). BOTH
// bounds are required and complementary:
// - Per-slot (MAX_SIGHTINGS_PER_BODY) closes single-slot spam: a fresh idempotency_key
// with identical or colliding bytes at one occupied (path_proof_id, path_index).
// - Per-tenant (MAX_SIGHTINGS_PER_TENANT) closes the role-conflict path, which records
// a sighting at the INCOMING path_proof_id even when no body row exists there: an
// attacker holding one legitimate different-role sibling can spray fresh path_proof_ids
// — each a brand-new slot the per-slot cap never sees — and grow the ledger without
// consuming the body quota. Counting by submitter tenant caps that vector and contains
// the cross-tenant blast radius on the shared observer store.
// Both fail closed (reject with QUOTA_EXCEEDED; never silently drop). The durable store owns final
// tuning against the durable schema (and likely replaces the append-ledger with a counter).
export const MAX_SIGHTINGS_PER_BODY = 100;
export const MAX_SIGHTINGS_PER_TENANT = 50_000;

// --- Rejection taxonomy ---

export const PERSIST_REJECTION_REASONS = [
  "IDEMPOTENCY_CONFLICT",
  "DIGEST_COLLISION",
  "ROLE_CONFLICT",
  "QUOTA_EXCEEDED",
] as const;

export type PersistRejectionReason = (typeof PERSIST_REJECTION_REASONS)[number];

// --- Row shapes ---

export interface StoredProofBody {
  readonly path_proof_id: string;
  readonly path_index: number;
  readonly source_kind: "PROOF_CHANNEL";
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly wallet_role: ProofBodyWalletRole;
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

export interface ProofBodySighting {
  readonly path_proof_id: string;
  readonly path_index: number;
  readonly raw_bytes_sha256: string;
  readonly idempotency_key: string;
  readonly tenant_id: string;
  readonly seen_at: string;
  readonly is_duplicate: boolean;
  readonly is_conflict: boolean;
}

// --- Repository interface ---

export interface ProofBodyStore {
  findByPathProofAndIndex(pathProofId: string, pathIndex: number): Promise<StoredProofBody | null>;
  /** Ordered exact candidate bytes for verification-material assembly. */
  findByPathProof?(pathProofId: string): Promise<StoredProofBody[]>;
  findByOperationAndPathIndex(operationId: string, pathIndex: number): Promise<StoredProofBody[]>;
  findByBodyDigest(digest: string): Promise<StoredProofBody[]>;
  insert(row: StoredProofBody): Promise<void>;
  insertSighting(sighting: ProofBodySighting): Promise<void>;
  countSightingsBySlot(pathProofId: string, pathIndex: number): Promise<number>;
  countSightingsByTenant(tenantId: string): Promise<number>;
  countByTenant(tenantId: string): Promise<number>;
  countByOperation(operationId: string): Promise<number>;
  countByRole(tenantId: string, role: string): Promise<number>;
  totalBytesByTenant(tenantId: string): Promise<number>;
  findByIdempotencyKey(tenantId: string, operationId: string, key: string): Promise<StoredProofBody | null>;
}

/** Composition-owned transaction boundary. The callback receives a transaction-scoped
 * store with no transaction property, so persistence cannot nest pool transactions. */
export interface TransactionalProofBodyStore extends ProofBodyStore {
  readonly transaction: <T>(body: (store: ProofBodyStore) => Promise<T>) => Promise<T>;
}

// --- Request / Result ---

export interface PersistProofBodyRequest {
  readonly accepted: ProofBodyAccepted;
  readonly identity: AuthenticatedRequestIdentity;
  readonly path_proof_id: string;
  readonly idempotency_key: string;
}

export type PersistProofBodyResult =
  | { readonly persisted: true; readonly sighting_count: number }
  | { readonly persisted: false; readonly reason: PersistRejectionReason; readonly detail: string };

// --- Core persistence function ---

// non-authority: persistProofBody only stores candidate evidence. It never verifies
// signatures, checks chain state, sets a verdict, releases a lease, or promotes a body
// to authoritative. That is job.
export async function persistProofBody(
  store: ProofBodyStore,
  request: PersistProofBodyRequest,
): Promise<PersistProofBodyResult> {
  const transaction = (store as Partial<TransactionalProofBodyStore>).transaction;
  if (transaction !== undefined) {
    return transaction((txStore) => persistProofBodyInTransaction(txStore, request));
  }
  return persistProofBodyInTransaction(store, request);
}

async function persistProofBodyInTransaction(
  store: ProofBodyStore,
  request: PersistProofBodyRequest,
): Promise<PersistProofBodyResult> {
  const { accepted, identity, path_proof_id, idempotency_key } = request;
  const { body, rawSha256 } = accepted;

  // 1. Idempotent retry: same key already seen (scoped to tenant + operation).
  const existingByKey = await store.findByIdempotencyKey(identity.tenant_id, identity.operation_id, idempotency_key);
  if (existingByKey !== null) {
    if (existingByKey.raw_bytes_sha256 === rawSha256) {
      const sightingCount = await store.countSightingsBySlot(path_proof_id, body.path_index);
      return { persisted: true, sighting_count: sightingCount };
    }
    return {
      persisted: false,
      reason: "IDEMPOTENCY_CONFLICT",
      detail: `idempotency_key ${idempotency_key} already used with different content`,
    };
  }

  // 2. Path depth quota (fail closed before any writes).
  if (body.path_index >= MAX_PATH_DEPTH) {
    return {
      persisted: false,
      reason: "QUOTA_EXCEEDED",
      detail: `path_index ${body.path_index} exceeds MAX_PATH_DEPTH ${MAX_PATH_DEPTH}`,
    };
  }

  // 3. Check existing row at (path_proof_id, path_index).
  const existing = await store.findByPathProofAndIndex(path_proof_id, body.path_index);

  if (existing !== null) {
    // Same digest → deduplication: record sighting, never duplicate the row.
    if (existing.raw_bytes_sha256 === rawSha256) {
      const capViolation = await sightingCapViolation(store, path_proof_id, body.path_index, identity.tenant_id);
      if (capViolation !== null) {
        return { persisted: false, reason: "QUOTA_EXCEEDED", detail: capViolation };
      }
      await store.insertSighting({
        path_proof_id,
        path_index: body.path_index,
        raw_bytes_sha256: rawSha256,
        idempotency_key,
        tenant_id: identity.tenant_id,
        seen_at: new Date().toISOString(),
        is_duplicate: true,
        is_conflict: false,
      });
      const sightingCount = await store.countSightingsBySlot(path_proof_id, body.path_index);
      return { persisted: true, sighting_count: sightingCount };
    }

    // Different digest at same slot → collision quarantine.
    const capViolation = await sightingCapViolation(store, path_proof_id, body.path_index, identity.tenant_id);
    if (capViolation !== null) {
      return { persisted: false, reason: "QUOTA_EXCEEDED", detail: capViolation };
    }
    await store.insertSighting({
      path_proof_id,
      path_index: body.path_index,
      raw_bytes_sha256: rawSha256,
      idempotency_key,
      tenant_id: identity.tenant_id,
      seen_at: new Date().toISOString(),
      is_duplicate: false,
      is_conflict: true,
    });
    return {
      persisted: false,
      reason: "DIGEST_COLLISION",
      detail: `different body claims (path_proof_id=${path_proof_id}, path_index=${body.path_index}) already occupied`,
    };
  }

  // 4. Role-mapping conflict: same operation+path_index with a different wallet_role.
  const siblings = await store.findByOperationAndPathIndex(identity.operation_id, body.path_index);
  const roleConflict = siblings.some((s) => s.wallet_role !== identity.wallet_role);
  if (roleConflict) {
    const capViolation = await sightingCapViolation(store, path_proof_id, body.path_index, identity.tenant_id);
    if (capViolation !== null) {
      return { persisted: false, reason: "QUOTA_EXCEEDED", detail: capViolation };
    }
    await store.insertSighting({
      path_proof_id,
      path_index: body.path_index,
      raw_bytes_sha256: rawSha256,
      idempotency_key,
      tenant_id: identity.tenant_id,
      seen_at: new Date().toISOString(),
      is_duplicate: false,
      is_conflict: true,
    });
    return {
      persisted: false,
      reason: "ROLE_CONFLICT",
      detail: `operation ${identity.operation_id} path_index ${body.path_index} already has a body with a different wallet_role`,
    };
  }

  // 5. Quota enforcement (body-count / byte quotas; all fail closed).
  const quotaViolation = await checkQuotas(store, identity, body.completed_transaction_octets);
  if (quotaViolation !== null) {
    return { persisted: false, reason: "QUOTA_EXCEEDED", detail: quotaViolation };
  }

  // 5b. Sighting-cap enforcement BEFORE the row insert — a body row is never written
  // without its first sighting, so the cap and the body write fail closed together.
  const sightingCap = await sightingCapViolation(store, path_proof_id, body.path_index, identity.tenant_id);
  if (sightingCap !== null) {
    return { persisted: false, reason: "QUOTA_EXCEEDED", detail: sightingCap };
  }

  // 6. Insert the new row.
  const row: StoredProofBody = {
    path_proof_id,
    path_index: body.path_index,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: body.completed_transaction_text,
    completed_transaction_sha256: body.completed_transaction_sha256,
    completed_transaction_octets: body.completed_transaction_octets,
    wallet_role: identity.wallet_role,
    s_signature: body.s_signature,
    p_signature: body.p_signature,
    b_amount: body.b_amount,
    inner_preimage_text: body.inner_preimage_text,
    inner_sha256: body.inner_sha256,
    step_1_signature: body.step_1_signature,
    step_2_signature: body.step_2_signature,
    verification_manifest_text: body.verification_manifest_text,
    verification_manifest_sha256: body.verification_manifest_sha256,
    raw_bytes_sha256: rawSha256,
    tenant_id: identity.tenant_id,
    operation_id: identity.operation_id,
    idempotency_key,
    persisted_at: new Date().toISOString(),
  };

  try {
    await store.insert(row);
  } catch (err: unknown) {
    if (isUniqueViolation(err)) {
      return {
        persisted: false,
        reason: "DIGEST_COLLISION",
        detail: "concurrent insert at same slot (race resolved to collision)",
      };
    }
    throw err;
  }
  await store.insertSighting({
    path_proof_id,
    path_index: body.path_index,
    raw_bytes_sha256: rawSha256,
    idempotency_key,
    tenant_id: identity.tenant_id,
    seen_at: row.persisted_at,
    is_duplicate: false,
    is_conflict: false,
  });

  return { persisted: true, sighting_count: 1 };
}

// --- Internal helpers ---

async function checkQuotas(
  store: ProofBodyStore,
  identity: AuthenticatedRequestIdentity,
  incomingOctets: number,
): Promise<string | null> {
  const tenantCount = await store.countByTenant(identity.tenant_id);
  if (tenantCount >= MAX_BODIES_PER_TENANT) {
    return `tenant ${identity.tenant_id} has reached MAX_BODIES_PER_TENANT (${MAX_BODIES_PER_TENANT})`;
  }

  const operationCount = await store.countByOperation(identity.operation_id);
  if (operationCount >= MAX_BODIES_PER_OPERATION) {
    return `operation ${identity.operation_id} has reached MAX_BODIES_PER_OPERATION (${MAX_BODIES_PER_OPERATION})`;
  }

  const roleCount = await store.countByRole(identity.tenant_id, identity.wallet_role);
  if (roleCount >= MAX_BODIES_PER_ROLE) {
    return `tenant ${identity.tenant_id} role ${identity.wallet_role} has reached MAX_BODIES_PER_ROLE (${MAX_BODIES_PER_ROLE})`;
  }

  const totalBytes = await store.totalBytesByTenant(identity.tenant_id);
  if (totalBytes + incomingOctets > MAX_TOTAL_BYTES_PER_TENANT) {
    return `tenant ${identity.tenant_id} would exceed MAX_TOTAL_BYTES_PER_TENANT (${MAX_TOTAL_BYTES_PER_TENANT})`;
  }

  return null;
}

// Bounded sighting ledger: both caps fail closed. Per-slot closes single-slot dedup /
// collision spam; per-tenant closes the fresh-slot role-conflict spray and contains the
// cross-tenant blast radius (see MAX_SIGHTINGS_* above). Called before EVERY sighting
// insert — the three secondary paths and, pre-insert, the happy path.
async function sightingCapViolation(
  store: ProofBodyStore,
  pathProofId: string,
  pathIndex: number,
  tenantId: string,
): Promise<string | null> {
  const slotCount = await store.countSightingsBySlot(pathProofId, pathIndex);
  if (slotCount >= MAX_SIGHTINGS_PER_BODY) {
    return `slot (path_proof_id=${pathProofId}, path_index=${pathIndex}) reached MAX_SIGHTINGS_PER_BODY (${MAX_SIGHTINGS_PER_BODY})`;
  }

  const tenantSightings = await store.countSightingsByTenant(tenantId);
  if (tenantSightings >= MAX_SIGHTINGS_PER_TENANT) {
    return `tenant ${tenantId} reached MAX_SIGHTINGS_PER_TENANT (${MAX_SIGHTINGS_PER_TENANT})`;
  }

  return null;
}

// Narrow unique-constraint detector: SQLSTATE 23505 (Postgres) or an anchored engine
// phrase only. Never a bare "unique" substring — that would misfire on unrelated error
// text (e.g. a body whose transaction contains the token "unique_combinable").
function isUniqueViolation(err: unknown): boolean {
  if (typeof err === "object" && err !== null && "code" in err) {
    if (String((err as { code?: unknown }).code) === "23505") {
      return true;
    }
  }

  const message = err instanceof Error ? err.message : String(err);
  return (
    /duplicate key value violates unique constraint/i.test(message) || // Postgres
    /UNIQUE constraint failed/i.test(message) // SQLite / better-sqlite3
  );
}
