import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  intakeProofBody,
  persistProofBody,
  PROOF_BODY_FIELDS,
  type AuthenticatedRequestIdentity,
  type ExpectedIdentityBinding,
  type PersistProofBodyRequest,
  type ProofBodyAccepted,
  type ProofBodyIntakeRequest,
  type ProofBodyTransportMetadata,
  type StoredProofBody,
  type ValidatedProofBody,
} from "../src/proof-body/index.js";
import {
  CANDIDATE_COLUMNS,
  SqlProofBodyStore,
  STATEMENTS,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/proof-body/sql-store.js";
import {
  A8_INNER_PREIMAGE_SHA256,
  A8_INNER_PREIMAGE_TEXT,
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
} from "./fixtures/splitchain-v2-byte-evidence.js";

// The byte-exact signing rule — byte-exact JSON.stringify signing, never reformat. This suite proves the
// persistence path honours that rule end to end: a body captured by intakeProofBody, stored
// through the durable SqlProofBodyStore, and read back is returned as the EXACT bytes that
// were captured — no reformatting, reordering, or prettifying — and the stored body hash
// equals the SHA-256 of those exact bytes (the signature preimage hash).
//
// Verification posture (node-core convention): node-core is network-contained and
// depends on no database driver, so the store is exercised through a faithful in-process
// SqlExecutor that models the candidate table's PK / UNIQUE constraints and stores every
// column verbatim as text (mirroring node-postgres text returns). This drives the store's
// REAL parameterized SQL (STATEMENTS) and REAL row mapping; what it does NOT prove — that a
// live Postgres preserves TEXT byte-for-byte — is a separate live-database obligation of
// src/schema/proof-body-store.contract.ts, not this suite.

const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const PATH_PROOF_ID = "44444444-4444-4444-8444-444444444444";

// 64-byte Ed25519 signature shape: 86 base64url chars + "==" (the data model
// padded_base64url_signature). Deterministic, schema-valid; this suite never signs.
const SIG_S = "A".repeat(86) + "==";
const SIG_STEP_1 = "B".repeat(86) + "==";
const SIG_STEP_2 = "C".repeat(86) + "==";

const encoder = new TextEncoder();

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function byteLength(text: string): number {
  return encoder.encode(text).byteLength;
}

// A schema-valid body whose three signed text columns carry arbitrary caller payloads. The
// object literal is built in the frozen PROOF_BODY_FIELDS sequence so JSON.stringify(body) is
// the canonical wire form — the byte-identity assertions below are meaningful only because
// the field order is fixed.
function makeBody(payloads: {
  completed: string;
  inner: string;
  manifest: string;
  amount?: string;
}): ValidatedProofBody {
  return {
    path_index: 0,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: payloads.completed,
    completed_transaction_sha256: sha256Hex(payloads.completed),
    completed_transaction_octets: byteLength(payloads.completed),
    wallet_role: "sender",
    s_signature: SIG_S,
    p_signature: "",
    b_amount: payloads.amount ?? "7.75",
    inner_preimage_text: payloads.inner,
    inner_sha256: sha256Hex(payloads.inner),
    step_1_signature: SIG_STEP_1,
    step_2_signature: SIG_STEP_2,
    verification_manifest_text: payloads.manifest,
    verification_manifest_sha256: sha256Hex(payloads.manifest),
  };
}

function makeIdentity(): AuthenticatedRequestIdentity {
  return { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "sender" };
}

function makeTransport(rawBytes: Uint8Array): ProofBodyTransportMetadata {
  return {
    claimed_signature: SIG_S,
    content_length: rawBytes.byteLength,
    media_type: "application/json",
    request_id: "99999999-9999-4999-8999-999999999999",
    provenance: "PROOF_CHANNEL",
  };
}

// Capture the exact bytes of a body the way a wire submission arrives: JSON.stringify in the
// frozen field order, UTF-8 encoded. Returns the accepted intake result plus those bytes.
function intake(body: ValidatedProofBody): { accepted: ProofBodyAccepted; rawBytes: Uint8Array } {
  const rawBytes = encoder.encode(JSON.stringify(body));
  const expected: ExpectedIdentityBinding = makeIdentity();
  const request: ProofBodyIntakeRequest = {
    authenticated: makeIdentity(),
    expected,
    transport: makeTransport(rawBytes),
    rawBytes,
  };
  const result = intakeProofBody(request);
  if (!result.accepted) {
    throw new Error(`intake rejected a fixture body: ${result.code} — ${result.detail}`);
  }
  return { accepted: result, rawBytes };
}

// Re-serialize the frozen body columns of a stored row in PROOF_BODY_FIELDS order — the
// canonical re-encoding a verifier would reconstruct from the persisted projection.
function reencodeBodyFields(row: StoredProofBody): string {
  const projection: Record<string, unknown> = {
    path_index: row.path_index,
    source_kind: row.source_kind,
    completed_transaction_text: row.completed_transaction_text,
    completed_transaction_sha256: row.completed_transaction_sha256,
    completed_transaction_octets: row.completed_transaction_octets,
    wallet_role: row.wallet_role,
    s_signature: row.s_signature,
    p_signature: row.p_signature,
    b_amount: row.b_amount,
    inner_preimage_text: row.inner_preimage_text,
    inner_sha256: row.inner_sha256,
    step_1_signature: row.step_1_signature,
    step_2_signature: row.step_2_signature,
    verification_manifest_text: row.verification_manifest_text,
    verification_manifest_sha256: row.verification_manifest_sha256,
  };
  const ordered: Record<string, unknown> = {};
  for (const field of PROOF_BODY_FIELDS) ordered[field] = projection[field];
  return JSON.stringify(ordered);
}

// --- Faithful in-process SqlExecutor over the candidate table (verbatim text columns) ---

function uniqueViolation(constraint: string): Error {
  return Object.assign(
    new Error(`duplicate key value violates unique constraint "${constraint}"`),
    { code: "23505", constraint },
  );
}

const slotKey = (pathProofId: unknown, pathIndex: unknown): string =>
  `${String(pathProofId)} ${String(pathIndex)}`;

class InProcessSqlExecutor implements SqlExecutor {
  private readonly bodies = new Map<string, Record<string, string>>();
  private readonly slotCounters = new Map<string, number>();
  private readonly tenantCounters = new Map<string, number>();

  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    return { rows: this.run(text, params) as R[] };
  }

  private run(text: string, params: readonly unknown[]): unknown[] {
    switch (text) {
      case STATEMENTS.ADVISORY_LOCK_PATH_PROOF:
        return [];
      case STATEMENTS.INSERT_CANDIDATE: {
        const record: Record<string, string> = {};
        CANDIDATE_COLUMNS.forEach((col, i) => {
          record[col] = String(params[i]);
        });
        const pk = slotKey(record.path_proof_id, record.path_index);
        if (this.bodies.has(pk)) throw uniqueViolation("proof_channel_candidate_bodies_pkey");
        for (const existing of this.bodies.values()) {
          if (
            existing.tenant_id === record.tenant_id &&
            existing.operation_id === record.operation_id &&
            existing.idempotency_key === record.idempotency_key
          ) {
            throw uniqueViolation("proof_channel_candidate_bodies_tenant_op_idem_key");
          }
        }
        this.bodies.set(pk, record);
        return [];
      }
      case STATEMENTS.SELECT_BY_SLOT: {
        const record = this.bodies.get(slotKey(params[0], params[1]));
        return record ? [record] : [];
      }
      case STATEMENTS.SELECT_BY_OPERATION_PATH: {
        const pathIndex = String(params[1]);
        return [...this.bodies.values()].filter(
          (r) => r.operation_id === params[0] && r.path_index === pathIndex,
        );
      }
      case STATEMENTS.SELECT_BY_DIGEST:
        return [...this.bodies.values()].filter((r) => r.raw_bytes_sha256 === params[0]);
      case STATEMENTS.SELECT_BY_IDEMPOTENCY: {
        const found = [...this.bodies.values()].find(
          (r) =>
            r.tenant_id === params[0] &&
            r.operation_id === params[1] &&
            r.idempotency_key === params[2],
        );
        return found ? [found] : [];
      }
      case STATEMENTS.COUNT_BY_TENANT:
        return [{ n: String([...this.bodies.values()].filter((r) => r.tenant_id === params[0]).length) }];
      case STATEMENTS.COUNT_BY_OPERATION:
        return [{ n: String([...this.bodies.values()].filter((r) => r.operation_id === params[0]).length) }];
      case STATEMENTS.COUNT_BY_ROLE:
        return [
          {
            n: String(
              [...this.bodies.values()].filter(
                (r) => r.tenant_id === params[0] && r.wallet_role === params[1],
              ).length,
            ),
          },
        ];
      case STATEMENTS.SUM_BYTES_BY_TENANT: {
        const sum = [...this.bodies.values()]
          .filter((r) => r.tenant_id === params[0])
          .reduce((acc, r) => acc + Number(r.completed_transaction_octets), 0);
        return [{ n: String(sum) }];
      }
      case STATEMENTS.UPSERT_SLOT_COUNTER: {
        const key = slotKey(params[0], params[1]);
        this.slotCounters.set(key, (this.slotCounters.get(key) ?? 0) + 1);
        return [];
      }
      case STATEMENTS.UPSERT_TENANT_COUNTER: {
        const key = String(params[0]);
        this.tenantCounters.set(key, (this.tenantCounters.get(key) ?? 0) + 1);
        return [];
      }
      case STATEMENTS.SELECT_SLOT_COUNTER: {
        const n = this.slotCounters.get(slotKey(params[0], params[1]));
        return n === undefined ? [] : [{ sighting_count: String(n) }];
      }
      case STATEMENTS.SELECT_TENANT_COUNTER: {
        const n = this.tenantCounters.get(String(params[0]));
        return n === undefined ? [] : [{ sighting_count: String(n) }];
      }
      default:
        throw new Error(`InProcessSqlExecutor: unmodelled statement:\n${text}`);
    }
  }
}

function newStore(): SqlProofBodyStore {
  return new SqlProofBodyStore(new InProcessSqlExecutor());
}

// Persist an accepted body under a fresh idempotency key and return the stored row.
async function persistAndRetrieve(
  store: SqlProofBodyStore,
  accepted: ProofBodyAccepted,
  idempotencyKey: string,
): Promise<StoredProofBody> {
  const request: PersistProofBodyRequest = {
    accepted,
    identity: makeIdentity(),
    path_proof_id: PATH_PROOF_ID,
    idempotency_key: idempotencyKey,
  };
  const result = await persistProofBody(store, request);
  expect(result.persisted).toBe(true);
  const row = await store.findByPathProofAndIndex(PATH_PROOF_ID, accepted.body.path_index);
  expect(row).not.toBeNull();
  return row as StoredProofBody;
}

// The four exactness assertions shared by every payload shape.
function expectByteExactRoundTrip(row: StoredProofBody, accepted: ProofBodyAccepted, rawBytes: Uint8Array): void {
  // 1. Stored body hash == SHA-256 of the exact captured bytes (the signature preimage hash).
  expect(row.raw_bytes_sha256).toBe(accepted.rawSha256);
  expect(row.raw_bytes_sha256).toBe(sha256Hex(new TextDecoder("utf-8").decode(rawBytes)));

  // 2. Retrieval returns the exact bytes: re-encoding the persisted frozen fields reproduces
  //    the captured bytes byte-for-byte (no reformat / reorder / prettify survived the store).
  expect(encoder.encode(reencodeBodyFields(row))).toEqual(rawBytes);

  // 3. Each signed text column round-trips byte-exact, and its persisted digest equals the
  //    SHA-256 of the retrieved text — the preimage hash matches the retrieved preimage.
  expect(row.completed_transaction_text).toBe(accepted.body.completed_transaction_text);
  expect(row.completed_transaction_sha256).toBe(sha256Hex(row.completed_transaction_text));
  expect(row.inner_preimage_text).toBe(accepted.body.inner_preimage_text);
  expect(row.inner_sha256).toBe(sha256Hex(row.inner_preimage_text));
  expect(row.verification_manifest_text).toBe(accepted.body.verification_manifest_text);
  expect(row.verification_manifest_sha256).toBe(sha256Hex(row.verification_manifest_text));

  // 4. The octet count is the exact UTF-8 byte length of the retrieved text.
  expect(row.completed_transaction_octets).toBe(byteLength(row.completed_transaction_text));
}

describe("exact-body persistence (the byte-exact signing rule: byte-exact, never reformat)", () => {
  it("nested-object payload round-trips byte-exact through intake → store → retrieval", async () => {
    const body = makeBody({
      completed:
        '{"inner":{"type":"unique_combinable","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25","nested":{"depth":3}}},"step_1_signature":"sig"}',
      inner: '{"type":"unique_combinable","state":{"amount":"7.75","meta":{"flags":{"a":true}}}}',
      manifest: '{"verifier":"fixture","checks":{"digest":true,"order":true}}',
    });
    const { accepted, rawBytes } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-nested");
    expectByteExactRoundTrip(row, accepted, rawBytes);
  });

  it("array payload round-trips byte-exact (arrays are never reordered or re-spaced)", async () => {
    const body = makeBody({
      completed: '{"outputs":[{"amount":"1.50","to":"a"},{"amount":"2.25","to":"b"}],"order":[3,1,2]}',
      inner: '{"signers":["sender","receiver"],"states":[{"amount":"7.75"},{"amount":"2.25"}]}',
      manifest: '{"verifier":"fixture","path":[0,1,2,3]}',
    });
    const { accepted, rawBytes } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-arrays");
    expectByteExactRoundTrip(row, accepted, rawBytes);
  });

  it("unicode / multi-byte payload round-trips byte-exact (no escaping or normalization added)", async () => {
    const body = makeBody({
      completed: '{"message":"Payment for services — ¥5000 💰","to":"zp1:café"}',
      inner: '{"message":"naïve résumé 中文 🚀","amount":"7.75"}',
      manifest: '{"verifier":"fixture","note":"emoji 🎯 + CJK 漢字"}',
    });
    const { accepted, rawBytes } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-unicode");
    expectByteExactRoundTrip(row, accepted, rawBytes);
    // The multi-byte text is stored as raw UTF-8 characters, not \uXXXX-escaped.
    expect(row.inner_preimage_text).toContain("中文 🚀");
  });

  it("escape-heavy payload round-trips byte-exact (quotes, backslashes, control chars preserved)", async () => {
    const body = makeBody({
      completed: '{"note":"line1\\nline2\\ttab \\"quoted\\" back\\\\slash","path":"C:\\\\dir"}',
      inner: '{"regex":"^a\\\\.b$","quote":"she said \\"hi\\""}',
      manifest: '{"verifier":"fixture","sep":"a\\\\/b"}',
    });
    const { accepted, rawBytes } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-escapes");
    expectByteExactRoundTrip(row, accepted, rawBytes);
  });

  it("real wallet v2 signed-transaction evidence round-trips byte-exact", async () => {
    const body = makeBody({
      completed: WALLET_SETTLED_TRANSACTION_TEXT,
      inner: WALLET_INNER_PREIMAGE_TEXT,
      manifest: '{"verifier":"fixture","fixture":"splitchain-v2-byte-evidence"}',
      amount: "7.5",
    });
    // The fixture's published digests are the authoritative preimage hashes of the exact
    // signed bytes; the body's digests must match them before persistence is even attempted.
    expect(body.completed_transaction_sha256).toBe(WALLET_SETTLED_TRANSACTION_SHA256);
    expect(body.inner_sha256).toBe(WALLET_INNER_PREIMAGE_SHA256);

    const { accepted, rawBytes } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-wallet-v2");
    expectByteExactRoundTrip(row, accepted, rawBytes);
    // The persisted inner preimage still hashes to the wallet's signed inner digest.
    expect(row.inner_sha256).toBe(WALLET_INNER_PREIMAGE_SHA256);
    expect(row.completed_transaction_sha256).toBe(WALLET_SETTLED_TRANSACTION_SHA256);
  });

  it("appendix A.8.1 inner preimage persists with its exact published digest", async () => {
    const body = makeBody({
      completed: WALLET_SETTLED_TRANSACTION_TEXT,
      inner: A8_INNER_PREIMAGE_TEXT,
      manifest: '{"verifier":"fixture","fixture":"appendix-A8"}',
    });
    expect(body.inner_sha256).toBe(A8_INNER_PREIMAGE_SHA256);
    const { accepted } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-appendix-a8");
    expect(row.inner_preimage_text).toBe(A8_INNER_PREIMAGE_TEXT);
    expect(row.inner_sha256).toBe(A8_INNER_PREIMAGE_SHA256);
    expect(sha256Hex(row.inner_preimage_text)).toBe(A8_INNER_PREIMAGE_SHA256);
  });

  it("retrieval by body digest returns the same byte-exact row as retrieval by slot", async () => {
    const body = makeBody({
      completed: '{"inner":{"type":"unique_combinable"},"step_1_signature":"s"}',
      inner: '{"type":"unique_combinable","amount":"7.75"}',
      manifest: '{"verifier":"fixture"}',
    });
    const { accepted, rawBytes } = intake(body);
    const store = newStore();
    const bySlot = await persistAndRetrieve(store, accepted, "idem-by-digest");

    const byDigest = await store.findByBodyDigest(accepted.rawSha256);
    expect(byDigest).toHaveLength(1);
    expect(byDigest[0]).toEqual(bySlot);
    expect(encoder.encode(reencodeBodyFields(byDigest[0] as StoredProofBody))).toEqual(rawBytes);
  });

  it("the stored hash is over the EXACT bytes: a prettified re-encoding of the same body has a different hash", async () => {
    const body = makeBody({
      completed: '{"inner":{"type":"unique_combinable"},"step_1_signature":"s"}',
      inner: '{"type":"unique_combinable","amount":"7.75"}',
      manifest: '{"verifier":"fixture"}',
    });
    const canonical = JSON.stringify(body);
    const pretty = JSON.stringify(body, null, 2);
    // Same semantic content, different bytes → different digest. This is exactly the
    // reformatting the byte-exact signing rule forbids; the persisted hash must be the canonical one.
    expect(sha256Hex(pretty)).not.toBe(sha256Hex(canonical));

    const { accepted } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-pretty");
    expect(row.raw_bytes_sha256).toBe(sha256Hex(canonical));
    expect(row.raw_bytes_sha256).not.toBe(sha256Hex(pretty));
  });

  it("the stored hash is over the EXACT field order: a resequenced encoding of the same body has a different hash", async () => {
    const body = makeBody({
      completed: '{"inner":{"type":"unique_combinable"},"step_1_signature":"s"}',
      inner: '{"type":"unique_combinable","amount":"7.75"}',
      manifest: '{"verifier":"fixture"}',
    });
    const canonical = JSON.stringify(body);
    // Reverse the frozen field sequence — same keys and values, different order.
    const reordered: Record<string, unknown> = {};
    for (const field of [...PROOF_BODY_FIELDS].reverse()) {
      reordered[field] = (body as unknown as Record<string, unknown>)[field];
    }
    const resequenced = JSON.stringify(reordered);
    expect(sha256Hex(resequenced)).not.toBe(sha256Hex(canonical));

    const { accepted } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-reorder");
    // The persisted projection re-encodes in the frozen order, matching the canonical bytes.
    expect(row.raw_bytes_sha256).toBe(sha256Hex(canonical));
    expect(reencodeBodyFields(row)).toBe(canonical);
    expect(reencodeBodyFields(row)).not.toBe(resequenced);
  });

  it("a single-byte mutation of a signed text column changes its preimage hash (digest is byte-sensitive)", async () => {
    const inner = '{"type":"unique_combinable","amount":"7.75"}';
    const body = makeBody({
      completed: '{"inner":{"type":"unique_combinable"},"step_1_signature":"s"}',
      inner,
      manifest: '{"verifier":"fixture"}',
    });
    const { accepted } = intake(body);
    const row = await persistAndRetrieve(newStore(), accepted, "idem-mutation");

    const mutated = inner.replace("7.75", "7.76");
    expect(sha256Hex(mutated)).not.toBe(row.inner_sha256);
    // The stored digest pins the exact retrieved text — any tamper is detectable.
    expect(sha256Hex(row.inner_preimage_text)).toBe(row.inner_sha256);
  });
});
