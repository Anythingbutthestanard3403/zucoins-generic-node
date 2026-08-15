// external-send create service.
//
// Governing spec: operation flows steps 1–3; the API contract;
// canonical fields.
//
// SCOPE OF THIS FILE: the service's decision logic, driven through a store double that
// models the two frozen database constraints and NOTHING ELSE — no state is ever hand-seeded
// to make a rejection happen. The one-in-flight-per-wallet case below calls `createExternalSend` twice
// and the second call is rejected because the first one's row exists, not because a test
// helper wrote a flag. That the constraints are real is proven separately, against a real
// PostgreSQL running the real frozen DDL, by send-external-create-pg.test.ts; a passing run
// here with that file absent would prove nothing about persistence.
import { createPrivateKey, createHash, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  buildExternalSendResponse,
  canonicalRequestSha256,
  createExternalSend,
  readExternalSend,
  SEND_CANONICAL_ROUTE,
  SEND_HTTP_METHOD,
  type SendArtifactSigner,
  type SendCreateRequest,
  type SendCreateStore,
  type SendExpectedArtifact,
  type SendInsertOutcome,
  type SendOperation,
  type SendSourceWalletRecord,
  type StoredSendOperation,
} from "../src/send/create.js";
import { STATEMENTS as SEND_SQL_STATEMENTS } from "../src/send/sql-store.js";

/* ─── the A.8 fixture, verbatim from the committed goldens ─────────── */

const GOLDENS = new URL("../../generic-node-contracts/goldens/artifacts/", import.meta.url);
const readGolden = (file: string): string => readFileSync(new URL(file, GOLDENS), "utf8");

const GOLDEN_PREIMAGE = readGolden("zp-send-external-expected-v1.preimage.txt");
const GOLDEN_DIGEST = readGolden("zp-send-external-expected-v1.digest.hex").trim();
const GOLDEN_SIGNATURE = readGolden("zp-send-external-expected-v1.sig.b64").trim();

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const ARTIFACT_ID = "44444444-4444-4444-8444-444444444444";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_ADDRESS = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const OTHER_ADDRESS = `${"A".repeat(43)}=`;
const SIGNING_KEY_ID = "66666666-6666-4666-8666-666666666666";
const IDEMPOTENCY_KEY = "idem-key-send-create-0001";

// A.8's node identity key: the RFC-8032 all-zero seed, whose public key is the goldens'
// verification_pubkey_b64. Real signing here, not a stub — the committed signature is the
// assertion, so a preimage byte out of place cannot pass.
const NODE_IDENTITY_KEY = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0)]),
  format: "der",
  type: "pkcs8",
});

const signer: SendArtifactSigner = {
  signingKeyId: SIGNING_KEY_ID,
  sign: (preimageBytes) => edSign(null, preimageBytes, NODE_IDENTITY_KEY),
};

const AVAILABLE_SOURCE: SendSourceWalletRecord = {
  walletId: SOURCE_WALLET_ID,
  nodeId: NODE_ID,
  publicKey: SOURCE_PUBKEY,
  keyOrigin: "node_generated",
  state: "AVAILABLE",
  allowExternalSend: true,
};

const request = (overrides: Partial<SendCreateRequest> = {}): SendCreateRequest => ({
  implementerId: IMPLEMENTER_ID,
  nodeId: NODE_ID,
  sourceWalletId: SOURCE_WALLET_ID,
  destinationAddress: DESTINATION_ADDRESS,
  amountZkz: "2.25",
  referencesOperationId: null,
  clientReference: null,
  description: null,
  idempotencyKey: IDEMPOTENCY_KEY,
  ...overrides,
});

/* ─── store double: the two frozen constraints, and nothing else ───── */

// the state-event reference terminal set, mirroring the partial unique index predicate in
// send-external-create.sql — which excludes these rather than listing the non-terminal states,
// so an unrecognised status is unsettled and holds the wallet here exactly as it does at rest.
const TERMINAL = new Set(["EXTERNAL_SEND_LANDED", "REJECTED"]);

class ConstraintStore implements SendCreateStore {
  readonly wallets = new Map<string, SendSourceWalletRecord>();
  readonly blessedInternal = new Set<string>();
  readonly operations = new Map<string, StoredSendOperation>();
  readonly artifacts = new Map<string, SendExpectedArtifact>();
  // Set when an inserted row must not be visible to a follower's read, so the rule-3
  // "creator has claimed the key but its row is not readable yet" branch is exercised.
  hideFromIdempotencyRead = false;

  async findSourceWallet(walletId: string): Promise<SendSourceWalletRecord | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async isBlessedInternalAddress(address: string): Promise<boolean> {
    return this.blessedInternal.has(address);
  }

  async insertCreated(
    operation: SendOperation,
    artifact: SendExpectedArtifact,
  ): Promise<SendInsertOutcome> {
    // send_operations_idempotency_scope, absorbed by ON CONFLICT DO NOTHING.
    for (const row of this.operations.values()) {
      if (
        row.implementerId === operation.implementerId &&
        row.httpMethod === operation.httpMethod &&
        row.route === operation.route &&
        row.idempotencyKey === operation.idempotencyKey
      ) {
        return { kind: "IDEMPOTENCY_CONFLICT" };
      }
    }
    // send_operations_one_unsettled_per_source_wallet, whose 23505 propagates.
    for (const row of this.operations.values()) {
      if (row.sourceWalletId === operation.sourceWalletId && !TERMINAL.has(row.status)) {
        return { kind: "WALLET_IN_FLIGHT", walletId: operation.sourceWalletId };
      }
    }
    // send_operation_expected_artifacts.operation_id UNIQUE, and the atomicity of the create
    // DB-TX: the artifact is written by the same statement that wrote the operation.
    if (this.artifacts.has(artifact.operationId)) {
      throw new Error("duplicate artifact for operation");
    }
    this.operations.set(operation.operationId, {
      ...operation,
      status: operation.status,
      rowVersion: operation.rowVersion,
      attentionRequired: operation.attentionRequired,
      formationState: operation.formationState,
      responseStatus: null,
      responseBody: null,
    });
    this.artifacts.set(artifact.operationId, artifact);
    return { kind: "INSERTED" };
  }

  async findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredSendOperation | null> {
    if (this.hideFromIdempotencyRead) return null;
    for (const row of this.operations.values()) {
      if (
        row.implementerId === implementerId &&
        row.httpMethod === httpMethod &&
        row.route === route &&
        row.idempotencyKey === idempotencyKey
      ) {
        return row;
      }
    }
    return null;
  }

  async findByOperationId(
    operationId: string,
  ): Promise<{ operation: StoredSendOperation; artifact: SendExpectedArtifact } | null> {
    const operation = this.operations.get(operationId);
    const artifact = this.artifacts.get(operationId);
    if (operation === undefined || artifact === undefined) return null;
    return { operation, artifact };
  }

  async completeOperation(
    operationId: string,
    responseStatus: number,
    responseBody: string,
  ): Promise<boolean> {
    const row = this.operations.get(operationId);
    if (row === undefined || row.responseBody !== null) return false;
    this.operations.set(operationId, { ...row, responseStatus, responseBody });
    return true;
  }
}

const readyStore = (): ConstraintStore => {
  const store = new ConstraintStore();
  store.wallets.set(SOURCE_WALLET_ID, AVAILABLE_SOURCE);
  return store;
};

// Deterministic id generator: the A.8 operation id first, its artifact id second, then
// fresh unique ids. A test that creates more than once shares ONE generator so the second
// call gets distinct ids, exactly as randomUUID would in production.
const fixtureIds = (): (() => string) => {
  const queue = [OPERATION_ID, ARTIFACT_ID];
  let n = 0;
  return () => queue.shift() ?? `99999999-9999-4999-8999-${String(n++).padStart(12, "0")}`;
};

const create = (
  store: ConstraintStore,
  overrides: Partial<SendCreateRequest> = {},
  generateId: () => string = fixtureIds(),
) =>
  createExternalSend(store, signer, request(overrides), {
    generateId,
    now: () => 1_700_000_000_000,
  });

/* ─── canonical fields golden reproduction, through the whole service ────────── */

describe("the create path reproduces the frozen A.8 send artifact byte-for-byte", () => {
  it("produces the committed preimage, digest, and node signature", async () => {
    const outcome = await create(readyStore());
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;

    expect(outcome.artifact.preimageText).toBe(GOLDEN_PREIMAGE);
    expect(outcome.artifact.preimageSha256).toBe(GOLDEN_DIGEST);
    expect(outcome.artifact.signature).toBe(GOLDEN_SIGNATURE);
    // The digest re-derives from the preimage the service actually emitted, so a golden file
    // and a preimage cannot drift together silently.
    expect(createHash("sha256").update(outcome.artifact.preimageText, "utf8").digest("hex")).toBe(
      GOLDEN_DIGEST,
    );
  });

  it("binds source_pubkey from the RESOLVED wallet record, never from the request", async () => {
    // The request type carries no pubkey field at all; this pins that the signed tuple takes
    // the key from the wallet row, so a caller cannot name a key the node does not control.
    const store = readyStore();
    // A real, canonically-encoded key (the goldens' node identity), not a synthetic filler:
    // parseWalletPublicKey rejects a non-canonical trailing character, so a made-up string
    // would be rejected by the parser and prove nothing about where the key came from.
    const impostor = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
    store.wallets.set(SOURCE_WALLET_ID, { ...AVAILABLE_SOURCE, publicKey: impostor });

    const outcome = await create(store);
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    expect(outcome.artifact.preimageText).toContain(`"source_pubkey":"${impostor}"`);
    expect(outcome.artifact.preimageText).not.toBe(GOLDEN_PREIMAGE);
  });

  it("carries the frozen purpose and canonical version, and exposes key_id only", async () => {
    const outcome = await create(readyStore());
    if (outcome.outcome !== "CREATED") throw new Error("expected CREATED");
    expect(outcome.artifact.purpose).toBe("zp-send-external-expected-v1");
    expect(outcome.artifact.canonicalVersion).toBe(1);
    expect(outcome.artifact.keyId).toBe(SIGNING_KEY_ID);
    const wire = buildExternalSendResponse(outcome.operation, outcome.artifact).expected_artifact;
    expect(Object.keys(wire)).toEqual(["key_id", "preimage_text", "preimage_sha256", "signature"]);
  });
});

/* ─── the one-in-flight-per-wallet rule ────────────────────────────────────────────────── */

describe("the one-in-flight-per-wallet rule — one in-flight transaction per wallet", () => {
  it("rejects a second send for one source wallet with NO pre-seeded store state", async () => {
    const store = readyStore();
    const ids = fixtureIds();

    const first = await create(store, {}, ids);
    expect(first.outcome).toBe("CREATED");

    // Different idempotency key, so the idempotency constraint cannot be what rejects it.
    const second = await create(store, { idempotencyKey: "idem-key-send-create-0002" }, ids);
    expect(second).toMatchObject({
      outcome: "REJECTED",
      code: "wallet_in_flight",
      detail: SOURCE_WALLET_ID,
    });
    expect(store.operations.size).toBe(1);
    expect(store.artifacts.size).toBe(1);
  });

  it("admits a fresh send once the predecessor reaches a terminal state", async () => {
    const store = readyStore();
    const ids = fixtureIds();
    const first = await create(store, {}, ids);
    if (first.outcome !== "CREATED") throw new Error("expected CREATED");

    const settled = store.operations.get(first.operation.operationId) as StoredSendOperation;
    store.operations.set(settled.operationId, { ...settled, status: "EXTERNAL_SEND_LANDED" });

    const second = await create(store, { idempotencyKey: "idem-key-send-create-0003" }, ids);
    expect(second.outcome).toBe("CREATED");
  });

  it("keeps the wallet held while the predecessor is NEEDS_ATTENTION", async () => {
    // the state-event reference: the source lease remains held at NEEDS_ATTENTION, so the
    // wallet is not free and NEEDS_ATTENTION is not one of the index's excluded terminal states.
    const store = readyStore();
    const ids = fixtureIds();
    const first = await create(store, {}, ids);
    if (first.outcome !== "CREATED") throw new Error("expected CREATED");

    const held = store.operations.get(first.operation.operationId) as StoredSendOperation;
    store.operations.set(held.operationId, { ...held, status: "NEEDS_ATTENTION" });

    const second = await create(store, { idempotencyKey: "idem-key-send-create-0004" }, ids);
    expect(second).toMatchObject({ outcome: "REJECTED", code: "wallet_in_flight" });
  });
});

/* ─── idempotency (node-core rules 1–3) ──────────────────────── */

describe("idempotency", () => {
  it("replays the first completed execution's exact status and body", async () => {
    const store = readyStore();
    const ids = fixtureIds();
    const first = await create(store, {}, ids);
    if (first.outcome !== "CREATED") throw new Error("expected CREATED");

    const body = JSON.stringify(buildExternalSendResponse(first.operation, first.artifact));
    expect(await store.completeOperation(first.operation.operationId, 201, body)).toBe(true);

    const replay = await create(store, {}, ids);
    expect(replay.outcome).toBe("IDEMPOTENT_REPLAY");
    if (replay.outcome !== "IDEMPOTENT_REPLAY") return;
    expect(replay.responseStatus).toBe(201);
    expect(replay.responseBody).toBe(body);
    // No second operation and no second artifact were created by the replay.
    expect(store.operations.size).toBe(1);
    expect(store.artifacts.size).toBe(1);
  });

  it("returns idempotency_key_reused for the same key with a different request", async () => {
    const store = readyStore();
    const ids = fixtureIds();
    const first = await create(store, {}, ids);
    if (first.outcome !== "CREATED") throw new Error("expected CREATED");
    const body = JSON.stringify(buildExternalSendResponse(first.operation, first.artifact));
    await store.completeOperation(first.operation.operationId, 201, body);

    const reused = await create(store, { amountZkz: "3.5" }, ids);
    expect(reused).toMatchObject({ outcome: "REJECTED", code: "idempotency_key_reused" });
  });

  it("returns idempotency_in_progress while the creator has stored no result", async () => {
    const store = readyStore();
    const ids = fixtureIds();
    await create(store, {}, ids);
    const follower = await create(store, {}, ids);
    expect(follower).toMatchObject({
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: 1,
    });
  });

  it("never inserts a second operation when the winner's row is not yet visible", async () => {
    const store = readyStore();
    const ids = fixtureIds();
    await create(store, {}, ids);
    store.hideFromIdempotencyRead = true;

    const follower = await create(store, {}, ids);
    expect(follower).toMatchObject({ outcome: "REJECTED", code: "idempotency_in_progress" });
    expect(store.operations.size).toBe(1);
  });

  it("hashes the full canonical request, so any economic field changes the fingerprint", () => {
    const base = canonicalRequestSha256(request());
    for (const overrides of [
      { sourceWalletId: "77777777-7777-4777-8777-777777777777" },
      { destinationAddress: OTHER_ADDRESS },
      { amountZkz: "2.26" },
      { referencesOperationId: "88888888-8888-4888-8888-888888888888" },
    ] as const) {
      expect(canonicalRequestSha256(request(overrides)), JSON.stringify(overrides)).not.toBe(base);
    }
  });

  it("client-visible idempotency overrides keep fingerprint stable when resolved fields differ (ZTR-1271)", () => {
    const clientOmit = request({
      sourceWalletId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      referencesOperationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      idempotencySourceWalletId: null,
      idempotencyReferencesOperationId: null,
    });
    const otherResolved = request({
      sourceWalletId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      referencesOperationId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      idempotencySourceWalletId: null,
      idempotencyReferencesOperationId: null,
    });
    expect(canonicalRequestSha256(clientOmit)).toBe(canonicalRequestSha256(otherResolved));
    // Explicit client source still differs from omit.
    expect(
      canonicalRequestSha256(
        request({
          sourceWalletId: SOURCE_WALLET_ID,
          idempotencySourceWalletId: SOURCE_WALLET_ID,
          idempotencyReferencesOperationId: null,
        }),
      ),
    ).not.toBe(canonicalRequestSha256(clientOmit));
  });

  it("binds expected artifact to the resolved source wallet, not the client fingerprint override", async () => {
    const store = readyStore();
    const outcome = await create(store, {
      sourceWalletId: SOURCE_WALLET_ID,
      idempotencySourceWalletId: null,
      idempotencyReferencesOperationId: null,
    });
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    // Artifact preimage must name the resolved wallet id (suite builder source_selector).
    expect(outcome.artifact.preimageText).toContain(SOURCE_WALLET_ID);
    expect(outcome.operation.sourceWalletId).toBe(SOURCE_WALLET_ID);
    const body = buildExternalSendResponse(outcome.operation, outcome.artifact);
    expect(body.source_wallet_id).toBe(SOURCE_WALLET_ID);
  });
});

/* ─── step 2 gates ────────────────────────────────────────────── */

describe("source and destination gates (operation flows step 2)", () => {
  it("rejects a destination that resolves to the node's blessed internal set", async () => {
    const store = readyStore();
    store.blessedInternal.add(DESTINATION_ADDRESS);

    const outcome = await create(store);
    expect(outcome).toMatchObject({ outcome: "REJECTED", code: "destination_is_internal" });
    // It is rejected, never silently converted into a MOVE_INTERNAL.
    expect(store.operations.size).toBe(0);
    expect(store.artifacts.size).toBe(0);
  });

  it("rejects an unknown source wallet", async () => {
    const outcome = await create(new ConstraintStore());
    expect(outcome).toMatchObject({ outcome: "REJECTED", code: "source_wallet_not_found" });
  });

  it("rejects an imported, non-AVAILABLE, or foreign-node source wallet", async () => {
    const cases: readonly Partial<SendSourceWalletRecord>[] = [
      { keyOrigin: "imported" },
      { state: "PINNED" },
      { state: "QUARANTINED" },
      { state: "RETIRED" },
      { nodeId: "99999999-9999-4999-8999-999999999999" },
    ];
    for (const patch of cases) {
      const store = readyStore();
      store.wallets.set(SOURCE_WALLET_ID, { ...AVAILABLE_SOURCE, ...patch });
      const outcome = await create(store);
      expect(outcome, JSON.stringify(patch)).toMatchObject({
        outcome: "REJECTED",
        code: "source_wallet_not_eligible",
      });
    }
  });

  it("rejects source when allow_external_send is false (ZTR-1268)", async () => {
    const store = readyStore();
    store.wallets.set(SOURCE_WALLET_ID, {
      ...AVAILABLE_SOURCE,
      allowExternalSend: false,
    });
    const outcome = await create(store);
    expect(outcome).toMatchObject({
      outcome: "REJECTED",
      code: "source_wallet_not_eligible",
      detail: "allow_external_send=false",
    });
    expect(store.operations.size).toBe(0);
  });

  it("rejects a wallet whose stored public key cannot be bound into the signed tuple", async () => {
    const store = readyStore();
    store.wallets.set(SOURCE_WALLET_ID, { ...AVAILABLE_SOURCE, publicKey: "not-a-public-key" });
    const outcome = await create(store);
    expect(outcome).toMatchObject({ outcome: "REJECTED", code: "source_wallet_not_eligible" });
    expect(store.operations.size).toBe(0);
  });
});

/* ─── amount bound, at this exact boundary ───────────────────── */

describe("amount_zkz is 0 < amount < 1e8 at the API/artifact boundary", () => {
  const rejected = [
    "0",
    "0.0",
    "0.00",
    `0.${"0".repeat(32)}`,
    "-1",
    "100000000",
    "999999999999",
    "1e3",
    "2.250",
    "",
  ];
  for (const amountZkz of rejected) {
    it(`rejects ${JSON.stringify(amountZkz)}`, async () => {
      const store = readyStore();
      const outcome = await create(store, { amountZkz });
      expect(outcome).toMatchObject({ outcome: "REJECTED", code: "invalid_amount" });
      expect(store.operations.size).toBe(0);
    });
  }

  it("admits the greatest legal value", async () => {
    const store = readyStore();
    const outcome = await create(store, { amountZkz: "99999999.99999999999999999999999999999999" });
    expect(outcome.outcome).toBe("CREATED");
  });
});

/* ─── request validation ───────────────────────────────────────────── */

describe("request validation", () => {
  it("requires an idempotency key of 16–255 visible ASCII characters", async () => {
    for (const idempotencyKey of ["", "short", "a".repeat(256), `ok-key-with-newline\n-pad`]) {
      const outcome = await create(readyStore(), { idempotencyKey });
      expect(outcome, JSON.stringify(idempotencyKey)).toMatchObject({
        outcome: "REJECTED",
        code: "missing_idempotency_key",
      });
    }
  });

  it("rejects malformed scalars before anything is resolved", async () => {
    const cases = [
      [{ sourceWalletId: "not-a-uuid" }, "invalid_source_wallet_id"],
      [{ destinationAddress: "short" }, "invalid_destination_address"],
      [{ referencesOperationId: "nope" }, "invalid_references_operation_id"],
      [{ nodeId: "nope" }, "invalid_tenant_id"],
      [{ implementerId: "nope" }, "invalid_tenant_id"],
    ] as const;
    for (const [overrides, code] of cases) {
      const store = readyStore();
      const outcome = await create(store, overrides);
      expect(outcome, JSON.stringify(overrides)).toMatchObject({ outcome: "REJECTED", code });
      expect(store.operations.size).toBe(0);
    }
  });

  it("pins the canonical route and method the idempotency scope is keyed by", () => {
    expect(SEND_HTTP_METHOD).toBe("POST");
    expect(SEND_CANONICAL_ROUTE).toBe("/v1/external-sends");
  });
});

/* ─── the API contract shapes ─────────────────────────────── */

describe("API response and read shapes", () => {
  it("the 201 body carries the fields, with no transfer code and no expiry", async () => {
    const store = readyStore();
    const outcome = await create(store);
    if (outcome.outcome !== "CREATED") throw new Error("expected CREATED");

    const body = buildExternalSendResponse(outcome.operation, outcome.artifact);
    expect(body.operation).toMatchObject({
      operation_id: OPERATION_ID,
      operation_type: "SEND_EXTERNAL",
      state: "CREATED",
      amount_zkz: "2.25",
      row_version: 1,
      attention_required: false,
      attention_reason: null,
      terminal_at: null,
      verification_material_available_until: null,
    });
    expect(body.source_wallet_id).toBe(SOURCE_WALLET_ID);
    expect(body.destination_address).toBe(DESTINATION_ADDRESS);
    expect(body.references_operation_id).toBeNull();
    expect(body.approval_status).toBe("PENDING");
    // No source lease and no SplitChain preimage exists in this slice, so there is nothing
    // for these three to be served from (the send expiry is materialized only at
    // sign-intent formation).
    expect(body.transfer_code).toBeNull();
    expect(body.transfer_code_sha256).toBeNull();
    expect(body.available_until).toBeNull();
    expect(body.expected_artifact.signature).toBe(GOLDEN_SIGNATURE);
  });

  it("the read returns the identical create-time artifact with transfer_code null", async () => {
    const store = readyStore();
    const created = await create(store);
    if (created.outcome !== "CREATED") throw new Error("expected CREATED");

    const read = await readExternalSend(store, created.operation.operationId);
    expect(read.outcome).toBe("FOUND");
    if (read.outcome !== "FOUND") return;
    expect(read.response.transfer_code).toBeNull();
    expect(read.response.available_until).toBeNull();
    expect(read.response.expected_artifact.preimage_text).toBe(created.artifact.preimageText);
    expect(read.response.expected_artifact.signature).toBe(created.artifact.signature);
  });

  it("reports NOT_FOUND; APPROVED+ is readable without inventing a transfer_code", async () => {
    const store = readyStore();
    expect(await readExternalSend(store, OPERATION_ID)).toEqual({ outcome: "NOT_FOUND" });

    const created = await create(store);
    if (created.outcome !== "CREATED") throw new Error("expected CREATED");
    const row = store.operations.get(created.operation.operationId) as StoredSendOperation;
    store.operations.set(row.operationId, { ...row, status: "APPROVED" });

    // APPROVED is on the read ladder (awaiting formation); codes stay null until partial.
    const approved = await readExternalSend(store, row.operationId);
    expect(approved.outcome).toBe("FOUND");
    if (approved.outcome !== "FOUND") return;
    expect(approved.response.operation.state).toBe("APPROVED");
    expect(approved.response.transfer_code).toBeNull();
    expect(approved.response.transfer_code_sha256).toBeNull();
    expect(approved.response.approval_status).toBe("APPROVED");
  });

  it("maps a readable REJECTED row to approval_status REJECTED, not CONSUMED", async () => {
    const store = readyStore();
    const created = await create(store);
    if (created.outcome !== "CREATED") throw new Error("expected CREATED");
    const row = store.operations.get(created.operation.operationId) as StoredSendOperation;
    store.operations.set(row.operationId, { ...row, status: "REJECTED" });

    const rejected = await readExternalSend(store, row.operationId);
    expect(rejected.outcome).toBe("FOUND");
    if (rejected.outcome !== "FOUND") return;
    expect(rejected.response.operation.state).toBe("REJECTED");
    expect(rejected.response.approval_status).toBe("REJECTED");
    expect(rejected.response.approval_status).not.toBe("CONSUMED");
  });

  it("keeps terminal-consumed approval rows as CONSUMED", async () => {
    const store = readyStore();
    const created = await create(store);
    if (created.outcome !== "CREATED") throw new Error("expected CREATED");
    const row = store.operations.get(created.operation.operationId) as StoredSendOperation;

    for (const status of ["AWAITING_REDEMPTION", "NEEDS_ATTENTION", "EXTERNAL_SEND_LANDED"] as const) {
      store.operations.set(row.operationId, { ...row, status });
      const read = await readExternalSend(store, row.operationId);
      expect(read.outcome).toBe("FOUND");
      if (read.outcome !== "FOUND") return;
      expect(read.response.operation.state).toBe(status);
      expect(read.response.approval_status).toBe("CONSUMED");
    }
  });
});

/* ─── money-path statement spelling ──────────
 * Unit tests mock the store and never execute SELECT_BLESSED_INTERNAL. The
 * production join must track wallets(id); a w.wallet_id reference fails on a
 * schema. Pin the statement text so a rename regression is caught here. */
describe("send sql-store wallets(id) joins", () => {
  it("SELECT_BLESSED_INTERNAL joins destinations to wallets.id (not wallets.wallet_id)", () => {
    expect(SEND_SQL_STATEMENTS.SELECT_BLESSED_INTERNAL).toContain("JOIN wallets w ON w.id = d.wallet_id");
    expect(SEND_SQL_STATEMENTS.SELECT_BLESSED_INTERNAL).not.toMatch(/\bw\.wallet_id\b/);
  });

  it("SELECT_SOURCE_WALLET reads wallets by id", () => {
    expect(SEND_SQL_STATEMENTS.SELECT_SOURCE_WALLET).toMatch(/WHERE id = \$1\s*$/);
    expect(SEND_SQL_STATEMENTS.SELECT_SOURCE_WALLET).toContain("id AS wallet_id");
  });
});
