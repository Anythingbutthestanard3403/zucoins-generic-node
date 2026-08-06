// External-send create — validate a SEND_EXTERNAL request, resolve idempotency, gate the
// source and destination, build and sign the one exact expected artifact, and create the
// operation in CREATED state.
//
// Layer 1 (node-core) only: no lease is acquired, no SplitChain preimage is formed, and no
// gateway call is made, so an idempotent replay can never repeat a protocol action.
//
// The invariants this module exists to guarantee are enforced by the DATABASE, not by
// application reads. `insertCreated` is the sole arbiter:
// * idempotency — the UNIQUE (implementer_id, http_method, route, idempotency_key)
// constraint on send_operations decides which of N concurrent first uses wins;
// * the one-in-flight-per-wallet rule — the partial unique index over an unsettled send's source wallet
// decides whether a second in-flight send for one wallet exists at all.
// There is deliberately no `hasInFlight`-style read: a check separated from its insert is a
// TOCTOU gap, and against a real store a flag nothing writes is permanently false. The
// frozen DDL and its structural inventory are src/schema/send-external-create.sql and
// send-external-create.contract.ts; the real-PostgreSQL drills are
// test/send-external-create-pg.test.ts.
//
// The byte-exact signing rule: the signed preimage is built by the frozen suite builder
// (`buildSendExternalExpectedArtifact`), never by a serializer in this file. The only
// `JSON.stringify` calls below produce the idempotency request fingerprint and the stored
// response body — neither is a signed surface.

import { createHash, randomUUID } from "node:crypto";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";
import { buildSendExternalExpectedArtifact } from "../protocol/suite/builders.js";

// The idempotency scope includes the HTTP method and the canonical
// route, never the key alone. This slice serves exactly one route.
export const SEND_HTTP_METHOD = "POST" as const;
export const SEND_CANONICAL_ROUTE = "/v1/external-sends" as const;

// A-canonical-fields: the frozen purpose for this operation's one artifact.
export const SEND_EXPECTED_ARTIFACT_PURPOSE = "zp-send-external-expected-v1" as const;

// Rule 3: followers of a concurrent first use wait briefly for the
// creator's stored result, then get 409 idempotency_in_progress with Retry-After.
export const IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS = 1;

export type SendWalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";

export interface SendSourceWalletRecord {
  readonly walletId: string;
  readonly nodeId: string;
  readonly publicKey: string;
  readonly keyOrigin: "node_generated" | "imported";
  readonly state: SendWalletState;
}

export interface SendCreateRequest {
  readonly implementerId: string;
  readonly nodeId: string;
  readonly sourceWalletId: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
  readonly clientReference: string | null;
  readonly description: string | null;
  readonly idempotencyKey: string;
}

export interface SendOperation {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly kind: "SEND_EXTERNAL";
  readonly status: "CREATED";
  readonly rowVersion: 1;
  readonly attentionRequired: false;
  readonly formationState: "APPROVAL_PENDING";
  readonly httpMethod: typeof SEND_HTTP_METHOD;
  readonly route: typeof SEND_CANONICAL_ROUTE;
  readonly sourceWalletId: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
  readonly clientReference: string | null;
  readonly description: string | null;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly createdAt: number;
}

// A-canonical-fields: the exact artifact envelope. `keyId` is the wire name of the
// storage column `signing_key_id`; no second aliased field is ever exposed.
export interface SendExpectedArtifact {
  readonly artifactId: string;
  readonly operationId: string;
  readonly purpose: typeof SEND_EXPECTED_ARTIFACT_PURPOSE;
  readonly canonicalVersion: 1;
  readonly keyId: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signature: string;
}

// A row as the store returns it. `responseBody === null` is the in-progress marker: the
// creator has claimed the key but has not yet stored its first completed execution. `status`
// widens to the full frozen vocabulary because a stored row may have advanced past CREATED.
export interface StoredSendOperation extends Omit<SendOperation, "status" | "rowVersion" | "attentionRequired" | "formationState"> {
  readonly status: string;
  readonly rowVersion: number;
  readonly attentionRequired: boolean;
  readonly formationState: string;
  readonly responseStatus: number | null;
  readonly responseBody: string | null;
}

export type SendRejectionCode =
  | "missing_idempotency_key"
  | "invalid_tenant_id"
  | "invalid_source_wallet_id"
  | "invalid_destination_address"
  | "invalid_amount"
  | "invalid_references_operation_id"
  | "source_wallet_not_found"
  | "source_wallet_not_eligible"
  | "destination_is_internal"
  | "signing_key_unavailable"
  | "wallet_in_flight"
  | "idempotency_key_reused"
  | "idempotency_in_progress";

export type SendCreateOutcome =
  | {
      readonly outcome: "CREATED";
      readonly operation: SendOperation;
      readonly artifact: SendExpectedArtifact;
    }
  | {
      readonly outcome: "IDEMPOTENT_REPLAY";
      readonly operation: StoredSendOperation;
      readonly responseStatus: number;
      readonly responseBody: string;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: SendRejectionCode;
      readonly detail?: string;
      readonly retryAfterSeconds?: number;
    };

// Outcome of the arbiter insert. Every branch is decided by the database, not by a prior
// read: INSERTED means this caller won the idempotency constraint, and WALLET_IN_FLIGHT
// means the one-in-flight-per-wallet partial unique index rejected the row.
export type SendInsertOutcome =
  | { readonly kind: "INSERTED" }
  | { readonly kind: "IDEMPOTENCY_CONFLICT" }
  | { readonly kind: "WALLET_IN_FLIGHT"; readonly walletId: string };

export interface SendCreateStore {
  findSourceWallet(walletId: string): Promise<SendSourceWalletRecord | null>;
  // Step 2: does this address resolve to the node's CURRENT blessed
  // internal set? A destination that does is a MOVE_INTERNAL, never a SEND_EXTERNAL.
  isBlessedInternalAddress(address: string): Promise<boolean>;
  // The create DB-TX: inserts the operation row AND its one expected-artifact row, or
  // neither. MUST NOT pre-read to decide the outcome — the constraints decide.
  insertCreated(operation: SendOperation, artifact: SendExpectedArtifact): Promise<SendInsertOutcome>;
  findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredSendOperation | null>;
  findByOperationId(
    operationId: string,
  ): Promise<{ operation: StoredSendOperation; artifact: SendExpectedArtifact } | null>;
  // Stores the first completed execution's status and exact response body, closing the
  // in-progress marker. Returns false if the row was already completed.
  completeOperation(operationId: string, responseStatus: number, responseBody: string): Promise<boolean>;
}

// The key-custody rule: node-core never holds key material. The vault implements this port; all
// this module receives is an opaque id and the ability to sign exact bytes.
export interface SendArtifactSigner {
  readonly signingKeyId: string;
  sign(preimageBytes: Uint8Array): Uint8Array;
}

// Frozen API grammar (api/scalars.ts): idempotency key 16–255 visible ASCII.
const IDEMPOTENCY_KEY_RE = /^[\x20-\x7E]{16,255}$/;

// origin conjunct: an imported-origin wallet never sources a node operation.
// Step 2 requires node-generated AND controlled by this node; a
// non-AVAILABLE wallet is already committed elsewhere.
export function isSendSourceEligible(wallet: SendSourceWalletRecord, nodeId: string): boolean {
  return (
    wallet.keyOrigin === "node_generated" && wallet.state === "AVAILABLE" && wallet.nodeId === nodeId
  );
}

export function validateSendCreateRequest(
  request: SendCreateRequest,
): { ok: true } | { ok: false; code: SendRejectionCode; detail?: string } {
  if (!IDEMPOTENCY_KEY_RE.test(request.idempotencyKey)) {
    return { ok: false, code: "missing_idempotency_key" };
  }
  // node_id and implementer_id are signed into the artifact tuple, so a malformed
  // one must be a rejection here rather than a throw out of the frozen builder later.
  try {
    parseUuid(request.nodeId);
    parseUuid(request.implementerId);
  } catch {
    return { ok: false, code: "invalid_tenant_id" };
  }
  try {
    parseUuid(request.sourceWalletId);
  } catch {
    return { ok: false, code: "invalid_source_wallet_id" };
  }
  try {
    parseWalletPublicKey(request.destinationAddress);
  } catch {
    return { ok: false, code: "invalid_destination_address" };
  }
  // canonical ZKZ amount contract, at the exact API/artifact boundary: strictly positive and strictly below 1e8.
  // The frozen parser owns both ends of the bound; nothing here re-implements it.
  try {
    parsePositiveZkzAmount(request.amountZkz);
  } catch {
    return {
      ok: false,
      code: "invalid_amount",
      detail: "amount_zkz must be a positive canonical decimal, strictly < 100000000",
    };
  }
  if (request.referencesOperationId !== null) {
    try {
      parseUuid(request.referencesOperationId);
    } catch {
      return { ok: false, code: "invalid_references_operation_id" };
    }
  }
  return { ok: true };
}

// A SHA-256 hash of the exact validated canonical request object. The
// field sequence below IS the preimage byte sequence — it is written out literally and is
// never sorted, rearranged, or normalized.
export function canonicalRequestSha256(request: SendCreateRequest): string {
  const canonical = JSON.stringify({
    implementer_id: request.implementerId,
    node_id: request.nodeId,
    source_wallet_id: request.sourceWalletId,
    destination_address: request.destinationAddress,
    amount_zkz: request.amountZkz,
    references_operation_id: request.referencesOperationId,
    client_reference: request.clientReference,
    description: request.description,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// A-canonical-fields padded base64url. The suite encoders own every signed byte; this
// only encodes the detached signature the signer returned.
function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

export interface SendCreateConfig {
  readonly generateId?: () => string;
  readonly now?: () => number;
  /**
   * hard gate for EXTERNAL send: the source wallet must hold an ACTIVE push
   * subscription. When injected, called after wallet eligibility check. MOVE_INTERNAL must
   * NOT inject this port.
   */
  readonly requireActiveSubscription?: (walletId: string) => Promise<void>;
}

export async function createExternalSend(
  store: SendCreateStore,
  signer: SendArtifactSigner,
  request: SendCreateRequest,
  config: SendCreateConfig = {},
): Promise<SendCreateOutcome> {
  const generateId = config.generateId ?? (() => randomUUID());
  const now = config.now ?? (() => Date.now());

  // Step 1 — validate the exact source/destination/amount before anything is resolved.
  const validation = validateSendCreateRequest(request);
  if (!validation.ok) {
    return { outcome: "REJECTED", code: validation.code, detail: validation.detail };
  }

  // Step 2 — the source must be a node-generated wallet controlled by this node. These
  // are reads; they create nothing, so idempotency is still resolved by the insert below.
  const wallet = await store.findSourceWallet(request.sourceWalletId);
  if (wallet === null) {
    return { outcome: "REJECTED", code: "source_wallet_not_found" };
  }
  if (!isSendSourceEligible(wallet, request.nodeId)) {
    return { outcome: "REJECTED", code: "source_wallet_not_eligible" };
  }

  // hard gate — source wallet must hold an ACTIVE push subscription.
  // The PushSubscriptionRequiredError propagates to the route error mapper
  // (mapStoreError → protocol_predicate_failed, 422). Do NOT catch it here.
  if (config.requireActiveSubscription) {
    await config.requireActiveSubscription(request.sourceWalletId);
  }

  // Step 2 — a destination that resolves to the node's current blessed internal set is a
  // MOVE_INTERNAL (three public money operations). It is rejected here, never silently accepted as an external send.
  if (await store.isBlessedInternalAddress(request.destinationAddress)) {
    return {
      outcome: "REJECTED",
      code: "destination_is_internal",
      detail: "destination resolves to a blessed internal destination; use MOVE_INTERNAL",
    };
  }

  const operationId = generateId();

  // Step 3 — the one exact expected artifact, built by the frozen
  // suite builder. source_pubkey is taken from the RESOLVED wallet record, never from the
  // request: the signed economic tuple must bind the wallet this node actually controls.
  let preimage;
  try {
    preimage = buildSendExternalExpectedArtifact({
      node_id: parseUuid(request.nodeId),
      implementer_id: parseUuid(request.implementerId),
      operation_id: parseUuid(operationId),
      source_selector: { kind: "WALLET_ID", wallet_id: parseUuid(wallet.walletId) },
      source_pubkey: parseWalletPublicKey(wallet.publicKey),
      destination_address: parseWalletPublicKey(request.destinationAddress),
      amount_zkz: parsePositiveZkzAmount(request.amountZkz),
      references_operation_id:
        request.referencesOperationId === null ? null : parseUuid(request.referencesOperationId),
    });
  } catch {
    // The only field not already validated above is the stored wallet public key. A wallet
    // whose recorded key cannot be parsed cannot be bound into a signed tuple, so it is not
    // an eligible source — fail closed rather than sign around it.
    return { outcome: "REJECTED", code: "source_wallet_not_eligible", detail: "source_pubkey" };
  }

  const artifact: SendExpectedArtifact = {
    artifactId: generateId(),
    operationId,
    purpose: SEND_EXPECTED_ARTIFACT_PURPOSE,
    canonicalVersion: 1,
    keyId: signer.signingKeyId,
    preimageText: preimage.preimageText,
    preimageSha256: preimage.sha256,
    signature: paddedBase64Url(signer.sign(preimage.preimageBytes)),
  };

  const operation: SendOperation = {
    operationId,
    implementerId: request.implementerId,
    nodeId: request.nodeId,
    kind: "SEND_EXTERNAL",
    status: "CREATED",
    rowVersion: 1,
    attentionRequired: false,
    formationState: "APPROVAL_PENDING",
    httpMethod: SEND_HTTP_METHOD,
    route: SEND_CANONICAL_ROUTE,
    sourceWalletId: request.sourceWalletId,
    destinationAddress: request.destinationAddress,
    amountZkz: request.amountZkz,
    referencesOperationId: request.referencesOperationId,
    clientReference: request.clientReference,
    description: request.description,
    idempotencyKey: request.idempotencyKey,
    requestSha256: canonicalRequestSha256(request),
    createdAt: now(),
  };

  // Step 3 — one DB-TX creates the operation row and its one artifact, or neither. The
  // database decides both idempotency and the one-in-flight-per-wallet rule; nothing above this line is
  // load-bearing for either invariant.
  const insert = await store.insertCreated(operation, artifact);
  if (insert.kind === "INSERTED") {
    return { outcome: "CREATED", operation, artifact };
  }
  if (insert.kind === "WALLET_IN_FLIGHT") {
    // The one-in-flight-per-wallet rule: an unsettled send already holds this source wallet.
    return { outcome: "REJECTED", code: "wallet_in_flight", detail: insert.walletId };
  }

  return resolveIdempotencyConflict(store, request, operation.requestSha256);
}

// Rules 1–3, decided against the row the winning inserter created.
async function resolveIdempotencyConflict(
  store: SendCreateStore,
  request: SendCreateRequest,
  requestSha256: string,
): Promise<SendCreateOutcome> {
  const existing = await store.findByIdempotency(
    request.implementerId,
    SEND_HTTP_METHOD,
    SEND_CANONICAL_ROUTE,
    request.idempotencyKey,
  );
  if (existing === null) {
    // The winner's row is not visible to this reader yet (or was rolled back after claiming
    // the key). Never treat that as "no operation exists" and insert a second one.
    return {
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
    };
  }
  // Rule 2 — same key, different request. Return the conflict; change nothing.
  if (existing.requestSha256 !== requestSha256) {
    return { outcome: "REJECTED", code: "idempotency_key_reused" };
  }
  // Rule 3 — the creator has not stored its result yet.
  if (existing.responseBody === null || existing.responseStatus === null) {
    return {
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
    };
  }
  // Rule 1 — replay the first completed execution's exact status and body.
  return {
    outcome: "IDEMPOTENT_REPLAY",
    operation: existing,
    responseStatus: existing.responseStatus,
    responseBody: existing.responseBody,
  };
}

// Response body. Create-time freezes transfer_code fields null;
// AWAITING_REDEMPTION fills transfer_code + sha256 + available_until from
// the durable partial — never recomputed.
export type ExternalSendApprovalStatus = "PENDING" | "APPROVED" | "CONSUMED";

export interface ExternalSendPartialDelivery {
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  /** Derived RFC3339 projection of signed T2 (SEND_EXTERNAL expiry single-source); null when not yet available. */
  readonly availableUntil: string | null;
}

export interface ExternalSendResponse {
  readonly operation: {
    readonly operation_id: string;
    readonly operation_type: "SEND_EXTERNAL";
    readonly state: string;
    readonly amount_zkz: string;
    readonly row_version: number;
    readonly attention_required: boolean;
    readonly attention_reason: null;
    readonly created_at: string;
    readonly updated_at: string;
    readonly terminal_at: null;
    readonly verification_material_available_until: null;
  };
  readonly source_wallet_id: string;
  readonly destination_address: string;
  readonly references_operation_id: string | null;
  readonly approval_status: ExternalSendApprovalStatus;
  readonly transfer_code: string | null;
  readonly transfer_code_sha256: string | null;
  readonly available_until: string | null;
  readonly expected_artifact: {
    readonly key_id: string;
    readonly preimage_text: string;
    readonly preimage_sha256: string;
    readonly signature: string;
  };
}

export function buildExternalSendResponse(
  operation: SendOperation | StoredSendOperation,
  artifact: SendExpectedArtifact,
  delivery: ExternalSendPartialDelivery | null = null,
): ExternalSendResponse {
  const createdAt = new Date(operation.createdAt).toISOString();
  const approvalStatus: ExternalSendApprovalStatus =
    operation.status === "CREATED"
      ? "PENDING"
      : operation.status === "APPROVED"
        ? "APPROVED"
        : "CONSUMED";
  return {
    operation: {
      operation_id: operation.operationId,
      operation_type: "SEND_EXTERNAL",
      state: operation.status,
      amount_zkz: operation.amountZkz,
      row_version: operation.rowVersion,
      attention_required: operation.attentionRequired,
      attention_reason: null,
      created_at: createdAt,
      updated_at: createdAt,
      terminal_at: null,
      verification_material_available_until: null,
    },
    source_wallet_id: operation.sourceWalletId,
    destination_address: operation.destinationAddress,
    references_operation_id: operation.referencesOperationId,
    approval_status: approvalStatus,
    transfer_code: delivery?.transferCodeText ?? null,
    transfer_code_sha256: delivery?.transferCodeSha256 ?? null,
    available_until: delivery?.availableUntil ?? null,
    expected_artifact: {
      key_id: artifact.keyId,
      preimage_text: artifact.preimageText,
      preimage_sha256: artifact.preimageSha256,
      signature: artifact.signature,
    },
  };
}

/** Loader for durable partial bytes at AWAITING_REDEMPTION. */
export interface ExternalSendPartialLoader {
  loadPartial(operationId: string): Promise<ExternalSendPartialDelivery | null>;
}

export type ExternalSendReadOutcome =
  | { readonly outcome: "FOUND"; readonly response: ExternalSendResponse }
  | { readonly outcome: "NOT_FOUND" }
  | { readonly outcome: "OUT_OF_SLICE"; readonly state: string };

const READABLE_SEND_STATUSES = new Set([
  "CREATED",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "NEEDS_ATTENTION",
  "EXTERNAL_SEND_LANDED",
  "REJECTED",
]);

// CREATED/APPROVED return without code; AWAITING_REDEMPTION joins the
// durable partial fingerprint (+ plaintext once delivered). Terminal/attention stay readable.
export async function readExternalSend(
  store: SendCreateStore,
  operationId: string,
  partials?: ExternalSendPartialLoader,
): Promise<ExternalSendReadOutcome> {
  const found = await store.findByOperationId(operationId);
  if (found === null) return { outcome: "NOT_FOUND" };
  if (!READABLE_SEND_STATUSES.has(found.operation.status)) {
    return { outcome: "OUT_OF_SLICE", state: found.operation.status };
  }
  let delivery: ExternalSendPartialDelivery | null = null;
  if (
    found.operation.status === "AWAITING_REDEMPTION" ||
    found.operation.status === "EXTERNAL_SEND_LANDED" ||
    found.operation.status === "NEEDS_ATTENTION"
  ) {
    delivery = partials !== undefined ? await partials.loadPartial(operationId) : null;
  }
  return {
    outcome: "FOUND",
    response: buildExternalSendResponse(found.operation, found.artifact, delivery),
  };
}
