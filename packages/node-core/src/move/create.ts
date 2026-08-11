// MOVE_INTERNAL admission — validate the request, resolve source/destination eligibility,
// resolve idempotency, and create the MOVE_INTERNAL/CREATED operation in one DB-TX.
//
// The internal custody and automatic-sink destination predicates gate the request; the
// operations CHECK constrains the row shape. There are three public money operations.
//
// Scope of THIS slice: admission only. No lease acquisition of source
// or destination wallets, no OBSERVE / baseline capture, no signing,
// no expected-artifact formation, and no gateway call. The create response therefore carries
// lease_status="WAITING" and expected_artifact=null; those fields fill in on later slices.
//
// The database is the arbiter for idempotency (operations UNIQUE (implementer_id, kind,
// idempotency_key) + request_sha256) and for the MOVE_INTERNAL row shape. Idempotency is
// resolved before eligibility and wallet_busy (rules 1 & 4; step 1) so a
// same-hash replay never loses to a later busy or ineligible wallet. Public admits still
// refuse an already-leased explicit wallet with 409 wallet_busy; receive-spawned
// children skip that public busy gate because the parent holds the source lease.

import { createHash, randomUUID } from "node:crypto";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid } from "../protocol/scalars.js";
import {
  deriveExecutionPhase,
  type DurableExecutionFacts,
  type ExecutionPhase,
} from "../core/execution-phase.js";

// The idempotency scope includes the HTTP method and the canonical
// route. This slice serves exactly one public route.
export const MOVE_HTTP_METHOD = "POST" as const;
export const MOVE_CANONICAL_ROUTE = "/v1/internal-moves" as const;
export const MOVE_OPERATION_KIND = "MOVE_INTERNAL" as const;

// Rule 3: followers of a concurrent first use wait briefly, then get
// 409 idempotency_in_progress with Retry-After.
export const MOVE_IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS = 1;

export type MoveWalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";
export type MoveDestinationState = "PENDING" | "BLESSED" | "RETIRED";

export interface MoveSourceWalletRecord {
  readonly walletId: string;
  readonly nodeId: string;
  readonly publicKey: string;
  readonly keyOrigin: "node_generated" | "imported";
  readonly state: MoveWalletState;
}

/** Destination resolved through destinations ⨝ wallets (predicates 2–4; generic core neutrality; recovery_verified_at gate). */
export interface MoveDestinationRecord {
  readonly destinationId: string;
  readonly nodeId: string;
  readonly walletId: string;
  readonly publicKey: string;
  readonly keyOrigin: "node_generated" | "imported";
  readonly walletState: MoveWalletState;
  readonly destinationState: MoveDestinationState;
  /** ISO-8601 timestamptz; null when recovery has never been verified. */
  readonly recoveryVerifiedAt: string | null;
}

export interface MoveCreateRequest {
  readonly implementerId: string;
  readonly nodeId: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly amountZkz: string;
  readonly idempotencyKey: string;
  /**
   * Receive-spawned child path only (step 4). Callers of POST /v1/internal-moves
   * cannot set this — the public body schema rejects unknown fields. When set, admission joins
   * the parent's lease group instead of creating a new one.
   */
  readonly spawnedFromOperationId?: string | null;
  /** Required when spawnedFromOperationId is set — the parent's existing lease_groups.id. */
  readonly parentLeaseGroupId?: string | null;
}

export interface MoveOperation {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly kind: typeof MOVE_OPERATION_KIND;
  readonly status: "CREATED";
  readonly rowVersion: 1;
  readonly attentionRequired: false;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly amountZkz: string;
  readonly spawnedFromOperationId: string | null;
  readonly leaseGroupId: string;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly createdAt: number;
}

export interface StoredMoveOperation {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly kind: typeof MOVE_OPERATION_KIND;
  readonly status: string;
  readonly rowVersion: number;
  readonly attentionRequired: boolean;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly amountZkz: string;
  readonly spawnedFromOperationId: string | null;
  readonly leaseGroupId: string | null;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface MoveExpectedArtifact {
  readonly keyId: string;
  /** Exact persisted signed preimage. Never parse and reconstruct this value. */
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signature: string;
}

export interface MoveReadProjection {
  readonly attentionReason: string | null;
  readonly terminalAt: string | null;
  readonly verificationMaterialAvailableUntil: string | null;
  /** MOVE_INTERNAL owns exactly source + destination leases. */
  readonly activeLeaseCount: number;
  readonly expectedArtifact: MoveExpectedArtifact | null;
  readonly executionFacts: DurableExecutionFacts;
  readonly sourceTerminalObservationId: string | null;
  readonly destinationTerminalObservationId: string | null;
}

export type MoveRejectionCode =
  | "missing_idempotency_key"
  | "invalid_tenant_id"
  | "invalid_source_wallet_id"
  | "invalid_destination_id"
  | "invalid_amount"
  | "invalid_spawned_from_operation_id"
  | "source_wallet_not_found"
  | "source_wallet_not_eligible"
  | "destination_not_found"
  | "destination_not_eligible"
  | "same_wallet"
  | "wallet_busy"
  | "idempotency_key_reused"
  | "idempotency_in_progress";

export type MoveCreateOutcome =
  | {
      readonly outcome: "CREATED";
      readonly operation: MoveOperation;
    }
  | {
      readonly outcome: "IDEMPOTENT_REPLAY";
      readonly operation: StoredMoveOperation;
      readonly responseStatus: number;
      readonly responseBody: string;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: MoveRejectionCode;
      readonly detail?: string;
      readonly retryAfterSeconds?: number;
    };

export type MoveInsertOutcome =
  | { readonly kind: "INSERTED"; readonly leaseGroupId: string }
  | { readonly kind: "IDEMPOTENCY_CONFLICT" };

export interface MoveAdmitInsert {
  readonly operation: MoveOperation;
  /** New lease group for a stand-alone move; null when joining a parent group. */
  readonly createLeaseGroup: boolean;
  readonly parentLeaseGroupId: string | null;
}

export interface MoveCreateStore {
  findSourceWallet(walletId: string): Promise<MoveSourceWalletRecord | null>;
  findDestination(destinationId: string): Promise<MoveDestinationRecord | null>;
  /** True when wallet_active_leases already holds this wallet (wallet_busy). */
  hasActiveLease(walletId: string): Promise<boolean>;
  /**
   * One DB-TX: insert MOVE_INTERNAL/CREATED, create or join lease_groups, append
   * internal_move.created, and record the idempotency response material. MUST NOT pre-read
   * to decide idempotency — the UNIQUE constraint decides.
   */
  insertAdmitted(input: MoveAdmitInsert): Promise<MoveInsertOutcome>;
  findByIdempotency(
    implementerId: string,
    kind: typeof MOVE_OPERATION_KIND,
    idempotencyKey: string,
  ): Promise<StoredMoveOperation | null>;
  findByOperationId(operationId: string): Promise<StoredMoveOperation | null>;
  /** Live GET overlay. Optional only for narrow admission-only test stores. */
  readProjection?(operationId: string): Promise<MoveReadProjection>;
}

// Frozen API grammar (api/scalars.ts): idempotency key 16–255 visible ASCII.
const IDEMPOTENCY_KEY_RE = /^[\x20-\x7E]{16,255}$/;

/**
 * Step 2 — source is node-generated and controlled by this node.
 * Public path: state must be AVAILABLE.
 * Receive-child path: parent holds the source lease continuously, so
 * wallets.state is PINNED — allow AVAILABLE|PINNED. Still refuse QUARANTINED/RETIRED.
 */
export function isMoveSourceEligible(
  wallet: MoveSourceWalletRecord,
  nodeId: string,
  options: { allowPinned?: boolean } = {},
): boolean {
  const stateOk =
    wallet.state === "AVAILABLE" ||
    (options.allowPinned === true && wallet.state === "PINNED");
  return (
    wallet.keyOrigin === "node_generated" &&
    wallet.nodeId === nodeId &&
    stateOk
  );
}

/**
 * Step 3 — automatic-sink destination: it resolves to a different
 * node-generated wallet that is BLESSED, recovery-verified, and wallet_state AVAILABLE.
 * Recovery verification never makes an imported or unblessed wallet internal.
 */
export function isMoveDestinationEligible(
  destination: MoveDestinationRecord,
  nodeId: string,
  sourceWalletId: string,
): { ok: true } | { ok: false; code: MoveRejectionCode; detail?: string } {
  if (destination.nodeId !== nodeId) {
    return { ok: false, code: "destination_not_eligible", detail: "foreign_node" };
  }
  if (destination.walletId === sourceWalletId) {
    return { ok: false, code: "same_wallet" };
  }
  if (destination.keyOrigin !== "node_generated") {
    return {
      ok: false,
      code: "destination_not_eligible",
      detail: "key_origin_not_node_generated",
    };
  }
  if (destination.destinationState !== "BLESSED") {
    return {
      ok: false,
      code: "destination_not_eligible",
      detail: `destination_state=${destination.destinationState}`,
    };
  }
  if (destination.recoveryVerifiedAt === null) {
    return {
      ok: false,
      code: "destination_not_eligible",
      detail: "recovery_unverified",
    };
  }
  if (destination.walletState !== "AVAILABLE") {
    return {
      ok: false,
      code: "destination_not_eligible",
      detail: `wallet_state=${destination.walletState}`,
    };
  }
  return { ok: true };
}

export function validateMoveCreateRequest(
  request: MoveCreateRequest,
): { ok: true } | { ok: false; code: MoveRejectionCode; detail?: string } {
  if (!IDEMPOTENCY_KEY_RE.test(request.idempotencyKey)) {
    return { ok: false, code: "missing_idempotency_key" };
  }
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
    parseUuid(request.destinationId);
  } catch {
    return { ok: false, code: "invalid_destination_id" };
  }
  // at the API boundary: strictly positive and strictly below 1e8.
  try {
    parsePositiveZkzAmount(request.amountZkz);
  } catch {
    return {
      ok: false,
      code: "invalid_amount",
      detail: "amount_zkz must be a positive canonical decimal, strictly < 100000000",
    };
  }
  const spawned = request.spawnedFromOperationId ?? null;
  if (spawned !== null) {
    try {
      parseUuid(spawned);
    } catch {
      return { ok: false, code: "invalid_spawned_from_operation_id" };
    }
    const parentGroup = request.parentLeaseGroupId ?? null;
    if (parentGroup === null) {
      return {
        ok: false,
        code: "invalid_spawned_from_operation_id",
        detail: "parent_lease_group_id required for receive child",
      };
    }
    try {
      parseUuid(parentGroup);
    } catch {
      return {
        ok: false,
        code: "invalid_spawned_from_operation_id",
        detail: "invalid_parent_lease_group_id",
      };
    }
  }
  return { ok: true };
}

// SHA-256 of the exact validated canonical request object. Field sequence
// IS the preimage — never sorted, rearranged, or normalized. spawned_from is omitted from the
// public-path fingerprint (callers cannot set it); the child path includes it so a public
// retry cannot collide with an internal spawn under the same key.
export function canonicalMoveRequestSha256(request: MoveCreateRequest): string {
  const spawned = request.spawnedFromOperationId ?? null;
  const canonical =
    spawned === null
      ? JSON.stringify({
          implementer_id: request.implementerId,
          node_id: request.nodeId,
          source_wallet_id: request.sourceWalletId,
          destination_id: request.destinationId,
          amount_zkz: request.amountZkz,
        })
      : JSON.stringify({
          implementer_id: request.implementerId,
          node_id: request.nodeId,
          source_wallet_id: request.sourceWalletId,
          destination_id: request.destinationId,
          amount_zkz: request.amountZkz,
          spawned_from_operation_id: spawned,
        });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export interface MoveCreateConfig {
  readonly generateId?: () => string;
  readonly now?: () => number;
}

export async function createInternalMove(
  store: MoveCreateStore,
  request: MoveCreateRequest,
  config: MoveCreateConfig = {},
): Promise<MoveCreateOutcome> {
  const generateId = config.generateId ?? (() => randomUUID());
  const now = config.now ?? (() => Date.now());

  // Step 1 — validate, then resolve idempotency before any eligibility/busy gate so a
  // same-hash replay never loses to wallet_busy or a later-ineligible wallet (r1/r4).
  const validation = validateMoveCreateRequest(request);
  if (!validation.ok) {
    return { outcome: "REJECTED", code: validation.code, detail: validation.detail };
  }

  const requestSha256 = canonicalMoveRequestSha256(request);
  const existing = await store.findByIdempotency(
    request.implementerId,
    MOVE_OPERATION_KIND,
    request.idempotencyKey,
  );
  if (existing !== null) {
    if (existing.requestSha256 !== requestSha256) {
      return { outcome: "REJECTED", code: "idempotency_key_reused" };
    }
    const body = JSON.stringify(buildInternalMoveResponse(existing));
    return {
      outcome: "IDEMPOTENT_REPLAY",
      operation: existing,
      responseStatus: 201,
      responseBody: body,
    };
  }

  // Step 2 — source must be a node-generated wallet controlled by this node.
  // Receive-child: parent lease pins the source — PINNED is eligible there only.
  const source = await store.findSourceWallet(request.sourceWalletId);
  if (source === null) {
    return { outcome: "REJECTED", code: "source_wallet_not_found" };
  }
  const receiveChild = request.spawnedFromOperationId != null;
  if (!isMoveSourceEligible(source, request.nodeId, { allowPinned: receiveChild })) {
    return { outcome: "REJECTED", code: "source_wallet_not_eligible" };
  }

  // Step 3 — destination_id → different node-generated BLESSED recovery-verified AVAILABLE.
  const destination = await store.findDestination(request.destinationId);
  if (destination === null) {
    return { outcome: "REJECTED", code: "destination_not_found" };
  }
  // Same-wallet before the broader eligibility detail (reject before DB-TX).
  if (destination.walletId === request.sourceWalletId) {
    return { outcome: "REJECTED", code: "same_wallet" };
  }
  const destOk = isMoveDestinationEligible(destination, request.nodeId, request.sourceWalletId);
  if (!destOk.ok) {
    return { outcome: "REJECTED", code: destOk.code, detail: destOk.detail };
  }

  const spawnedFromOperationId = request.spawnedFromOperationId ?? null;
  const parentLeaseGroupId =
    spawnedFromOperationId === null ? null : (request.parentLeaseGroupId ?? null);
  const createLeaseGroup = spawnedFromOperationId === null;

  // Public path — explicitly selected busy wallets return 409 wallet_busy.
  // Receive-child: parent holds the source lease (and dest may be busy
  // while the child queues CREATED/JOINED). Never surface public wallet_busy on the child path.
  if (spawnedFromOperationId === null) {
    if (await store.hasActiveLease(request.sourceWalletId)) {
      return {
        outcome: "REJECTED",
        code: "wallet_busy",
        detail: `source_wallet_id=${request.sourceWalletId}`,
      };
    }
    if (await store.hasActiveLease(destination.walletId)) {
      return {
        outcome: "REJECTED",
        code: "wallet_busy",
        detail: `destination_wallet_id=${destination.walletId}`,
      };
    }
  }

  const operationId = generateId();
  // Placeholder lease group id for stand-alone moves: the store assigns the durable id inside
  // the insert TX and returns it. For a receive child the parent group id is already known.
  const provisionalLeaseGroupId = createLeaseGroup
    ? generateId()
    : (parentLeaseGroupId as string);

  const operation: MoveOperation = {
    operationId,
    implementerId: request.implementerId,
    nodeId: request.nodeId,
    kind: MOVE_OPERATION_KIND,
    status: "CREATED",
    rowVersion: 1,
    attentionRequired: false,
    sourceWalletId: request.sourceWalletId,
    destinationId: request.destinationId,
    destinationWalletId: destination.walletId,
    amountZkz: request.amountZkz,
    spawnedFromOperationId,
    leaseGroupId: provisionalLeaseGroupId,
    idempotencyKey: request.idempotencyKey,
    requestSha256,
    createdAt: now(),
  };

  // Step 4 — one DB-TX creates the operation, lease group (or join), event, and
  // idempotency response material. The UNIQUE constraint decides concurrent first use
  // that raced past the pre-insert lookup above.
  const insert = await store.insertAdmitted({
    operation,
    createLeaseGroup,
    parentLeaseGroupId,
  });

  if (insert.kind === "INSERTED") {
    return {
      outcome: "CREATED",
      operation: { ...operation, leaseGroupId: insert.leaseGroupId },
    };
  }

  return resolveIdempotencyConflict(store, request, requestSha256);
}

async function resolveIdempotencyConflict(
  store: MoveCreateStore,
  request: MoveCreateRequest,
  requestSha256: string,
): Promise<MoveCreateOutcome> {
  const existing = await store.findByIdempotency(
    request.implementerId,
    MOVE_OPERATION_KIND,
    request.idempotencyKey,
  );
  if (existing === null) {
    return {
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: MOVE_IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
    };
  }
  // Rule 2 — same key, different body. Change nothing.
  if (existing.requestSha256 !== requestSha256) {
    return { outcome: "REJECTED", code: "idempotency_key_reused" };
  }
  // Rule 1 — replay the first completed execution's exact status and body.
  // Body is rebuilt from the durable operation row (all create-time fields are immutable).
  const body = JSON.stringify(buildInternalMoveResponse(existing));
  return {
    outcome: "IDEMPOTENT_REPLAY",
    operation: existing,
    responseStatus: 201,
    responseBody: body,
  };
}

// Response body. expected_artifact stays null until baseline acquisition binds it;
// lease_status is WAITING until dual-lease acquisition.
export type MoveLeaseStatus =
  | "WAITING"
  | "HELD"
  | "RELEASED"
  | "PINNED_FOR_ATTENTION";

export interface InternalMoveCreateResponse {
  readonly operation: {
    readonly operation_id: string;
    readonly operation_type: "MOVE_INTERNAL";
    readonly state: string;
    readonly amount_zkz: string;
    readonly row_version: number;
    readonly attention_required: boolean;
    readonly attention_reason: string | null;
    readonly created_at: string;
    readonly updated_at: string;
    readonly terminal_at: string | null;
    readonly verification_material_available_until: string | null;
  };
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly spawned_from_operation_id: string | null;
  readonly lease_status: MoveLeaseStatus;
  readonly execution_phase: ExecutionPhase;
  readonly expected_artifact: {
    readonly key_id: string;
    readonly preimage_text: string;
    readonly preimage_sha256: string;
    readonly signature: string;
  } | null;
  readonly source_terminal_observation_id: string | null;
  readonly destination_terminal_observation_id: string | null;
}

const emptyMoveExecutionFacts = (): DurableExecutionFacts => ({
  operationKind: "MOVE_INTERNAL",
  attemptPhase: null,
  signIntentPersisted: false,
  partialPersisted: false,
  partialFirstDelivered: false,
  submitStarted: false,
  submitReturned: false,
  verificationAccepted: false,
  terminalObservationsPresent: false,
});

export function buildInternalMoveResponse(
  operation: MoveOperation | StoredMoveOperation,
): InternalMoveCreateResponse {
  const createdAt = new Date(operation.createdAt).toISOString();
  const updatedAt =
    "updatedAt" in operation
      ? new Date(operation.updatedAt).toISOString()
      : createdAt;
  return {
    operation: {
      operation_id: operation.operationId,
      operation_type: "MOVE_INTERNAL",
      state: operation.status,
      amount_zkz: operation.amountZkz,
      row_version: operation.rowVersion,
      attention_required: operation.attentionRequired,
      attention_reason: null,
      created_at: createdAt,
      updated_at: updatedAt,
      terminal_at: null,
      verification_material_available_until: null,
    },
    source_wallet_id: operation.sourceWalletId,
    destination_id: operation.destinationId,
    spawned_from_operation_id: operation.spawnedFromOperationId,
    lease_status: "WAITING",
    execution_phase: deriveExecutionPhase(emptyMoveExecutionFacts()),
    expected_artifact: null,
    source_terminal_observation_id: null,
    destination_terminal_observation_id: null,
  };
}

function projectMoveLeaseStatus(
  operation: StoredMoveOperation,
  projection: MoveReadProjection,
): MoveLeaseStatus {
  // A move is a two-lease unit. Any disagreement (exactly one live lease) is
  // projected as pinned rather than laundering a split group into HELD/RELEASED.
  if (operation.attentionRequired || projection.activeLeaseCount === 1) {
    return "PINNED_FOR_ATTENTION";
  }
  if (projection.activeLeaseCount === 2) return "HELD";
  if (projection.activeLeaseCount === 0) {
    return operation.status === "CREATED" ? "WAITING" : "RELEASED";
  }
  return "PINNED_FOR_ATTENTION";
}

export type InternalMoveReadOutcome =
  | { readonly outcome: "FOUND"; readonly response: InternalMoveCreateResponse }
  | { readonly outcome: "NOT_FOUND" };

export async function readInternalMove(
  store: MoveCreateStore,
  operationId: string,
): Promise<InternalMoveReadOutcome> {
  const found = await store.findByOperationId(operationId);
  if (found === null) return { outcome: "NOT_FOUND" };
  const body = buildInternalMoveResponse(found);
  const projection = await store.readProjection?.(operationId);
  if (projection === undefined) return { outcome: "FOUND", response: body };
  const artifact = projection.expectedArtifact;
  return {
    outcome: "FOUND",
    response: {
      ...body,
      operation: {
        ...body.operation,
        attention_reason: projection.attentionReason,
        terminal_at: projection.terminalAt,
        verification_material_available_until:
          projection.verificationMaterialAvailableUntil,
      },
      lease_status: projectMoveLeaseStatus(found, projection),
      execution_phase: deriveExecutionPhase(projection.executionFacts),
      expected_artifact:
        artifact === null
          ? null
          : {
              key_id: artifact.keyId,
              preimage_text: artifact.preimageText,
              preimage_sha256: artifact.preimageSha256,
              signature: artifact.signature,
            },
      source_terminal_observation_id: projection.sourceTerminalObservationId,
      destination_terminal_observation_id: projection.destinationTerminalObservationId,
    },
  };
}

/**
 * Map a MoveCreateOutcome onto the OperationRouteStore contract used by
 * handleCreateInternalMove (throws WalletBusyError / MoveAdmissionError).
 */
export function moveOutcomeToRouteResult(
  outcome: MoveCreateOutcome,
): {
  readonly status: 201;
  readonly body: InternalMoveCreateResponse;
  readonly idempotentReplay?: boolean;
} {
  if (outcome.outcome === "CREATED") {
    return { status: 201, body: buildInternalMoveResponse(outcome.operation) };
  }
  if (outcome.outcome === "IDEMPOTENT_REPLAY") {
    return {
      status: 201,
      body: JSON.parse(outcome.responseBody) as InternalMoveCreateResponse,
      idempotentReplay: true,
    };
  }
  // Rejection — callers translate via throwMoveRejection.
  throw new MoveAdmissionError(outcome.code, outcome.detail, outcome.retryAfterSeconds);
}

export class MoveAdmissionError extends Error {
  readonly code: MoveRejectionCode;
  readonly detail?: string;
  readonly retryAfterSeconds?: number;
  constructor(code: MoveRejectionCode, detail?: string, retryAfterSeconds?: number) {
    super(code);
    this.name = "MoveAdmissionError";
    this.code = code;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
