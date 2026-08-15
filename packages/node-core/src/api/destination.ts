// Destination registration and blessing — the operator-facing custody ceremony that
// admits a node-generated wallet as an internal move / external-send sink.
// Spec: (register, list)
// and (bless, retire); (destinations table, predicates 2/3/6);
// (internal_custody vs automatic_sink_eligible).
//
// State machine (`destination_state`): PENDING -> BLESSED -> RETIRED.
// WORKER is a node-owned send-worker sink (scaler mint), not this ceremony.
// A destination registers PENDING; only a BLESSED destination is internal custody
// (predicate 3: key_origin='node_generated' AND state='BLESSED') and may receive an
// implementer-facing internal move; RETIRED is terminal and is never reselected.
// Blessing is a device-key ceremony — TOTP alone cannot bless (predicate 6) — and the
// blessed wallet must be node-generated (predicate 2: imported wallets never enter
// destination history). Key custody: the node generates the keypair in its vault and
// this service only ever handles the public key, never private key material.
//
// GET /v1/destinations derives `move_eligible` / `ineligibility_reason` live
// from verifyAutomaticSinkEligibility — never stored columns. MOVE_INTERNAL and
// after_landing recheck the same predicates at execution time.

import {
  verifyAutomaticSinkEligibility,
  type CustodyDenialReason,
  type DestinationState,
  type WalletKeyOrigin,
  type WalletState,
} from "@zucoins/generic-node-contracts/custody";

import type { Uuid, WalletPublicKey } from "../protocol/scalars.js";

export type { DestinationState, CustodyDenialReason };

export interface DestinationRecord {
  readonly destinationId: Uuid;
  readonly nodeId: Uuid;
  readonly walletId: Uuid;
  readonly walletPublicKey: WalletPublicKey;
  readonly state: DestinationState;
  readonly label: string;
  readonly blessedAt: string | null;
  readonly blessedByDeviceKeyId: Uuid | null;
  readonly blessingArtifactId: Uuid | null;
  readonly retiredAt: string | null;
  readonly createdAt: string;
}

/** List item — eligibility fields are derived, not mutable destination state. */
export interface DestinationListItem extends DestinationRecord {
  readonly move_eligible: boolean;
  readonly ineligibility_reason: CustodyDenialReason | null;
}

export interface DestinationFilter {
  readonly state?: DestinationState;
  readonly after?: Uuid;
  readonly limit?: number;
}

export interface DestinationPage {
  readonly items: readonly DestinationListItem[];
  readonly nextAfter: Uuid | null;
}

export interface NewDestination {
  readonly destinationId: Uuid;
  readonly nodeId: Uuid;
  readonly walletId: Uuid;
  readonly walletPublicKey: WalletPublicKey;
  readonly label: string;
  readonly createdAt: string;
}

/**
 * Authoritative wallet facts used only for live eligibility derivation (generic core neutrality).
 * Callers never supply precomputed eligibility booleans — only raw wallet columns.
 */
export interface DestinationWalletFacts {
  readonly keyOrigin: WalletKeyOrigin;
  readonly walletState: WalletState;
  /** ISO-8601 timestamptz when recovery was verified; null if never verified. */
  readonly recoveryVerifiedAt: string | null;
}

// Persistence port. The store is the structural owner of the data-model invariants
// this service cannot see: predicate 2 (a destinations insert is rejected unless the
// referenced wallet is node_generated) and the wallet_id uniqueness bar. Insert is
// idempotent on idempotencyKey — a replay returns the original row.
export interface DestinationStore {
  findById(destinationId: Uuid): Promise<DestinationRecord | null>;
  findByIdempotencyKey(nodeId: Uuid, idempotencyKey: string): Promise<DestinationRecord | null>;
  insert(record: NewDestination, idempotencyKey: string): Promise<DestinationRecord>;
  walletKeyOrigin(walletId: Uuid): Promise<WalletKeyOrigin | null>;
  /**
   * Load authoritative wallet columns for sink-eligibility derivation.
   * Returns null only when the wallet row is missing (fail-closed at the list edge).
   */
  walletFacts(walletId: Uuid): Promise<DestinationWalletFacts | null>;
  /**
   * Atomic PENDING → BLESSED compare-and-set.
   * Returns the updated row on success, or null when no PENDING row matched
   * (lost race / already transitioned). Callers must re-read and map.
   */
  bless(
    destinationId: Uuid,
    patch: {
      readonly blessedAt: string;
      readonly blessedByDeviceKeyId: Uuid;
      readonly blessingArtifactId: Uuid;
    },
  ): Promise<DestinationRecord | null>;
  retire(destinationId: Uuid, retiredAt: string): Promise<DestinationRecord>;
  list(
    nodeId: Uuid,
    filter: DestinationFilter,
  ): Promise<{ readonly items: readonly DestinationRecord[]; readonly nextAfter: Uuid | null }>;
}

// The node generates a fresh wallet keypair inside its vault and exposes only the
// public key here — the service never touches private key material.
// Register passes `{ idempotencyKey, label }` so a production generator can
// reserve the UNIQUE (node_id, key) inside the same mint txn. In-memory
// generators ignore the claim.
export interface DestinationWalletKeyClaim {
  readonly idempotencyKey: string;
  readonly label: string;
}

export interface DestinationWalletKeyGenerator {
  generate(
    nodeId: Uuid,
    claim?: DestinationWalletKeyClaim,
  ): Promise<{ readonly walletId: Uuid; readonly publicKey: WalletPublicKey }>;
}

/**
 * Unique-claim miss on destinations_node_idempotency_key_uidx. The caller
 * already rolled back its mint; register must find the winner and return
 * already_registered — never treat this as service_unavailable.
 */
export class DestinationIdempotencyKeyClaimedError extends Error {
  constructor(
    readonly nodeId: Uuid,
    readonly idempotencyKey: string,
  ) {
    super("destination idempotency key already claimed");
    this.name = "DestinationIdempotencyKeyClaimedError";
  }
}

export function isDestinationIdempotencyKeyClaimed(err: unknown): boolean {
  return err instanceof DestinationIdempotencyKeyClaimedError;
}

// The destination-blessing ceremony (A.4.2 `zp-destination-bless-v1`): the caller
// supplies a fresh nonce and an operator device-key signature over the blessing
// preimage; the authorizer binds the signed node/destination/wallet/public-key fields
// to this destination, enforces the issued_at/expires_at window, verifies the device
// signature, and returns the signing device key id plus the persisted blessing
// artifact id. A null result is a failed ceremony (bad signature, expired window, or
// field mismatch). TOTP alone never reaches this port (predicate 6).
export interface BlessingAuthorizer {
  /**
   * Verify A.4.2 preimage (incl. expires_at) + device signature + window.
   * Concrete authorizers rebuild/verify via buildDestinationBless /
   * verifyDestinationBless; this port only carries the full field set.
   * TOTP alone never reaches this port (predicate 6).
   */
  authorize(input: {
    readonly nodeId: Uuid;
    readonly destinationId: Uuid;
    readonly walletId: Uuid;
    readonly walletPublicKey: WalletPublicKey;
    readonly nonce: Uuid;
    readonly issuedAt: string;
    readonly expiresAt: string;
    readonly deviceSignature: string;
    /** Enrolled operator_device_keys.id (A.4.2 device dual-control). */
    readonly deviceKeyId: Uuid;
  }): Promise<{ readonly deviceKeyId: Uuid; readonly artifactId: Uuid } | null>;
}

export interface DestinationClock {
  now(): string;
}

export interface DestinationIdGenerator {
  destinationId(): Uuid;
}

/**
 * Register request — structurally cannot carry an imported public key, address, or
 * key_origin. Only `label` (plus tenant/idempotency) is accepted; the node mints the
 * wallet inside its vault (R-04).
 */
export interface RegisterDestinationRequest {
  readonly nodeId: Uuid;
  readonly label: string;
  readonly idempotencyKey: string;
}

export interface BlessDestinationRequest {
  readonly nodeId: Uuid;
  readonly destinationId: Uuid;
  readonly nonce: Uuid;
  readonly issuedAt: string;
  /** A.4.2 field 9 — signed window end; authorizer enforces 0 < expires_at − issued_at ≤ 300s. */
  readonly expiresAt: string;
  readonly deviceSignature: string;
  /** Enrolled operator_device_keys.id that produced deviceSignature. */
  readonly deviceKeyId: Uuid;
}

export interface RetireDestinationRequest {
  readonly nodeId: Uuid;
  readonly destinationId: Uuid;
}

export type RegisterDestinationOutcome =
  | { readonly status: "created"; readonly destination: DestinationRecord }
  | { readonly status: "already_registered"; readonly destination: DestinationRecord };

export type BlessDestinationOutcome =
  | { readonly status: "blessed"; readonly destination: DestinationRecord }
  | { readonly status: "already_blessed"; readonly destination: DestinationRecord }
  | { readonly status: "not_found"; readonly destinationId: Uuid }
  | { readonly status: "invalid_transition"; readonly destinationId: Uuid; readonly from: DestinationState }
  | { readonly status: "authorization_rejected"; readonly destinationId: Uuid };

export type RetireDestinationOutcome =
  | { readonly status: "retired"; readonly destination: DestinationRecord }
  | { readonly status: "already_retired"; readonly destination: DestinationRecord }
  | { readonly status: "not_found"; readonly destinationId: Uuid }
  | { readonly status: "invalid_transition"; readonly destinationId: Uuid; readonly from: DestinationState };

export interface DestinationService {
  register(request: RegisterDestinationRequest): Promise<RegisterDestinationOutcome>;
  bless(request: BlessDestinationRequest): Promise<BlessDestinationOutcome>;
  retire(request: RetireDestinationRequest): Promise<RetireDestinationOutcome>;
  list(nodeId: Uuid, filter: DestinationFilter): Promise<DestinationPage>;
  get(nodeId: Uuid, destinationId: Uuid): Promise<DestinationListItem | null>;
}

const DEFAULT_LIST_LIMIT = 20;

/**
 * Derive move eligibility from authoritative wallet + destination facts.
 * Uses automatic_sink_eligible (generic core neutrality): internal custody AND recovery-verified AND
 * wallet state in {AVAILABLE, PINNED}. Never caches; never accepts caller booleans.
 */
export function deriveMoveEligibility(
  destination: DestinationRecord,
  facts: DestinationWalletFacts | null,
): Pick<DestinationListItem, "move_eligible" | "ineligibility_reason"> {
  if (facts === null) {
    // Missing wallet row — fail closed (same family as INVALID_KEY_ORIGIN).
    return { move_eligible: false, ineligibility_reason: "INVALID_KEY_ORIGIN" };
  }
  const decision = verifyAutomaticSinkEligibility({
    keyOrigin: facts.keyOrigin,
    destinationState: destination.state,
    recoveryVerifiedAt: facts.recoveryVerifiedAt,
    walletState: facts.walletState,
  });
  return {
    move_eligible: decision.eligible,
    ineligibility_reason: decision.denialReason,
  };
}

async function withEligibility(
  store: DestinationStore,
  destination: DestinationRecord,
): Promise<DestinationListItem> {
  const facts = await store.walletFacts(destination.walletId);
  const eligibility = deriveMoveEligibility(destination, facts);
  return { ...destination, ...eligibility };
}

export function createDestinationService(deps: {
  readonly store: DestinationStore;
  readonly keyGenerator: DestinationWalletKeyGenerator;
  readonly blessingAuthorizer: BlessingAuthorizer;
  readonly clock: DestinationClock;
  readonly ids: DestinationIdGenerator;
}): DestinationService {
  const { store, keyGenerator, blessingAuthorizer, clock, ids } = deps;

  return {
    async register(request) {
      const replay = await store.findByIdempotencyKey(request.nodeId, request.idempotencyKey);
      if (replay !== null) {
        return { status: "already_registered", destination: replay };
      }

      // Node-minted keypair only — RegisterDestinationRequest has no public-key /
      // address / key_origin field, so no code path can write an imported origin.
      // Pass the claim so a production generator reserves UNIQUE (node_id, key)
      // inside the mint txn. A typed unique-claim miss means another writer
      // already committed that key; replay, never mint again.
      let wallet: { readonly walletId: Uuid; readonly publicKey: WalletPublicKey };
      try {
        wallet = await keyGenerator.generate(request.nodeId, {
          idempotencyKey: request.idempotencyKey,
          label: request.label,
        });
      } catch (err) {
        if (!isDestinationIdempotencyKeyClaimed(err)) throw err;
        const winner = await store.findByIdempotencyKey(request.nodeId, request.idempotencyKey);
        if (winner === null) throw err;
        return { status: "already_registered", destination: winner };
      }
      const destination = await store.insert(
        {
          destinationId: ids.destinationId(),
          nodeId: request.nodeId,
          walletId: wallet.walletId,
          walletPublicKey: wallet.publicKey,
          label: request.label,
          createdAt: clock.now(),
        },
        request.idempotencyKey,
      );
      return { status: "created", destination };
    },

    async bless(request) {
      // Device signature is required on the wire (predicate 6 / A.4.2). Empty or
      // missing sig never reaches the authorizer and never mutates state — TOTP
      // alone cannot bless even if a future binder forgot to gate.
      if (typeof request.deviceSignature !== "string" || request.deviceSignature.length === 0) {
        return { status: "authorization_rejected", destinationId: request.destinationId };
      }
      if (typeof request.expiresAt !== "string" || request.expiresAt.length === 0) {
        return { status: "authorization_rejected", destinationId: request.destinationId };
      }
      if (typeof request.deviceKeyId !== "string" || request.deviceKeyId.length === 0) {
        return { status: "authorization_rejected", destinationId: request.destinationId };
      }

      const destination = await store.findById(request.destinationId);
      if (destination === null || destination.nodeId !== request.nodeId) {
        return { status: "not_found", destinationId: request.destinationId };
      }
      if (destination.state === "BLESSED") {
        return { status: "already_blessed", destination };
      }
      if (destination.state !== "PENDING") {
        return {
          status: "invalid_transition",
          destinationId: request.destinationId,
          from: destination.state,
        };
      }

      // Predicate 2 recheck: only a node-generated wallet may be blessed into custody.
      // Collapse to authorization_rejected so the wire does not confirm wallet existence
      // or key_origin (ZTR-1170 / dual-control opacity precedent in send/approve).
      const keyOrigin = await store.walletKeyOrigin(destination.walletId);
      if (keyOrigin !== "node_generated") {
        return { status: "authorization_rejected", destinationId: request.destinationId };
      }

      const authorized = await blessingAuthorizer.authorize({
        nodeId: request.nodeId,
        destinationId: request.destinationId,
        walletId: destination.walletId,
        walletPublicKey: destination.walletPublicKey,
        nonce: request.nonce,
        issuedAt: request.issuedAt,
        expiresAt: request.expiresAt,
        deviceSignature: request.deviceSignature,
        deviceKeyId: request.deviceKeyId,
      });
      if (authorized === null) {
        return { status: "authorization_rejected", destinationId: request.destinationId };
      }

      // PENDING → BLESSED is atomic. CAS loser re-reads and maps.
      const blessed = await store.bless(request.destinationId, {
        blessedAt: clock.now(),
        blessedByDeviceKeyId: authorized.deviceKeyId,
        blessingArtifactId: authorized.artifactId,
      });
      if (blessed === null) {
        const current = await store.findById(request.destinationId);
        if (current === null || current.nodeId !== request.nodeId) {
          return { status: "not_found", destinationId: request.destinationId };
        }
        if (current.state === "BLESSED") {
          return { status: "already_blessed", destination: current };
        }
        return {
          status: "invalid_transition",
          destinationId: request.destinationId,
          from: current.state,
        };
      }
      return { status: "blessed", destination: blessed };
    },

    async retire(request) {
      const destination = await store.findById(request.destinationId);
      if (destination === null || destination.nodeId !== request.nodeId) {
        return { status: "not_found", destinationId: request.destinationId };
      }
      if (destination.state === "RETIRED") {
        return { status: "already_retired", destination };
      }
      // Only a BLESSED destination can be retired; a PENDING destination was never
      // admitted to custody, and RETIRED is terminal.
      if (destination.state !== "BLESSED") {
        return {
          status: "invalid_transition",
          destinationId: request.destinationId,
          from: destination.state,
        };
      }

      const retired = await store.retire(request.destinationId, clock.now());
      return { status: "retired", destination: retired };
    },

    async list(nodeId, filter) {
      const page = await store.list(nodeId, { limit: DEFAULT_LIST_LIMIT, ...filter });
      const items: DestinationListItem[] = [];
      for (const row of page.items) {
        items.push(await withEligibility(store, row));
      }
      return { items, nextAfter: page.nextAfter };
    },

    async get(nodeId, destinationId) {
      const destination = await store.findById(destinationId);
      if (destination === null || destination.nodeId !== nodeId) {
        return null;
      }
      return withEligibility(store, destination);
    },
  };
}
