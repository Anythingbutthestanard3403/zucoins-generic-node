// verification-material access-window RECORD.
//
// The endpoint answers 409 while material is not yet ready and 410 once the window has
// expired. The window opens at the landed terminal and runs for 30 days; expiry revokes
// endpoint access only, never the retained evidence. The record follows the same shape as
// approval_challenges: issued_at / expires_at / status / unique nonce.
//
// This is NOT a second bearer-token auth scheme. Auth for the endpoint remains the
// signed reporting credential. This module owns the *availability
// window* that opens at the landed-terminal milestone and closes after the configured
// window — the additional per-operation gate on top of reporting auth.
//
// Identifiers are stored hashed (SHA-256 of a random nonce). Plaintext never reaches
// durable storage, logs, or audit details (ticket AC).
//
// Every successful or denied *read decision* that consults the window can emit an
// audit_log entry via the optional AuditWriter (actor_kind=IMPLEMENTER for
// reporting-key reads). details never carry raw evidence bytes — only the fact and
// scope of the read.

import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  decideProofAccess,
  isLandedTerminalStatus,
  resolveVerificationMaterialAccess,
  verificationMaterialAvailableUntilMs,
  type ProofAccessVerdict,
  type VerificationMaterialAccess,
} from "../core/index.js";
import type { AuditWriter } from "../core/audit-writer.js";
import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

// --- Closed vocabularies ----------------------------------------------------------------

export const VERIFICATION_ACCESS_WINDOW_STATUSES = ["OPEN", "EXPIRED", "REVOKED"] as const;
export type VerificationAccessWindowStatus = (typeof VERIFICATION_ACCESS_WINDOW_STATUSES)[number];

/** Audit action for a verification-material access-window read decision. */
export const VERIFICATION_MATERIAL_READ_AUDIT_ACTION =
  "verification_material.access_read" as const;

// --- Record shape (mirrors approval_challenges) -----------------------------------------

/**
 * Durable access-window record. `nonceHash` is SHA-256 hex of the random nonce
 * the plaintext nonce is never part of this structure and never persists.
 */
export interface VerificationAccessWindowRecord {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly status: VerificationAccessWindowStatus;
  /** SHA-256 hex of the random nonce. Plaintext is never stored. */
  readonly nonceHash: string;
  /** Millisecond epoch of the landed-terminal milestone that opened the window. */
  readonly issuedAtMs: number;
  /** Millisecond epoch at which endpoint access lapses (issuedAt + window). */
  readonly expiresAtMs: number;
  /** Millisecond epoch of explicit revoke, or null while not REVOKED. */
  readonly revokedAtMs: number | null;
}

export interface VerificationAccessWindowStore {
  /** Insert a newly issued window. Rejects duplicate operation_id / nonce_hash. */
  save(record: VerificationAccessWindowRecord): Promise<void>;
  /** Lookup by operation + implementer (tenant). Cross-tenant returns null (no-oracle). */
  findByOperation(
    operationId: string,
    implementerId: string,
  ): Promise<VerificationAccessWindowRecord | null>;
  /** Lookup by hashed nonce (for identifier-based resolve). */
  findByNonceHash(nonceHash: string): Promise<VerificationAccessWindowRecord | null>;
  /**
   * Persist a status transition (OPEN → REVOKED / EXPIRED). Never deletes.
   * Returns false when the row is absent.
   */
  updateStatus(
    operationId: string,
    status: VerificationAccessWindowStatus,
    revokedAtMs: number | null,
  ): Promise<boolean>;
}

// --- Hashing ----------------------------------------------------------------------------

/** SHA-256 hex of the utf-8 plaintext. Plaintext is never logged or returned from store APIs. */
export function hashAccessWindowNonce(plaintext: string): string {
  return createHash("sha256").update(plaintext, "utf8").digest("hex");
}

/** Mint a random 32-byte base64url nonce. Caller must hash before any durable write. */
export function mintAccessWindowNoncePlaintext(): string {
  return randomBytes(32).toString("base64url");
}

// --- In-memory store (reference adapter) ------------------------------------------------

/**
 * Single-process reference adapter. Keys the durable map by nonce_hash (never plaintext)
 * and by operation_id. Atomicity: status updates contain no await between read and write.
 */
export class InMemoryVerificationAccessWindowStore implements VerificationAccessWindowStore {
  private readonly byNonceHash = new Map<string, VerificationAccessWindowRecord>();
  private readonly byOperationId = new Map<string, string>(); // operationId → nonceHash

  async save(record: VerificationAccessWindowRecord): Promise<void> {
    if (this.byNonceHash.has(record.nonceHash)) {
      throw new VerificationAccessWindowError(
        `duplicate nonce_hash "${record.nonceHash.slice(0, 8)}…"`,
      );
    }
    if (this.byOperationId.has(record.operationId)) {
      throw new VerificationAccessWindowError(
        `duplicate operation_id "${record.operationId}"`,
      );
    }
    // Store under the HASH key only — plaintext never enters the map.
    this.byNonceHash.set(record.nonceHash, record);
    this.byOperationId.set(record.operationId, record.nonceHash);
  }

  async findByOperation(
    operationId: string,
    implementerId: string,
  ): Promise<VerificationAccessWindowRecord | null> {
    const hash = this.byOperationId.get(operationId);
    if (hash === undefined) return null;
    const record = this.byNonceHash.get(hash) ?? null;
    if (record === null) return null;
    // Tenant predicate: cross-tenant collapses to absent (no-oracle).
    if (record.implementerId !== implementerId) return null;
    return record;
  }

  async findByNonceHash(nonceHash: string): Promise<VerificationAccessWindowRecord | null> {
    return this.byNonceHash.get(nonceHash) ?? null;
  }

  async updateStatus(
    operationId: string,
    status: VerificationAccessWindowStatus,
    revokedAtMs: number | null,
  ): Promise<boolean> {
    const hash = this.byOperationId.get(operationId);
    if (hash === undefined) return false;
    const current = this.byNonceHash.get(hash);
    if (current === undefined) return false;
    const next: VerificationAccessWindowRecord = {
      id: current.id,
      nodeId: current.nodeId,
      implementerId: current.implementerId,
      operationId: current.operationId,
      status,
      nonceHash: current.nonceHash,
      issuedAtMs: current.issuedAtMs,
      expiresAtMs: current.expiresAtMs,
      revokedAtMs,
    };
    this.byNonceHash.set(hash, next);
    return true;
  }

  /** Test/inspection helper: every durable row, keyed only by hash. */
  rows(): readonly VerificationAccessWindowRecord[] {
    return [...this.byNonceHash.values()];
  }

  /**
   * Test helper: prove a specific plaintext was never used as a map key and never
   * appears inside any stored field value.
   */
  containsPlaintext(plaintext: string): boolean {
    if (this.byNonceHash.has(plaintext)) return true;
    if (this.byOperationId.has(plaintext)) return true;
    for (const record of this.byNonceHash.values()) {
      const blob = JSON.stringify(record);
      if (blob.includes(plaintext)) return true;
    }
    return false;
  }
}

export class VerificationAccessWindowError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationAccessWindowError";
  }
}

// --- Issue (terminal milestone only) ----------------------------------------------------

export interface IssueAccessWindowRequest {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly kind: OperationKind;
  /** Current Layer-1 status. Window opens ONLY at the kind's landed terminal. */
  readonly status: string;
  /** Millisecond epoch of the landed terminal (operations.terminal_at). */
  readonly terminalAtMs: number;
  /** Access window duration; defaults to 30 days. */
  readonly windowMs?: number;
  /** Optional pre-generated id (tests); otherwise a random UUID. */
  readonly id?: string;
  /** Optional pre-minted plaintext nonce (tests); otherwise random 32 bytes. */
  readonly noncePlaintext?: string;
}

export interface IssuedAccessWindow {
  readonly record: VerificationAccessWindowRecord;
  /**
   * Plaintext nonce, returned ONCE at issue for callers that need an out-of-band
   * correlation id. NEVER persisted. Prefer discarding immediately — the gate
   * itself resolves by (operationId, implementerId), not by presenting this value.
   */
  readonly noncePlaintext: string;
}

/**
 * Issue the access-window record at a landed-terminal milestone.
 * Throws when the operation is not at its kind's landed terminal (caller should
 * surface 409 via the read path, not issue a window early).
 */
export async function issueVerificationAccessWindow(
  store: VerificationAccessWindowStore,
  request: IssueAccessWindowRequest,
): Promise<IssuedAccessWindow> {
  if (!isLandedTerminalStatus(request.kind, request.status)) {
    throw new VerificationAccessWindowError(
      `refusing to issue access window before landed terminal (kind=${request.kind} status=${request.status})`,
    );
  }
  if (!Number.isFinite(request.terminalAtMs)) {
    throw new VerificationAccessWindowError("terminalAtMs must be a finite millisecond epoch");
  }
  const windowMs = request.windowMs ?? DEFAULT_PROOF_ACCESS_WINDOW_MS;
  const expiresAtMs = verificationMaterialAvailableUntilMs(request.terminalAtMs, windowMs);
  if (!(expiresAtMs > request.terminalAtMs)) {
    // verificationMaterialAvailableUntilMs allows windowMs=0 (expires==issued); the
    // durable CHECK requires expires_at > issued_at, so refuse a zero/negative window.
    throw new VerificationAccessWindowError("window must yield expires_at strictly after issued_at");
  }

  const noncePlaintext = request.noncePlaintext ?? mintAccessWindowNoncePlaintext();
  const nonceHash = hashAccessWindowNonce(noncePlaintext);
  const record: VerificationAccessWindowRecord = {
    id: request.id ?? randomUUID(),
    nodeId: request.nodeId,
    implementerId: request.implementerId,
    operationId: request.operationId,
    status: "OPEN",
    nonceHash,
    issuedAtMs: request.terminalAtMs,
    expiresAtMs,
    revokedAtMs: null,
  };
  await store.save(record);
  return { record, noncePlaintext };
}

// --- Authorize / gate -------------------------------------------------------------------

export type AccessWindowDecisionReason =
  | "not_ready" // no window row yet (pre-terminal) → 409
  | "expired" // past expires_at or status EXPIRED → 410
  | "revoked" // explicit REVOKED → 410 (access revoked, evidence retained)
  | "accessible";

export interface AccessWindowDecision {
  readonly reason: AccessWindowDecisionReason;
  readonly verdict: ProofAccessVerdict;
  readonly http: 200 | 409 | 410;
  readonly code: string | null;
  readonly record: VerificationAccessWindowRecord | null;
}

export interface AuthorizeAccessWindowInput {
  readonly operationId: string;
  readonly implementerId: string;
  readonly kind: OperationKind;
  readonly status: string;
  readonly nowMs: number;
  /**
   * When the operations row already carries verification_material_available_until,
   * pass it so the pure gate and the window record stay aligned. When omitted, the
   * window record's expiresAtMs is used.
   */
  readonly verificationMaterialAvailableUntilMs?: number | null;
}

/**
 * Resolve the access-window gate for one operation. Pure over the store snapshot:
 * never deletes, never mutates evidence. Cross-tenant / unknown → not_ready-shaped
 * absence is the caller's 404 job (tenant source collapses first); this function
 * only sees rows the store already tenant-filtered.
 */
export async function authorizeVerificationAccessWindow(
  store: VerificationAccessWindowStore,
  input: AuthorizeAccessWindowInput,
): Promise<AccessWindowDecision> {
  const record = await store.findByOperation(input.operationId, input.implementerId);

  // No window yet: material is not ready. Prefer the pure gate's status check so a
  // stray window cannot open access pre-terminal either (defence in depth).
  if (record === null) {
    const access = resolveFromOperation(input, null);
    return {
      reason: "not_ready",
      verdict: access.verdict,
      http: access.http,
      code: access.code,
      record: null,
    };
  }

  // Explicit revoke always denies (410), regardless of clock.
  if (record.status === "REVOKED") {
    return {
      reason: "revoked",
      verdict: "EXPIRED",
      http: 410,
      code: "verification_material_expired",
      record,
    };
  }

  // Status already marked EXPIRED, or clock past expires_at.
  const untilMs =
    input.verificationMaterialAvailableUntilMs !== undefined
      ? input.verificationMaterialAvailableUntilMs
      : record.expiresAtMs;
  const access = resolveFromOperation(input, untilMs);

  if (record.status === "EXPIRED" || access.verdict === "EXPIRED") {
    return {
      reason: "expired",
      verdict: "EXPIRED",
      http: 410,
      code: "verification_material_expired",
      record,
    };
  }

  if (access.verdict === "NOT_READY") {
    return {
      reason: "not_ready",
      verdict: "NOT_READY",
      http: 409,
      code: "verification_material_not_ready",
      record,
    };
  }

  return {
    reason: "accessible",
    verdict: "ACCESSIBLE",
    http: 200,
    code: null,
    record,
  };
}

function resolveFromOperation(
  input: AuthorizeAccessWindowInput,
  untilMs: number | null,
): VerificationMaterialAccess {
  return resolveVerificationMaterialAccess({
    kind: input.kind,
    status: input.status,
    verificationMaterialAvailableUntilMs: untilMs,
    nowMs: input.nowMs,
  });
}

// --- Revoke (access only — never deletes) -----------------------------------------------

/** Explicitly revoke endpoint access. Underlying evidence is untouched. */
export async function revokeVerificationAccessWindow(
  store: VerificationAccessWindowStore,
  operationId: string,
  nowMs: number,
): Promise<boolean> {
  return store.updateStatus(operationId, "REVOKED", nowMs);
}

/** Mark the window EXPIRED after the clock passes expires_at. Never deletes. */
export async function markVerificationAccessWindowExpired(
  store: VerificationAccessWindowStore,
  operationId: string,
): Promise<boolean> {
  return store.updateStatus(operationId, "EXPIRED", null);
}

// --- Read audit -------------------------------------------------------------------------

export interface AccessReadAuditInput {
  readonly audit: AuditWriter;
  readonly auditId: string;
  readonly nodeId: string;
  readonly actorId: string | null;
  readonly operationId: string;
  readonly decision: AccessWindowDecision;
  readonly createdAt: string;
}

/**
 * Append one audit_log row for a verification-material access-window read.
 * actor_kind is always IMPLEMENTER (reporting-key reads). details carry only the
 * fact and scope of the read — never raw evidence bytes, never the plaintext nonce.
 */
export async function auditVerificationMaterialAccessRead(
  input: AccessReadAuditInput,
): Promise<void> {
  const details = {
    scope: "verification-material:read",
    decision: input.decision.reason,
    verdict: input.decision.verdict,
    http: input.decision.http,
    // Window identity by hash only — never the plaintext nonce.
    window_id: input.decision.record?.id ?? null,
    nonce_hash: input.decision.record?.nonceHash ?? null,
    window_status: input.decision.record?.status ?? null,
  };
  await input.audit.write({
    id: input.auditId,
    nodeId: input.nodeId,
    actorKind: "IMPLEMENTER",
    actorId: input.actorId,
    action: VERIFICATION_MATERIAL_READ_AUDIT_ACTION,
    operationId: input.operationId,
    details,
    createdAt: input.createdAt,
  });
}

// --- Convenience: decide + audit in one step --------------------------------------------

export interface GatedAccessReadInput extends AuthorizeAccessWindowInput {
  readonly store: VerificationAccessWindowStore;
  readonly audit?: AuditWriter;
  readonly auditId?: string;
  readonly nodeId?: string;
  readonly actorId?: string | null;
  readonly createdAt?: string;
}

/**
 * Authorize the access window and optionally audit the read decision.
 * Returns the decision; never returns evidence bytes (those stay with).
 */
export async function gatedVerificationAccessRead(
  input: GatedAccessReadInput,
): Promise<AccessWindowDecision> {
  const decision = await authorizeVerificationAccessWindow(input.store, input);
  if (input.audit !== undefined) {
    if (
      input.auditId === undefined ||
      input.nodeId === undefined ||
      input.createdAt === undefined
    ) {
      throw new VerificationAccessWindowError(
        "auditId, nodeId, and createdAt are required when audit is supplied",
      );
    }
    await auditVerificationMaterialAccessRead({
      audit: input.audit,
      auditId: input.auditId,
      nodeId: input.nodeId,
      actorId: input.actorId ?? null,
      operationId: input.operationId,
      decision,
      createdAt: input.createdAt,
    });
  }
  return decision;
}

// Re-export the pure gate primitives so consumers of this module need not import
// retention separately for the same 409/200/410 vocabulary.
export {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  decideProofAccess,
  isLandedTerminalStatus,
  resolveVerificationMaterialAccess,
  verificationMaterialAvailableUntilMs,
  type ProofAccessVerdict,
  type VerificationMaterialAccess,
};
