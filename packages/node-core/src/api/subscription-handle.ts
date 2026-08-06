// subscription-handle auth class.
// Bearer `sh_…` authorizes lifecycle status for exactly one operation. Handles are
// stored hashed (SHA-256 hex of the utf-8 plaintext), expire shortly after terminal
// state, and never authorize raw bodies, T0, arm, or verification-complete.
//
// Failure posture (ticket AC + AUTH_CLASS_POLICY.SUBSCRIPTION_HANDLE):
// every credential / binding / expiry / absent-operation failure collapses to the
// same 401 invalid_api_key envelope. Cross-operation path mismatches are treated as
// credential failures (the handle does not authorize that path), not 404 oracles.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";

export const SUBSCRIPTION_HANDLE_PREFIX = "sh_" as const;
const BEARER_SCHEME = "bearer";

/** Default post-terminal remaining lifetime when an issuer does not supply one. */
export const DEFAULT_SUBSCRIPTION_HANDLE_POST_TERMINAL_TTL_MS = 15 * 60 * 1000;

/** Closed field list for GET /v1/operations/:operation_id/subscribe. */
export const OPERATION_LIFECYCLE_FIELD_KEYS = [
  "operation_id",
  "operation_type",
  "state",
  "row_version",
  "attention_required",
  "updated_at",
] as const;

export type OperationLifecycleFieldKey = (typeof OPERATION_LIFECYCLE_FIELD_KEYS)[number];

// The terminal-state vocabulary moved to protocol/ so workers/boot-recovery
// can share it — workers may import protocol but not api. Re-exported here unchanged so
// the public path is untouched.
export {
  NONTERMINAL_OPERATION_STATES,
  TERMINAL_OPERATION_STATES,
  isKnownOperationState,
  isTerminalOperationState,
  type NonterminalOperationState,
  type OperationState,
  type TerminalOperationState,
} from "../protocol/operation-states.js";

export interface OperationLifecycleRow {
  readonly operationId: string;
  readonly operationType: OperationKind;
  readonly state: string;
  readonly rowVersion: number;
  readonly attentionRequired: boolean;
  /** RFC3339 UTC timestamp of the last lifecycle mutation. */
  readonly updatedAt: string;
}

/** Durable handle binding — only the hash is ever persisted (schema: subscription_handles). */
export interface SubscriptionHandleRecord {
  readonly operationId: string;
  readonly handleHash: string;
  /** Absolute expiry instant (ms since epoch). After this, the handle never authorizes. */
  readonly expiresAtMs: number;
  /** Server-side implementer binding; never trusted from the client. */
  readonly implementerId: string;
  readonly nodeId: string;
}

export interface SubscriptionHandleStore {
  lookupByHandleHash(handleHash: string): Promise<SubscriptionHandleRecord | null>;
}

export interface OperationLifecycleStore {
  getLifecycle(operationId: string): Promise<OperationLifecycleRow | null>;
  /**
   * Notify listeners when this operation's lifecycle row advances. Concurrent
   * subscribers are permitted (implementer judgment — documented in handoff).
   */
  subscribe(
    operationId: string,
    listener: (row: OperationLifecycleRow) => void,
  ): () => void;
}

/** SHA-256 hex of the utf-8 plaintext. Plaintext is never logged or returned here. */
export function hashSubscriptionHandle(plaintext: string): string {
  return createHash("sha256").update(plaintext, "utf8").digest("hex");
}

export function mintSubscriptionHandlePlaintext(): string {
  return `${SUBSCRIPTION_HANDLE_PREFIX}${randomBytes(24).toString("base64url")}`;
}

/** Constant-time hex digest compare (both sides must be 64-char lowercase hex). */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}

/**
 * Extract `sh_…` from Authorization: Bearer. Returns null for absent / wrong scheme /
 * non-handle tokens (including `ik_…` implementer keys).
 */
export function extractSubscriptionHandle(
  headers: Readonly<Record<string, string | string[] | undefined>>,
): string | null {
  const rawHeader = headers["authorization"] ?? headers["Authorization"];
  if (rawHeader === undefined) return null;
  const raw = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
  if (raw === undefined) return null;
  const spaceIndex = raw.indexOf(" ");
  if (spaceIndex === -1) return null;
  const scheme = raw.slice(0, spaceIndex).toLowerCase();
  if (scheme !== BEARER_SCHEME) return null;
  const token = raw.slice(spaceIndex + 1).trim();
  if (token.length === 0 || token.includes(" ") || /\s/.test(token)) return null;
  if (!token.startsWith(SUBSCRIPTION_HANDLE_PREFIX)) return null;
  // Prefix alone is not a handle.
  if (token.length <= SUBSCRIPTION_HANDLE_PREFIX.length) return null;
  return token;
}

/** Explicit allowlist projection — never "rich object minus fields". */
export function projectOperationLifecycle(
  row: OperationLifecycleRow,
): Readonly<Record<OperationLifecycleFieldKey, string | number | boolean>> {
  return {
    operation_id: row.operationId,
    operation_type: row.operationType,
    state: row.state,
    row_version: row.rowVersion,
    attention_required: row.attentionRequired,
    updated_at: row.updatedAt,
  };
}

/** Byte-exact body. Key insertion sequence is the frozen field ordering. */
export function renderOperationLifecycleBody(row: OperationLifecycleRow): string {
  const projected = projectOperationLifecycle(row);
  // Explicit insertion ordering keeps the signed bytes exact.
  return JSON.stringify({
    operation_id: projected.operation_id,
    operation_type: projected.operation_type,
    state: projected.state,
    row_version: projected.row_version,
    attention_required: projected.attention_required,
    updated_at: projected.updated_at,
  });
}

export function assertLifecycleFieldAllowlist(body: unknown): body is Record<
  OperationLifecycleFieldKey,
  unknown
> {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return false;
  const keys = Object.keys(body).sort();
  const expected = [...OPERATION_LIFECYCLE_FIELD_KEYS].sort();
  if (keys.length !== expected.length) return false;
  for (let i = 0; i < expected.length; i += 1) {
    if (keys[i] !== expected[i]) return false;
  }
  return true;
}

export type SubscribeAuthorizeOutcome =
  | {
      readonly kind: "AUTHORIZED";
      readonly record: SubscriptionHandleRecord;
      readonly lifecycle: OperationLifecycleRow;
    }
  | { readonly kind: "DENIED"; readonly response: ApiErrorResponse };

/**
 * Resolve a subscribe request. Path `operationId` must equal the handle's bound
 * operation; implementer binding is enforced via the durable record, never a client field.
 *
 * All denial paths share one envelope builder so invalid / expired / wrong-op /
 * nonexistent collapse to byte-identical bodies for a fixed request_id.
 */
export async function authorizeOperationSubscribe(input: {
  readonly requestId: string;
  readonly pathOperationId: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly handleStore: SubscriptionHandleStore;
  readonly lifecycleStore: OperationLifecycleStore;
  readonly nowMs: () => number;
}): Promise<SubscribeAuthorizeOutcome> {
  const denied = (): SubscribeAuthorizeOutcome => ({
    kind: "DENIED",
    response: apiErrorResponse("invalid_api_key", input.requestId),
  });

  const plaintext = extractSubscriptionHandle(input.headers);
  if (plaintext === null) return denied();

  const handleHash = hashSubscriptionHandle(plaintext);
  let record: SubscriptionHandleRecord | null;
  try {
    record = await input.handleStore.lookupByHandleHash(handleHash);
  } catch {
    return denied();
  }
  if (record === null) return denied();

  // Binding: handle authorizes exactly one operation_id.
  if (record.operationId !== input.pathOperationId) return denied();

  // Expiry: post-terminal window (and any absolute cap set at mint).
  if (input.nowMs() >= record.expiresAtMs) return denied();

  let lifecycle: OperationLifecycleRow | null;
  try {
    lifecycle = await input.lifecycleStore.getLifecycle(record.operationId);
  } catch {
    return denied();
  }
  if (lifecycle === null) return denied();
  // Defense in depth: lifecycle row id must match the binding.
  if (lifecycle.operationId !== record.operationId) return denied();

  return { kind: "AUTHORIZED", record, lifecycle };
}
