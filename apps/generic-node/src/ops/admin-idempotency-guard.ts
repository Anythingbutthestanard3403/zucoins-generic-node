// Shared Idempotency-Key enforcement for every REQUIRED admin POST mutation
// (ROUTE_POLICIES idempotency: "REQUIRED"). Factored out of
// the api-keys-issue inline logic so every REQUIRED route (approve, reject, bless,
// retire, halt, api-keys issue/revoke) enforces the identical check-before/record-after
// sequence instead of re-deriving it per call site.
//
// Sequence: validate key format -> look up a completed row -> matching fingerprint replays
// the frozen bytes; a mismatched fingerprint is a 409 conflict; a miss proceeds to the
// mutation. The caller records the completed row (recordAdminIdempotency) only after its own
// TOTP/nonce burn and mutation succeed — this function never burns anything itself, so the
// check always runs strictly before TOTP/nonce burn.

import {
  sha256HexUtf8,
  type AdminIdempotencyFingerprint,
  type AdminIdempotencyStore,
} from "./admin-idempotency.js";

const IDEMPOTENCY_KEY_RE = /^[!-~]{16,255}$/;

/** UNIQUE(node_id, route_id, idempotency_key) violation — the only error `recordAdminIdempotency`
 * may treat as a race rather than a system failure. Anything else (connection drop, syntax
 * error, deadlock) must propagate so the caller never mistakes "the DB is broken" for "a
 * concurrent identical request already completed". */
export function isAdminIdempotencyUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code: unknown }).code === "23505"
  );
}

export type AdminIdempotencyCheckResult =
  | { readonly outcome: "missing_key" }
  | {
      readonly outcome: "proceed";
      readonly idemKey: string;
      readonly fingerprint: AdminIdempotencyFingerprint;
    }
  | { readonly outcome: "replay"; readonly status: number; readonly bodyBytes: Buffer }
  | { readonly outcome: "conflict" };

/**
 * Structural body fingerprint for routes whose request body carries secrets that
 * MUST NOT be hashed into durable idempotency rows (the no-key-hash rule — no hash-of-master-key
 * oracle). The sentinel is constant per route label; replay identity is then the
 * Idempotency-Key (+ method/target), never a digest of the key-bearing body.
 */
export function structuralBodyFingerprint(routeLabel: string): string {
  return sha256HexUtf8(`zupayments:admin-idempotency:structural:${routeLabel}`);
}

/** Ceremony start body fingerprint — never derived from the master-key POST body. */
export const RECOVERY_CEREMONY_START_BODY_FINGERPRINT = structuralBodyFingerprint(
  "admin_recovery_ceremony_start",
);

export async function checkAdminIdempotency(input: {
  readonly store: AdminIdempotencyStore | undefined;
  readonly nodeId: string;
  readonly routeId: string;
  readonly idemKeyHeader: string | undefined;
  readonly method: string;
  readonly rawTarget: string;
  readonly rawBody: Uint8Array;
  /**
   * When set, used as fingerprint.bodySha256 instead of sha256(rawBody).
   * Required for key-bearing routes: never hash a body that contains
   * vault_master_key / archive_epoch_master_key.
   */
  readonly bodySha256?: string;
}): Promise<AdminIdempotencyCheckResult> {
  const idemKey = input.idemKeyHeader;
  if (idemKey === undefined || !IDEMPOTENCY_KEY_RE.test(idemKey)) {
    return { outcome: "missing_key" };
  }
  const fingerprint: AdminIdempotencyFingerprint = {
    method: input.method,
    rawTarget: input.rawTarget,
    bodySha256:
      input.bodySha256 ??
      sha256HexUtf8(Buffer.from(input.rawBody).toString("utf8")),
  };
  if (input.store === undefined) {
    // Test-only unwired posture (matches the rest of AdminRouteDeps's optional-dep fallbacks).
    return { outcome: "proceed", idemKey, fingerprint };
  }
  const completed = await input.store.findCompleted(input.nodeId, input.routeId, idemKey);
  if (completed === null) {
    return { outcome: "proceed", idemKey, fingerprint };
  }
  const sameRequest =
    completed.fingerprint.method === fingerprint.method &&
    completed.fingerprint.rawTarget === fingerprint.rawTarget &&
    completed.fingerprint.bodySha256 === fingerprint.bodySha256;
  if (sameRequest) {
    return { outcome: "replay", status: completed.responseStatus, bodyBytes: completed.responseBytes };
  }
  return { outcome: "conflict" };
}

export type RecordAdminIdempotencyResult =
  | { readonly outcome: "recorded"; readonly responseBytes: Buffer }
  /** A concurrent identical request (same key, same fingerprint) won the race and committed
   * first. The loser replays the winner's exact bytes — it never re-runs its own effect. */
  | { readonly outcome: "replay_winner"; readonly responseStatus: number; readonly responseBytes: Buffer }
  /** A concurrent request reused the key with a *different* fingerprint. */
  | { readonly outcome: "conflict" };

/**
 * Records the completed row after a successful mutation. Only a genuine UNIQUE
 * (node_id, route_id, idempotency_key) violation (pg 23505) is a race outcome — resolved by
 * re-reading the winner's row and comparing fingerprints (replay on match, conflict on
 * mismatch). Any other error (connection loss, constraint violation elsewhere, etc.) is
 * rethrown: it is a system failure, never miscast as an idempotency conflict, so the caller's
 * own transaction handling (see ops/atomic-admin-mutation.ts) can roll back the child effect
 * instead of leaving it orphaned.
 */
export async function recordAdminIdempotency(input: {
  readonly store: AdminIdempotencyStore | undefined;
  readonly nodeId: string;
  readonly routeId: string;
  readonly idemKey: string;
  readonly fingerprint: AdminIdempotencyFingerprint;
  readonly responseStatus: number;
  readonly responseBody: unknown;
}): Promise<RecordAdminIdempotencyResult> {
  const responseBytes = Buffer.from(JSON.stringify(input.responseBody), "utf8");
  if (input.store === undefined) {
    return { outcome: "recorded", responseBytes };
  }
  try {
    await input.store.recordCompleted({
      nodeId: input.nodeId,
      routeId: input.routeId,
      idempotencyKey: input.idemKey,
      fingerprint: input.fingerprint,
      responseStatus: input.responseStatus,
      responseBytes,
    });
    return { outcome: "recorded", responseBytes };
  } catch (err) {
    if (!isAdminIdempotencyUniqueViolation(err)) {
      throw err;
    }
    const winner = await input.store.findCompleted(input.nodeId, input.routeId, input.idemKey);
    if (winner === null) {
      // Unreachable in practice: a 23505 on this exact key means a completed row exists.
      // Fail closed rather than silently proceed as if nothing raced.
      return { outcome: "conflict" };
    }
    const sameRequest =
      winner.fingerprint.method === input.fingerprint.method &&
      winner.fingerprint.rawTarget === input.fingerprint.rawTarget &&
      winner.fingerprint.bodySha256 === input.fingerprint.bodySha256;
    if (sameRequest) {
      return {
        outcome: "replay_winner",
        responseStatus: winner.responseStatus,
        responseBytes: winner.responseBytes,
      };
    }
    return { outcome: "conflict" };
  }
}
