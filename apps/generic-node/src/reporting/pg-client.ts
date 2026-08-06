// The minimal database seam the durable reporting store is written against. The store
// never imports pg directly; it takes an injected ReportingQueryClient so the money path is fully
// unit-testable with a fake (no socket). The production wiring (createPoolReportingClient) backs
// it with the pg Pool from ./db/client.js. Also carries the Postgres SQLSTATE mapping the burn
// transaction relies on to translate the frozen admission function's errors into store outcomes.

export type ReportingQueryFn = (
  text: string,
  params?: readonly unknown[],
) => Promise<readonly Record<string, unknown>[]>;

export type ReportingTransactionFn = <T>(
  body: (query: ReportingQueryFn) => Promise<T>,
) => Promise<T>;

// The single seam the durable store needs: plain (autocommit) queries for the read/peek/insert
// paths, and a short transaction runner for the atomic burn. The runner must surface the
// database error (with its SQLSTATE `code`) to the caller on failure and roll back.
export interface ReportingQueryClient {
  readonly query: ReportingQueryFn;
  readonly transact: ReportingTransactionFn;
}

const UNIQUE_VIOLATION = "23505";
const OBJECT_NOT_IN_PREREQUISITE_STATE = "55000";
const NO_DATA_FOUND = "P0002";

interface PgErrorShape {
  code?: unknown;
  message?: unknown;
  // node-postgres sets `constraint` to the violated constraint's name on integrity errors
  // (23xxx). The burn/completion outcome mapping discriminates a 23505 by this name — a
  // unique violation on the replay/idempotency guard is a benign outcome, one on any other
  // unique (the burn-sequence guard, reporting_nonce_id, child_record_id) is an integrity
  // failure that must surface — so the mapping can never read `code` alone.
  constraint?: unknown;
  cause?: unknown;
}

// drizzle-orm (>=0.44) wraps the driver error in DrizzleQueryError with the original pg error on
// `.cause`; walk that chain (bounded depth) so both a raw node-postgres error and a wrapped one
// are recognized — mirroring apps/node/src/db/pg-errors.ts.
function asPgError(err: unknown): PgErrorShape | null {
  let current: unknown = err;
  for (let depth = 0; current != null && depth < 5; depth += 1) {
    if (typeof current !== "object") return null;
    const candidate = current as PgErrorShape;
    if (typeof candidate.code === "string") return candidate;
    current = candidate.cause;
  }
  return null;
}

export function pgErrorCode(err: unknown): string | null {
  const code = asPgError(err)?.code;
  return typeof code === "string" ? code : null;
}

export function isUniqueViolation(err: unknown): boolean {
  return pgErrorCode(err) === UNIQUE_VIOLATION;
}

// The name of the violated constraint (walks the same DrizzleQueryError `.cause` chain as
// pgErrorCode). Null when the driver did not attach one, so a nameless 23505 fails closed
// (mapped as "not the benign guard" and surfaced) rather than being silently swallowed.
export function pgErrorConstraint(err: unknown): string | null {
  const constraint = asPgError(err)?.constraint;
  return typeof constraint === "string" ? constraint : null;
}

export function isAdmissionStateError(err: unknown): boolean {
  return pgErrorCode(err) === OBJECT_NOT_IN_PREREQUISITE_STATE;
}

export function isNoDataFound(err: unknown): boolean {
  return pgErrorCode(err) === NO_DATA_FOUND;
}

// The admission function raises ERRCODE 55000 with one of two messages; the store distinguishes
// HOLD (restore hold) from LIFECYCLE_RECHECK_FAILED (lifecycle/key/epoch/auth) by this text.
export function isRestoreHoldMessage(err: unknown): boolean {
  const shape = asPgError(err);
  return typeof shape?.message === "string" && shape.message.includes("restore hold");
}
