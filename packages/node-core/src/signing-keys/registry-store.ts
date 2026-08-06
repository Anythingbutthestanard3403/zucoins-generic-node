// the READ layer over the two signing-key registries, the half of the
// slice that makes the schema enforce something. src/schema/signing-key-registry.sql declares
// the tables; this module is the only sanctioned way the rest of the node asks them a question.
//
// (key inventory and separation — "the verifier checks both signature and expected purpose/key
// class") and rule 8 ("Purpose comparison occurs before signature verification and uses an
// exact literal; there is no fallback verifier that tries multiple purposes").
// Schema:. Decisions: custody claim boundary (v2 implementation open).
//
// Rule 8 is discharged structurally, not by convention:
// - every entry point takes ONE purpose, never a list, so no caller can express a fallback;
// - assertExactPurpose runs BEFORE the statement is issued, so an unrecognised purpose can
// never reach the database, let alone a verifier;
// - the comparison is exact literal equality — no trim, case-fold, or Unicode normalization;
// - the historical lookup is purpose-scoped too, so a key registered under NODE_IDENTITY can
// never be handed back to satisfy an EVENT_SIGNING question.
//
// These tables hold PUBLIC keys only. node_signing_keys.vault_secret_ref is an
// opaque uuid the node vault resolves; it is deliberately NOT in the projection below, because
// nothing that resolves a key for verification needs it. No private key material is selected,
// returned, or logged by this module.
//
// DRIVER-AGNOSTIC, like src/proof-body/sql-store.ts: node-core is network-contained
// and depends on no database driver. The pg Pool is injected at the composition root, which is
// the only layer that touches a socket.

// The narrow node-postgres-shaped query surface this store depends on. `pg.Pool` and
// `pg.PoolClient` both satisfy it structurally. Declared here rather than imported from
// proof-body/sql-store.ts on purpose: test/boundaries.test.ts holds every read/persist module in
// this package to zero internal imports, and borrowing a three-line structural port is not worth
// minting a permanent signing-keys -> proof-body layering edge in that registry.
export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

export const NODE_SIGNING_KEY_PURPOSES = ["NODE_IDENTITY", "EVENT_SIGNING"] as const;

export type NodeSigningKeyPurpose = (typeof NODE_SIGNING_KEY_PURPOSES)[number];

export class UnknownSigningKeyPurposeError extends Error {
  constructor(readonly presented: string) {
    super("unknown signing-key purpose");
    this.name = "UnknownSigningKeyPurposeError";
  }
}

/**
 * rule 8 — exact-literal purpose comparison, performed before anything else. Throws on
 * any value that is not byte-identical to one of the two admissible literals; the presented
 * value is carried on the error but never interpolated into a message or a statement.
 */
export function assertExactPurpose(presented: string): NodeSigningKeyPurpose {
  for (const purpose of NODE_SIGNING_KEY_PURPOSES) {
    if (presented === purpose) return purpose;
  }
  throw new UnknownSigningKeyPurposeError(presented);
}

// The exact column sequence selected from each table, kept as one constant so the projection
// and the row shape cannot drift apart. vault_secret_ref is excluded by design (see header).
export const NODE_SIGNING_KEY_COLUMNS = [
  "id",
  "node_id",
  "purpose",
  "public_key",
  "activated_at",
  "retired_at",
] as const;

export const REPORTING_KEY_COLUMNS = [
  "id",
  "node_id",
  "implementer_id",
  "public_key",
  "registered_at",
] as const;

const SIGNING_SELECT = NODE_SIGNING_KEY_COLUMNS.join(", ");
const REPORTING_SELECT = REPORTING_KEY_COLUMNS.join(", ");

// Statement catalogue. ACTIVE resolution carries the validity window; the historical lookups
// deliberately do not, so a retired key stays resolvable by its exact public key forever.
//
// The window is BOTH-SIDED — [activated_at, retired_at), the same half-open interval
// reporting/event-verifier.ts applies per event. does not bar a future activated_at, and
// time-bounded overlap rotation makes pre-registering a successor a plausible pattern,
// so a lower bound is load-bearing rather than defensive: without `activated_at <= now` a key
// that is not yet valid is reported as currently active and its signatures would be accepted
// before its window opens. Not-yet-active keys are excluded here for the same reason retired
// ones are, and stay retrievable by exact public key for the same reason too.
//
// No sort clause, deliberately. Each of these returns a SET, and during a rotation overlap
// every member of that set is equally admissible — ranking them would invite a caller to take
// the first row as "the" key and silently ignore the other live one. A caller that needs a
// stable presentation sequence sorts what it gets.
// RETAINED resolution deliberately drops the SELECT_ACTIVE_NODE_KEYS upper-bound
// clause `(retired_at IS NULL OR retired_at > now)`: node_signing_keys rows are never
// deleted (rotation only sets retired_at — see signing-keys/ensure.ts retireActiveRows; the
// schema's CHECK is retired_at >= activated_at, not a purge trigger), so retention is durable
// and unbounded. A signature produced under a since-retired key must stay independently
// verifiable, which is only possible if discovery keeps publishing that key's public half and
// validity interval ("key validity intervals"). The lower bound
// (`activated_at <= now`) is kept for the same reason SELECT_ACTIVE_NODE_KEYS keeps it: a
// pre-registered successor is not yet valid and must not be advertised early.
export const STATEMENTS = {
  SELECT_ACTIVE_NODE_KEYS: `SELECT ${SIGNING_SELECT} FROM node_signing_keys WHERE node_id = $1 AND purpose = $2 AND activated_at <= now() AND (retired_at IS NULL OR retired_at > now())`,
  SELECT_RETAINED_NODE_KEYS: `SELECT ${SIGNING_SELECT} FROM node_signing_keys WHERE node_id = $1 AND purpose = $2 AND activated_at <= now() ORDER BY activated_at ASC, id ASC`, // contract-allow:order:frozen structural vocabulary
  SELECT_NODE_KEY_BY_PUBLIC_KEY: `SELECT ${SIGNING_SELECT} FROM node_signing_keys WHERE node_id = $1 AND purpose = $2 AND public_key = $3`,
  SELECT_REPORTING_KEYS: `SELECT ${REPORTING_SELECT} FROM implementer_reporting_keys WHERE node_id = $1 AND implementer_id = $2`,
  SELECT_REPORTING_KEY_BY_PUBLIC_KEY: `SELECT ${REPORTING_SELECT} FROM implementer_reporting_keys WHERE node_id = $1 AND implementer_id = $2 AND public_key = $3`,
} as const;

// Rows as the driver returns them: timestamps as strings, retired_at nullable.
export interface NodeSigningKeyRow {
  readonly id: string;
  readonly node_id: string;
  readonly purpose: NodeSigningKeyPurpose;
  readonly public_key: string;
  readonly activated_at: string;
  readonly retired_at: string | null;
}

export interface ReportingKeyRow {
  readonly id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly public_key: string;
  readonly registered_at: string;
}

export class SigningKeyRegistry {
  constructor(private readonly sql: SqlExecutor) {}

  /**
   * Every key of exactly `purpose` currently inside its validity window for `nodeId`, as an
   * unranked set. Returns a list, not a single row: rotation deliberately overlaps a successor
   * with its predecessor until the predecessor is retired, and collapsing that to one row would
   * silently pick a winner. Empty when the node has no active key of that purpose — including
   * when it has an active key of the OTHER purpose.
   */
  async findActiveNodeSigningKeys(
    nodeId: string,
    purpose: string,
  ): Promise<readonly NodeSigningKeyRow[]> {
    const exact = assertExactPurpose(purpose);
    const { rows } = await this.sql.query<NodeSigningKeyRow>(STATEMENTS.SELECT_ACTIVE_NODE_KEYS, [
      nodeId,
      exact,
    ]);
    return rows;
  }

  /**
   * Every key of exactly `purpose` for `nodeId` that has reached its activation time — the
   * currently active key (if any) PLUS every retired predecessor, oldest first. Use this for
   * a published surface (e.g. discovery) that must let a caller verify a signature produced
   * before the most recent rotation; use findActiveNodeSigningKeys when only the live signer
   * is wanted. See the SELECT_RETAINED_NODE_KEYS comment for why retired rows are retained
   * without an upper time bound.
   */
  async findRetainedNodeSigningKeys(
    nodeId: string,
    purpose: string,
  ): Promise<readonly NodeSigningKeyRow[]> {
    const exact = assertExactPurpose(purpose);
    const { rows } = await this.sql.query<NodeSigningKeyRow>(
      STATEMENTS.SELECT_RETAINED_NODE_KEYS,
      [nodeId, exact],
    );
    return rows;
  }

  /**
   * Historical resolution: the (node, purpose, public key) row whether or not it is retired
   * the UNIQUE on those three columns makes it at most one. Still purpose-scoped, so this is a
   * lookup of a known key's record, never a way to reach a key of the wrong class.
   */
  async findNodeSigningKey(
    nodeId: string,
    purpose: string,
    publicKey: string,
  ): Promise<NodeSigningKeyRow | null> {
    const exact = assertExactPurpose(purpose);
    const { rows } = await this.sql.query<NodeSigningKeyRow>(
      STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY,
      [nodeId, exact, publicKey],
    );
    return rows[0] ?? null;
  }

  /**
   * The reporting keys enrolled for one (node, implementer), as an unranked set.
   * gives implementer_reporting_keys no activated_at/retired_at — reporting-key lifecycle
   * (epochs, revocation, overlap) lives in the separate lifecycle tables consumed by
   * src/reporting/store.ts, NOT in this registry — so every enrolled row is returned and no
   * validity window is applied or implied here.
   */
  async findReportingKeys(
    nodeId: string,
    implementerId: string,
  ): Promise<readonly ReportingKeyRow[]> {
    const { rows } = await this.sql.query<ReportingKeyRow>(STATEMENTS.SELECT_REPORTING_KEYS, [
      nodeId,
      implementerId,
    ]);
    return rows;
  }

  /** The (node, implementer, public key) enrolment row, or null. UNIQUE on those three. */
  async findReportingKey(
    nodeId: string,
    implementerId: string,
    publicKey: string,
  ): Promise<ReportingKeyRow | null> {
    const { rows } = await this.sql.query<ReportingKeyRow>(
      STATEMENTS.SELECT_REPORTING_KEY_BY_PUBLIC_KEY,
      [nodeId, implementerId, publicKey],
    );
    return rows[0] ?? null;
  }
}
