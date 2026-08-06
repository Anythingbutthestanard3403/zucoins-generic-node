// The RECEIVE_T0 read and the not-verified branch. Steps 1–2 (eligibility select +
// assignment DB-TX) are `assignReceiveWallet`; steps 5–8 (expiry, code, artifact,
// READY) are the code-formation path. This module is
// the seam between them and owns exactly one question: may this operation read this wallet, and
// what durable evidence does the read leave behind.
//
// Governing rules: one active lease per wallet, owned "before its first fresh gateway
// read"; the observation invariant (genesis is exact, INDETERMINATE is never an empty
// wallet); and the wallet_active_leases / operation_observation_bindings tables.
//
// Why the lease check is SQL and not an `await` ordering. already sequences the read
// after the assignment in-process (`assignReceiveWalletThenObserve`), and that is necessary but
// not sufficient: a second node instance, a resumed boot-recovery worker, or a retried formation
// can enter this function against a wallet whose lease has since moved. Application ordering
// inside one process says nothing about those. So both ends are database predicates —
// SELECT_HELD_RECEIVE_LEASE gates the read on a lease row that exists NOW, and BIND_RECEIVER_T0
// re-asserts the SAME row at the SAME `lease_epoch` inside the insert itself. A capture whose
// lease was released or re-acquired mid-read binds zero rows rather than binding a T0 the
// operation had no standing to take.
//
// The one-in-flight-per-wallet rule is not re-implemented here: `wallet_active_leases.wallet_id` is the PRIMARY KEY
// so "at most one active lease per wallet" is the database's. The key-custody rule holds
// trivially — the only key material touched is the leased wallet's PUBLIC key, and it is read
// out of the wallets row rather than accepted from the caller, so an operation can never observe
// a wallet other than the one it holds.
//
// Driver-agnostic, like every other receive module: the composition root injects the
// executor and the observation-service adapter.

import type { T0Projection } from "./arm-mutation.js";
import type { WalletStateProjection } from "../protocol/wallet-role.js";

/**
 * Narrow node-postgres-shaped surface, declared locally for the same reason pool-allocator.ts
 * and arm-sql.ts declare theirs: `receive` is a leaf in the node-core dependency map
 * (test/boundaries.test.ts) and may not reach into `data` or `observation`.
 */
export interface SqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[]; readonly rowCount?: number | null }>;
}

/** Step 3's observation role. One value; named so call sites read as the spec does. */
export const RECEIVE_T0_OBSERVATION_ROLE = "RECEIVE_T0" as const;

/** `operation_observation_bindings.evidence_role` this step writes. */
export const RECEIVE_T0_EVIDENCE_ROLE = "RECEIVER_T0" as const;

/**
 * "For a validated never-used node-generated wallet, S0="", P0="", and
 * B0="0". Empty strings are the canonical genesis projection; `null` means a projection was
 * unavailable and therefore cannot be armed or verified... Any response that cannot support an
 * unambiguous projection is INDETERMINATE; it must never be treated as an empty wallet or a zero
 * balance."
 *
 * INDETERMINATE is therefore its own variant rather than a projection carrying nulls — "treat
 * the ambiguous read as zero" is unrepresentable, not merely discouraged. Structurally identical
 * to core/move-baseline-binding.ts's `ObservationOutcome` so one composition-root adapter serves
 * both flows; duplicated rather than imported because of the module boundary above.
 */
export type ReceiveT0Observation =
  | {
      readonly kind: "VERIFIED";
      readonly observationId: string;
      readonly projection: WalletStateProjection;
    }
  | { readonly kind: "INDETERMINATE"; readonly detail: string }
  | { readonly kind: "UNVERIFIED"; readonly detail: string };

/**
 * The observation service. Never a gateway client: "No operation worker may call the
 * gateway client directly." The port takes the role so the service can tag the appended
 * observation, and returns the durable `observation_id` it wrote.
 */
export interface ReceiveT0Observer {
  observe(
    walletPublicKey: string,
    role: typeof RECEIVE_T0_OBSERVATION_ROLE,
  ): Promise<ReceiveT0Observation>;
}

/**
 * Canonical SQL for this step. Exported so tests and any in-process fake executor match the
 * exact strings — a silent predicate drift then fails loudly rather than quietly widening what
 * counts as "the lease is held".
 */
export const RECEIVE_T0_STATEMENTS = {
  /**
   * The pre-read gate. Returns a row only while this operation holds this wallet's
   * single `RECEIVE_WINDOW` lease; no row means no read happens at all.
   *
   * The wallet's public key is projected from the joined `wallets` row rather than taken as a
   * parameter. That is the whole point of routing the read through here: the pubkey observed and
   * the wallet leased are the same fact read from the same join, so no caller — including a
   * resumed recovery worker reconstructing state — can observe wallet A under wallet B's lease.
   *
   * `lease_epoch` is cast to text: it is `bigint` and would silently lose precision
   * through a JSON number.
   */
  SELECT_HELD_RECEIVE_LEASE: `
SELECT l.lease_epoch::text AS lease_epoch,
       l.lease_group_id::text AS lease_group_id,
       w.public_key AS wallet_public_key
  FROM wallet_active_leases l
  JOIN wallets w ON w.id = l.wallet_id
 WHERE l.wallet_id = $1
   AND l.operation_id = $2
   AND l.lease_role = 'RECEIVE_WINDOW'`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * T0 binding, fenced on the lease that authorised the read.
   *
   * INSERT ... SELECT, not INSERT ... VALUES: the lease predicate is evaluated by the same
   * statement that writes, so there is no window between checking the lease and binding the T0.
   * If the lease was released, expired or re-acquired at a higher epoch while the gateway read
   * was in flight, the SELECT yields nothing and zero rows are written — the caller learns the
   * capture is void instead of persisting evidence it no longer had standing to take.
   *
   * `wallet_public_key` likewise comes from the joined wallets row, so the bound key cannot
   * disagree with the leased wallet. PRIMARY KEY (operation_id, evidence_role) makes the write
   * exactly-once per operation: a retried formation cannot rebind a DIFFERENT head over the T0
   * the arm barrier will be compared against ("the node does not overwrite T0 in place").
   */
  BIND_RECEIVER_T0: `
INSERT INTO operation_observation_bindings
       (operation_id, observation_id, evidence_role, wallet_public_key)
SELECT l.operation_id, $3, 'RECEIVER_T0', w.public_key
  FROM wallet_active_leases l
  JOIN wallets w ON w.id = l.wallet_id
 WHERE l.wallet_id = $1
   AND l.operation_id = $2
   AND l.lease_role = 'RECEIVE_WINDOW'
   AND l.lease_epoch = $4
RETURNING observation_id::text AS observation_id`
    .replace(/\s+/g, " ")
    .trim(),

  /** The already-durable T0, read only on the conflict path so a resume is idempotent. */
  SELECT_BOUND_RECEIVER_T0: `
SELECT observation_id::text AS observation_id
  FROM operation_observation_bindings
 WHERE operation_id = $1
   AND evidence_role = 'RECEIVER_T0'`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Row 1's two durable facts, in one statement: does a receive-window lease exist, and
   * is a T0 bound under it. Counted rather than `EXISTS` so a second lease row — which
   * `wallet_active_leases`' PRIMARY KEY makes impossible and which would therefore mean the
   * schema itself has been tampered with — is visible rather than flattened to `true`.
   */
  COUNT_T0_PHASE_EVIDENCE: `
SELECT (SELECT count(*)::int
          FROM wallet_active_leases
         WHERE operation_id = $1
           AND lease_role = 'RECEIVE_WINDOW') AS lease_rows,
       (SELECT count(*)::int
          FROM operation_observation_bindings
         WHERE operation_id = $1
           AND evidence_role = 'RECEIVER_T0') AS t0_rows`
    .replace(/\s+/g, " ")
    .trim(),
} as const;

/**
 * Thrown when captureReceiveT0 is invoked without a money-admission port.
 * Fail-closed: omit never means admit.
 */
export class MoneyAdmissionPortMissingError extends Error {
  constructor() {
    super("captureReceiveT0 requires assertMoneyAdmitted (fail-closed)");
    this.name = "MoneyAdmissionPortMissingError";
  }
}

export interface CaptureReceiveT0Params {
  readonly operationId: string;
  /** The wallet step-2 transaction attached as operation role `RECEIVER`. */
  readonly walletId: string;
  readonly observer: ReceiveT0Observer;
  /**
   * Refuse NEW T0 capture when observation/DB/vault gating is closed.
   * Required. Composition injects assertNewMoneyWorkAdmitted via
   * createMoneyPathAdmissionPorts; pure lease/bind unit tests pass a no-op.
   */
  readonly assertMoneyAdmitted: () => void;
}

export type ReceiveT0Outcome =
  /** Step 3 complete: T0 durable, code construction (step 5) may begin. */
  | {
      readonly kind: "CAPTURED";
      readonly t0: T0Projection;
      readonly walletPublicKey: string;
      readonly leaseGroupId: string;
      readonly leaseEpoch: bigint;
    }
  /** Idempotent resume: this operation already has a durable T0; it is returned, never rewritten. */
  | { readonly kind: "ALREADY_CAPTURED"; readonly t0ObservationId: string }
  /** No lease at read time — the lease rule forbids the read, so none was issued. */
  | { readonly kind: "LEASE_NOT_HELD"; readonly detail: string }
  /** The lease moved while the read was in flight; the T0 is void and nothing was bound. */
  | { readonly kind: "LEASE_LOST"; readonly detail: string }
  /** Step 4 — not verified genesis/head. Do not construct a code; follow the expiry path. */
  | {
      readonly kind: "NOT_VERIFIED";
      readonly reason: "observation_indeterminate" | "observation_unverified";
      readonly detail: string;
    };

type HeldLeaseRow = {
  lease_epoch: string;
  lease_group_id: string;
  wallet_public_key: string;
};

const SQLSTATE_UNIQUE_VIOLATION = "23505";

function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === SQLSTATE_UNIQUE_VIOLATION;
}

/**
 * Steps 3–4.
 *
 * Returns `CAPTURED` only once `{S0,P0,B0}` is durable and provably taken under the lease that
 * still holds the wallet. Every other outcome is typed and terminal for this step: the caller
 * routes `NOT_VERIFIED` to the expiry / pre-ready-failure path and never falls through to
 * step 5. No outcome coerces an ambiguous read into a genesis or zero baseline — INDETERMINATE
 * cannot reach the projection branch at all.
 *
 * Not transactional by design. The gateway read sits between the two SQL statements, and holding
 * a transaction open across it would pin a lock for the duration of a network call; the epoch
 * fence in BIND_RECEIVER_T0 is what makes that safe, so the durable outcome is decided by the
 * database at bind time rather than by how long the read took.
 */
export async function captureReceiveT0(
  db: SqlExecutor,
  params: CaptureReceiveT0Params,
): Promise<ReceiveT0Outcome> {
  // No new leased operation advances past the T0-requiring point when
  // observation is not read-capable (or other gating readiness fails).
  // Required port — omit throws (fail-closed), never admits.
  if (typeof params.assertMoneyAdmitted !== "function") {
    throw new MoneyAdmissionPortMissingError();
  }
  params.assertMoneyAdmitted();

  const held = await db.query<HeldLeaseRow>(RECEIVE_T0_STATEMENTS.SELECT_HELD_RECEIVE_LEASE, [
    params.walletId,
    params.operationId,
  ]);
  const lease = held.rows[0];
  if (lease === undefined) {
    return {
      kind: "LEASE_NOT_HELD",
      detail: `operation ${params.operationId} holds no RECEIVE_WINDOW lease on wallet ${params.walletId}; no T0 read was issued`,
    };
  }

  const observation = await params.observer.observe(
    lease.wallet_public_key,
    RECEIVE_T0_OBSERVATION_ROLE,
  );
  if (observation.kind === "INDETERMINATE") {
    return {
      kind: "NOT_VERIFIED",
      reason: "observation_indeterminate",
      detail: observation.detail,
    };
  }
  if (observation.kind === "UNVERIFIED") {
    return { kind: "NOT_VERIFIED", reason: "observation_unverified", detail: observation.detail };
  }

  let bound;
  try {
    bound = await db.query<{ observation_id: string }>(RECEIVE_T0_STATEMENTS.BIND_RECEIVER_T0, [
      params.walletId,
      params.operationId,
      observation.observationId,
      lease.lease_epoch,
    ]);
  } catch (error) {
    if (isUniqueViolation(error)) {
      const existing = await db.query<{ observation_id: string }>(
        RECEIVE_T0_STATEMENTS.SELECT_BOUND_RECEIVER_T0,
        [params.operationId],
      );
      const durable = existing.rows[0]?.observation_id;
      // A unique violation with no RECEIVER_T0 row is the OTHER constraint —
      // UNIQUE (operation_id, observation_id), i.e. this observation is already bound under a
      // different role. That is a caller bug, not an idempotent resume, and reporting it as
      // ALREADY_CAPTURED would claim a durable T0 that does not exist.
      if (durable === undefined) throw error;
      return { kind: "ALREADY_CAPTURED", t0ObservationId: durable };
    }
    throw error;
  }
  if (bound.rows.length === 0) {
    return {
      kind: "LEASE_LOST",
      detail: `wallet ${params.walletId} is no longer leased to operation ${params.operationId} at epoch ${lease.lease_epoch}; T0 ${observation.observationId} was not bound`,
    };
  }

  return {
    kind: "CAPTURED",
    t0: {
      observationId: observation.observationId,
      s0: observation.projection.S,
      p0: observation.projection.P,
      b0: observation.projection.B,
    },
    walletPublicKey: lease.wallet_public_key,
    leaseGroupId: lease.lease_group_id,
    leaseEpoch: BigInt(lease.lease_epoch),
  };
}

/**
 * Row 1's durable-evidence half — the part this slice owns.
 *
 * `PROVEN_NOT_STARTED` here means "lease exists, no T0". The row's remaining conjuncts (no code,
 * no artifact preimage, no signer audit) live in tables; boot recovery ANDs them in.
 * That ordering is deliberate: a lease with no T0 is a safe resumable state, so a boot-recovery
 * worker calls `captureReceiveT0` again rather than treating the pinned-but-T0-less wallet as an
 * anomaly.
 */
export type ReceiveT0Phase = "NO_LEASE" | "PROVEN_NOT_STARTED" | "T0_DURABLE";

export async function classifyReceiveT0Phase(
  db: SqlExecutor,
  operationId: string,
): Promise<ReceiveT0Phase> {
  const evidence = await db.query<{ lease_rows: number; t0_rows: number }>(
    RECEIVE_T0_STATEMENTS.COUNT_T0_PHASE_EVIDENCE,
    [operationId],
  );
  const row = evidence.rows[0];
  if (Number(row?.t0_rows ?? 0) > 0) return "T0_DURABLE";
  if (Number(row?.lease_rows ?? 0) > 0) return "PROVEN_NOT_STARTED";
  return "NO_LEASE";
}
