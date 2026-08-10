/**
 * Residual crash/replay proof harness — obligation records.
 *
 * The model-level harness proves recovery-logic exactness GIVEN durable-state fixtures;
 * everything it cannot prove is recorded here, split by what would discharge it: a real
 * database for the persistence obligations, real fault injection for the rest. Every
 * entry is phrased "not proven here; discharged where" — never "covered by" a model test.
 * These EXTEND the frozen SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS (transaction-material.
 * contract.ts) without duplicating its inventoried data-model negatives.
 */
import { CRASH_POINTS } from "../../generic-node-contracts/src/approval/crash-recovery.contract.ts";

export const CRASH_REPLAY_PERSISTENCE_OBLIGATIONS = [
  "crash axiom: the harness's model — commit atomicity, volatile-state loss, uncommitted-write discard (a kill inside DB-TX-N ≡ end of DB-TX-(N-1)) — is assumed, not proven here; discharged against a real database once the data-model operations DDL exists.",
  "live-Postgres CAS race: N concurrent single-statement UPDATE operations SET formation_state='SIGNING_CLAIMED' WHERE id=$1 AND formation_state='APPROVED_UNSIGNED' leaves exactly one committed winner (custody step 5; the test plan 'real database concurrency tests, not only mocked unit tests') — not proven here; discharged against a real database with real DDL, since no operations.sql artifact exists to parse here.",
  "concurrent sign-intent and partial insert negatives (duplicate operation_id, duplicate approval_id) on real DDL — not proven here; discharged against a real database by the already-inventoried mandatory DB tests 9/10/11 in SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS (cross-referenced, not duplicated).",
  "redelivery-counter UPDATE semantics under the byte-immutability enforcement (the signed-byte columns): the harness models the column-restricted regime only — not proven here; discharged against a real database by transaction-material-byte-immutability.pg.test.ts (pack slice transaction-material-byte-immutability.sql / ZTR-1138).",
  "production signer conformity to DETERMINISTIC_RESIGN (custody; RFC 8032 pure deterministic Ed25519, no hedged/randomized variant, fail-closed on violation) against the real vault-backed signer — not proven here; the harness demonstrates only the testkit signer's determinism; discharged against a real database when the custody signer lands.",
] as const;

export const CRASH_REPLAY_FAULT_INJECTION_OBLIGATIONS = [
  // Residual: the challenge-refresh and TOTP single-use Layer-1 services ship, but the
  // real-PostgreSQL concurrent drills against approval-stores.sql remain outstanding.
  // The CREATED CAS arbiter itself is discharged by
  // test/send-approval-race-pg.test.ts against real PostgreSQL.
  "challenge-refresh racing an in-flight approve under approval_challenges_one_issued_per_operation — the Layer-1 service and its in-memory UNIQUE mirror ship in src/send/approve.ts and approval-store.ts; real-PostgreSQL concurrent refresh is not proven here, and is discharged under real fault injection against approval-stores.sql.",
  "concurrent duplicate/replayed TOTP under operation_approvals_totp_single_use (an opaque factor failure) — the Layer-1 unique-claim arbiter and its replay tests already ship; real-PostgreSQL concurrent-approve is not proven here, and is discharged under real fault injection against approval-stores.sql.",
  "admin HTTP reject surface (CSRF + X-ZP-TOTP + idempotency wrapping POST /admin/v1/external-sends/:operation_id/reject) — not proven here; the guarded CREATED→REJECTED transition is src/send/decide.ts and is race-proven by test/send-approval-race-pg.test.ts; the transport factors are discharged under real fault injection with the shared guarded-mutation middleware.",
  `real SIGKILL injection at each of the four frozen crash points (${CRASH_POINTS.map((p) => p.point).join(",")}) against the real formation worker and real database, boot recovery, matrix-prescribed outcome per cell — not proven here; discharged under real fault injection against the three-operation engine, as SEND_EXTERNAL exit evidence.`,
  "delivery replay after process restart (the test plan mandatory matrix row) on the real delivery path — not proven here; discharged under real fault injection with the real worker and API.",
  "lease acquisition racing with crash recovery against the real wallet_active_leases lane — not proven here; the one-in-flight-per-wallet rule (one in-flight transaction per wallet) rides on that lease lane and is never claimed from this harness; discharged under real fault injection.",
  "'the node never calls submit and re-delivery never rebuilds bytes' on the real SEND_EXTERNAL delivery path — not proven here; discharged under real fault injection.",
  "signer-audit evidence completeness after a real kill — the APPROVAL_CONSUMED_NO_SIGN_INTENT guard's premise 'prove the signer was never called' is only as strong as the durability of the real signer's audit trail — not proven here; discharged under real fault injection.",
] as const;
