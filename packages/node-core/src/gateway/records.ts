// Transport-evidence row shapes and recorder seams for the two append-only
// submit-attempt and observation ledgers. These are the transport layer's view of
// the evidence it must land — the full tables (parse_result, relationship, lineage
// proofs) belong to the observation-verification lanes; here each exchange contributes
// exactly its fingerprinted endpoint identity and its raw bytes + digests.
//
// Persistence is injected (ObservationRecorder / SubmitAttemptRecorder) so the
// primitives stay database-free and network-contained under test; the schema phase
// executes src/schema/submit-attempts.sql and observation-ledger.sql and
// supplies real recorders. Recorder failures propagate (fail-closed): evidence that
// cannot be persisted aborts the operation rather than silently vanishing.

// gateway_submit_attempts.transport_outcome — the closed set of transport-level
// outcomes for the single submit attempt. ACK is receipt-only (receipt-only ACK posture / C-09: a
// status:true acknowledgement is NEVER settlement — landing requires a fresh
// signature-verified chain observation via the landing-path oracle landing oracle). INDETERMINATE is
// reconcile-only: no re-attempt, no rebuild, no assumed failure (the never-blind-retry rule).
export const SUBMIT_TRANSPORT_OUTCOMES = ["ACK", "REJECT", "INDETERMINATE"] as const;

export type SubmitTransportOutcome = (typeof SUBMIT_TRANSPORT_OUTCOMES)[number];

// One gateway_observations contribution: the endpoint fingerprint copied at
// read time (so later reconfiguration cannot rewrite evidence provenance) plus the raw
// response bytes and their SHA-256, captured before any parse. A transport-ambiguous
// attempt (no complete response obtained) still lands a row — httpStatus / raw bytes /
// digest are null and transportAmbiguous marks it — because the attempt itself is
// evidence (every non-verified result is permanent).
export interface GatewayObservationRecord {
  readonly endpointFingerprint: string;
  readonly observedAt: string;
  readonly httpStatus: number | null;
  readonly rawResponseBytes: Uint8Array | null;
  readonly rawResponseSha256: string | null;
  readonly transportAmbiguous: boolean;
}

export interface ObservationRecorder {
  recordObservation(record: GatewayObservationRecord): Promise<void>;
}

// One gateway_submit_attempts row: at most one row per authorized
// submit_decision_id — decision_id is UNIQUE, and the UNIQUE (operation_id, attempt_no)
// and UNIQUE (operation_id, transaction_attempt_no) constraints make a second row for
// the same decision/transaction attempt a database violation. That stops a second ROW
// when the single shot is re-invoked, not a second POST — the transport is re-callable,
// and one in-flight tx per wallet chain-side dedup is the re-invocation backstop for the POST itself. Request
// bytes + digest are always present (the exact bytes POSTed); response bytes + digest
// are null exactly when no complete response was captured
// (CHECK ((response_body IS NULL) = (response_sha256 IS NULL))).
export interface GatewaySubmitAttemptRecord {
  readonly decisionId: string;
  readonly operationId: string;
  readonly attemptNo: number;
  readonly transactionAttemptNo: number;
  readonly requestBytes: Uint8Array;
  readonly requestSha256: string;
  readonly responseBytes: Uint8Array | null;
  readonly responseSha256: string | null;
  readonly transportOutcome: SubmitTransportOutcome;
  readonly startedAt: string;
  readonly completedAt: string | null;
}

export interface SubmitAttemptRecorder {
  recordSubmitAttempt(record: GatewaySubmitAttemptRecord): Promise<void>;
}

// Injectable clock seam (ISO-8601 UTC): tests pin exact timestamps; production uses the
// wall clock. Kept as a plain function type so recorders and primitives share one seam.
export type NowIsoFn = () => string;

export const defaultNowIso: NowIsoFn = () => new Date().toISOString();
