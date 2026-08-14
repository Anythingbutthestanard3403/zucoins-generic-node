// destination_state += WORKER (send-worker auto-scale). Enum-only fix-forward slice.

export const DESTINATION_STATE_WORKER_SCHEMA_FILE = "destination-state-worker.sql" as const;

export interface DestinationStateWorkerInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DESTINATION_STATE_WORKER_INVARIANTS: readonly DestinationStateWorkerInvariant[] = [
  {
    id: "ADD_WORKER_ENUM",
    sqlAnchor: "ALTER TYPE destination_state ADD VALUE 'WORKER'",
    rule: "idempotently admits WORKER on already-applied destination_state enums; own slice so the ADD VALUE transaction commits before later CHECKs / trigger branches reference the label.",
  },
] as const;

export const DESTINATION_STATE_WORKER_EXECUTION_OBLIGATIONS: readonly string[] = [
  "Must pack sequence before destination-worker-sink so ADD VALUE is committed before the CHECK rewrite and G2 overlay reference WORKER.",
  "Idempotent: no-op when the label already exists.",
] as const;

export const DESTINATION_STATE_WORKER_SOURCE =
  "destination_state WORKER; send-worker auto-scale" as const;
