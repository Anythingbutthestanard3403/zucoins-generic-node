/**
 * Worker-sink destination + G2 overlay (send-worker auto-scale).
 *
 * Frozen inventory of destination-worker-sink.sql. Requires destination-state-worker.
 */

export const DESTINATION_WORKER_SINK_SCHEMA_FILE = "destination-worker-sink.sql" as const;

export interface DestinationWorkerSinkInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DESTINATION_WORKER_SINK_INVARIANTS: readonly DestinationWorkerSinkInvariant[] = [
  {
    id: "BLESSED_IFF_ALLOWS_WORKER",
    sqlAnchor: "state <> 'WORKER'",
    rule: "WORKER destinations exist only with null blessing columns; PENDING stays unblessed; BLESSED/RETIRED still require blessed_at.",
  },
  {
    id: "G2_ADMITS_WORKER_SINK",
    sqlAnchor: "AND destination_row.state IS DISTINCT FROM 'WORKER' THEN",
    rule: "MOVE_DESTINATION lease admits BLESSED or WORKER; other destination states still raise CUSTODY_LEASE_DESTINATION_NOT_BLESSED.",
  },
  {
    id: "BLESSED_STILL_REQUIRES_RECOVERY",
    sqlAnchor: "IF destination_row.state = 'BLESSED'",
    rule: "BLESSED MOVE_DESTINATION still requires recovery_verified_at; WORKER does not.",
  },
  {
    id: "MONEY_CAPABILITY_RETAINED",
    sqlAnchor: "CUSTODY_LEASE_SEND_CAPABILITY_REJECTED",
    rule: "Money-capability conjuncts from wallet-money-capability-lease-guard remain on RECEIVE_WINDOW / SEND_SOURCE / MOVE_*.",
  },
] as const;

export const DESTINATION_WORKER_SINK_PACK_NOTES = [
  "Applies after destination-state-worker.sql (WORKER enum label must be committed).",
  "Does not CREATE TABLE; CHECK rewrite + function body replace.",
  "custody-eligibility.sql and wallet-money-capability-lease-guard.sql stay frozen for pack sql_sha256.",
] as const;

export const DESTINATION_WORKER_SINK_SOURCE =
  "send-worker auto-scale; WORKER destination sink" as const;
