/**
 * Shared IPC contract for the migration lock-class classifier.
 *
 * Side-effect-free types only. Imported by both the parent
 * (`migration-classifier.ts`) and the isolated child
 * (`migration-classifier.worker.ts`) so the wire format cannot drift while the
 * two compile independently.
 *
 * This module MUST stay inert: no runtime imports, no environment access, no DB
 * client, no key material, no boot graph. Enforced by
 * `migration-classifier.ipc.boundary.test.ts`.
 *
 * Protocol (fork IPC channel):
 *   Main → Worker: WorkerRequest  { id, sqlText }
 *   Worker → Main: WorkerResponse { id, result } | { id, error }
 */

export type LockClass = "online" | "blocking";

export interface StatementClassification {
  sql: string;
  lockClass: LockClass;
  reason: string;
}

export interface ClassificationResult {
  lockClass: LockClass;
  statements: StatementClassification[];
}

export interface WorkerRequest {
  id: number;
  sqlText: string;
}

export type WorkerResponse =
  | { id: number; result: ClassificationResult }
  | { id: number; error: string };
