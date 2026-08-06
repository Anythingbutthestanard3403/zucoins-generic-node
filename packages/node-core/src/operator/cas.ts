export type OperationStatus = string;

export interface CasTransitionRequest<S extends OperationStatus = OperationStatus> {
  readonly operationId: string;
  readonly expectedStatus: S;
  readonly expectedRowVersion: number;
  readonly newStatus: S;
}

export interface CasTransitionSuccess<S extends OperationStatus = OperationStatus> {
  readonly ok: true;
  readonly operationId: string;
  readonly newStatus: S;
  readonly newRowVersion: number;
}

export interface CasTransitionConflict<S extends OperationStatus = OperationStatus> {
  readonly ok: false;
  readonly operationId: string;
  readonly actualStatus: S;
  readonly actualRowVersion: number;
}

export type CasTransitionResult<S extends OperationStatus = OperationStatus> =
  | CasTransitionSuccess<S>
  | CasTransitionConflict<S>;

export interface OperationRecord<S extends OperationStatus = OperationStatus> {
  readonly operationId: string;
  readonly status: S;
  readonly rowVersion: number;
}

// Persistence port for CAS-guarded operation state. The store atomically checks
// (status, rowVersion) before applying a transition — a version mismatch rejects
// the write (optimistic concurrency, preventing lost updates).
export interface OperationStateStore<S extends OperationStatus = OperationStatus> {
  read(operationId: string): Promise<OperationRecord<S> | null>;
  compareAndSwap(
    operationId: string,
    expectedStatus: S,
    expectedRowVersion: number,
    newStatus: S,
  ): Promise<CasTransitionResult<S>>;
}

export class CasConflictError extends Error {
  readonly operationId: string;
  readonly actualStatus: string;
  readonly actualRowVersion: number;

  constructor(conflict: CasTransitionConflict) {
    super(
      `CAS conflict on operation ${conflict.operationId}: ` +
        `found status=${conflict.actualStatus} version=${conflict.actualRowVersion}`,
    );
    this.name = "CasConflictError";
    this.operationId = conflict.operationId;
    this.actualStatus = conflict.actualStatus;
    this.actualRowVersion = conflict.actualRowVersion;
  }
}

export async function applyCasTransition<S extends OperationStatus>(
  store: OperationStateStore<S>,
  request: CasTransitionRequest<S>,
): Promise<CasTransitionSuccess<S>> {
  const result = await store.compareAndSwap(
    request.operationId,
    request.expectedStatus,
    request.expectedRowVersion,
    request.newStatus,
  );
  if (!result.ok) {
    throw new CasConflictError(result);
  }
  return result;
}

export function createInMemoryOperationStateStore<
  S extends OperationStatus = OperationStatus,
>(): OperationStateStore<S> & { seed(record: OperationRecord<S>): void } {
  const records = new Map<string, OperationRecord<S>>();

  return {
    seed(record: OperationRecord<S>): void {
      records.set(record.operationId, record);
    },

    async read(operationId: string): Promise<OperationRecord<S> | null> {
      return records.get(operationId) ?? null;
    },

    async compareAndSwap(
      operationId: string,
      expectedStatus: S,
      expectedRowVersion: number,
      newStatus: S,
    ): Promise<CasTransitionResult<S>> {
      const current = records.get(operationId);
      if (!current) {
        return { ok: false, operationId, actualStatus: "" as S, actualRowVersion: 0 };
      }
      if (current.status !== expectedStatus || current.rowVersion !== expectedRowVersion) {
        return { ok: false, operationId, actualStatus: current.status, actualRowVersion: current.rowVersion };
      }
      const updated: OperationRecord<S> = { operationId, status: newStatus, rowVersion: current.rowVersion + 1 };
      records.set(operationId, updated);
      return { ok: true, operationId, newStatus, newRowVersion: updated.rowVersion };
    },
  };
}
