import {
  type SchedulerCursor,
  type StreamKind,
  type ReconcileVerdict,
  type VerdictApplyResult,
  type WorkerPoolConfig,
  DEFAULT_POOL_CONFIG,
  STREAM_KINDS,
} from "./types.js";
import { type ClaimStore, acquireClaim, heartbeatClaim, releaseClaim } from "./claim.js";

export interface CursorStore {
  getCursor(walletId: string, stream: StreamKind): SchedulerCursor | null;
  putCursor(cursor: SchedulerCursor): void;
}

export class InMemoryCursorStore implements CursorStore {
  private readonly cursors = new Map<string, SchedulerCursor>();

  private key(walletId: string, stream: StreamKind): string {
    return `${walletId}:${stream}`;
  }

  getCursor(walletId: string, stream: StreamKind): SchedulerCursor | null {
    return this.cursors.get(this.key(walletId, stream)) ?? null;
  }

  putCursor(cursor: SchedulerCursor): void {
    this.cursors.set(this.key(cursor.walletId, cursor.streamKind), cursor);
  }

  clear(): void {
    this.cursors.clear();
  }
}

export interface OperationRow {
  readonly operationId: string;
  readonly walletId: string;
  readonly status: string;
  readonly rowVersion: number;
  readonly stream: StreamKind;
}

export interface OperationStore {
  findByWallet(walletId: string, stream: StreamKind, afterPosition: number, limit: number): OperationRow[];
  applyVerdict(operationId: string, expectedRowVersion: number, newStatus: string): VerdictApplyResult;
}

export class InMemoryOperationStore implements OperationStore {
  private readonly rows: OperationRow[] = [];
  private readonly applied = new Set<string>();

  addRow(row: OperationRow): void {
    this.rows.push(row);
  }

  findByWallet(walletId: string, stream: StreamKind, afterPosition: number, limit: number): OperationRow[] {
    return this.rows
      .filter((r) => r.walletId === walletId && r.stream === stream)
      .slice(afterPosition, afterPosition + limit);
  }

  applyVerdict(operationId: string, expectedRowVersion: number, newStatus: string): VerdictApplyResult {
    const key = `${operationId}:${newStatus}`;
    if (this.applied.has(key)) {
      return { outcome: "ALREADY_APPLIED" };
    }

    const row = this.rows.find((r) => r.operationId === operationId);
    if (!row) return { outcome: "CAS_CONFLICT", actualRowVersion: -1 };
    if (row.rowVersion !== expectedRowVersion) {
      return { outcome: "CAS_CONFLICT", actualRowVersion: row.rowVersion };
    }

    this.applied.add(key);
    const idx = this.rows.indexOf(row);
    this.rows[idx] = { ...row, status: newStatus, rowVersion: row.rowVersion + 1 };
    return { outcome: "APPLIED", newRowVersion: row.rowVersion + 1 };
  }

  getRow(operationId: string): OperationRow | undefined {
    return this.rows.find((r) => r.operationId === operationId);
  }

  clear(): void {
    this.rows.length = 0;
    this.applied.clear();
  }
}

export interface SchedulerTickResult {
  readonly walletId: string;
  readonly stream: StreamKind;
  readonly verdicts: readonly ReconcileVerdict[];
  readonly applied: number;
  readonly skipped: number;
  /** Rows whose guarded transition lost the CAS. They stay in front of the cursor and are re-classified next tick. */
  readonly conflicted: number;
  readonly cursorAdvanced: boolean;
}

export type ClassifyFn = (row: OperationRow) => ReconcileVerdict;

export function schedulerTick(
  claimStore: ClaimStore,
  cursorStore: CursorStore,
  opStore: OperationStore,
  classify: ClassifyFn,
  workerId: string,
  walletId: string,
  now: number,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): SchedulerTickResult[] {
  const claimResult = acquireClaim(claimStore, workerId, walletId, now, config);
  if (claimResult.outcome !== "ACQUIRED") return [];

  const results: SchedulerTickResult[] = [];
  const batchSize = 10;

  try {
    for (const stream of STREAM_KINDS) {
      const cursor = cursorStore.getCursor(walletId, stream);
      const position = cursor?.position ?? 0;

      const rows = opStore.findByWallet(walletId, stream, position, batchSize);
      if (rows.length === 0) continue;

      const verdicts: ReconcileVerdict[] = [];
      let applied = 0;
      let skipped = 0;
      let conflicted = 0;

      // The cursor may only cross rows whose guarded transition actually committed
      // (APPLIED) or was already at the verdict state (ALREADY_APPLIED). A CAS conflict
      // means the row moved under us, so its classification is stale: leave it in front
      // of the cursor and re-classify it on the next tick rather than losing it forever.
      // Re-reading and re-classifying is a read retry, not a submit retry (axiom 1),
      // and the transition stays guarded on the freshly read row_version.
      let advanceBy = 0;
      let prefixIntact = true;

      for (const row of rows) {
        const verdict = classify(row);
        verdicts.push(verdict);

        const applyResult = opStore.applyVerdict(
          verdict.operationId,
          verdict.expectedRowVersion,
          verdict.classification,
        );

        if (applyResult.outcome === "APPLIED") applied++;
        else skipped++;

        if (applyResult.outcome === "CAS_CONFLICT") {
          conflicted++;
          prefixIntact = false;
        } else if (prefixIntact) {
          advanceBy++;
        }
      }

      const newPosition = position + advanceBy;
      if (newPosition > position) {
        cursorStore.putCursor({
          walletId,
          streamKind: stream,
          position: newPosition,
          updatedAt: now,
        });
      }

      results.push({
        walletId,
        stream,
        verdicts,
        applied,
        skipped,
        conflicted,
        cursorAdvanced: newPosition > position,
      });
    }
  } finally {
    // A worker claim is a short execution lease: it is released on every exit path,
    // including a throw out of classify/applyVerdict, so a fault cannot strand the
    // wallet's scheduling behind a claim that only a TTL expiry would clear.
    heartbeatClaim(claimStore, walletId, workerId, now, config);
    releaseClaim(claimStore, walletId, workerId);
  }

  return results;
}
