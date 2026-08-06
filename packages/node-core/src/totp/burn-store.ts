// Global (node_id, totp_timestep) burn registry — shared by enrol_confirm, money
// reject/bless/recovery (verifyTotp), and SEND_EXTERNAL approve. Same physical
// code/step cannot hop across purposes once claimed.
//
// In-memory for Layer-1 tests; SqlTotpBurnStore for production (operational DDL,
// same class as admin_operators — not part of the frozen money-schema pack).
// Destination binding burn-on-verify, operator surface durable claim posture, single-use.

export interface TotpBurnStore {
  /**
   * Atomically claim (nodeId, timestep). Returns false if already burned (replay).
   * Implementations MUST fail closed on store errors (throw) — callers treat as reject.
   */
  claim(nodeId: string, timestep: number): Promise<boolean>;

  /** Read-only probe; true if the timestep is already claimed. */
  isBurned(nodeId: string, timestep: number): Promise<boolean>;
}

function burnKey(nodeId: string, timestep: number): string {
  return `${nodeId}:${timestep}`;
}

/**
 * Process-local burn registry. Production binds {@link SqlTotpBurnStore} instead
 * (or hydrates this class from a durable snapshot on test reboot sims).
 */
export class InMemoryTotpBurnStore implements TotpBurnStore {
  private readonly consumed = new Set<string>();

  async isBurned(nodeId: string, timestep: number): Promise<boolean> {
    return this.consumed.has(burnKey(nodeId, timestep));
  }

  async claim(nodeId: string, timestep: number): Promise<boolean> {
    const k = burnKey(nodeId, timestep);
    if (this.consumed.has(k)) return false;
    this.consumed.add(k);
    return true;
  }

  /** Sync probe — legacy callers / tests. */
  isConsumed(nodeId: string, timestep: number): boolean {
    return this.consumed.has(burnKey(nodeId, timestep));
  }

  /** Sync claim — legacy callers / tests. Prefer {@link claim}. */
  consume(nodeId: string, timestep: number): boolean {
    const k = burnKey(nodeId, timestep);
    if (this.consumed.has(k)) return false;
    this.consumed.add(k);
    return true;
  }

  snapshot(): readonly string[] {
    return [...this.consumed];
  }

  hydrate(keys: readonly string[]): void {
    this.consumed.clear();
    for (const k of keys) this.consumed.add(k);
  }
}

/** @deprecated Use InMemoryTotpBurnStore — alias kept for call-site stability. */
export class TotpConsumptionLog extends InMemoryTotpBurnStore {}

export interface TotpBurnSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

const ENSURE_DDL = `
CREATE TABLE IF NOT EXISTS admin_totp_burns (
  node_id text NOT NULL,
  totp_timestep bigint NOT NULL,
  burned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, totp_timestep)
);
`;

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code: unknown }).code === "23505"
  );
}

/**
 * Durable global (node_id, timestep) burn table. Survives process restart so a
 * confirm-consumed code cannot reopen SEND approve after reboot in-window.
 */
export class SqlTotpBurnStore implements TotpBurnStore {
  constructor(private readonly db: TotpBurnSqlExecutor) {}

  async ensureSchema(): Promise<void> {
    await this.db.query(ENSURE_DDL);
  }

  async isBurned(nodeId: string, timestep: number): Promise<boolean> {
    const { rows } = await this.db.query(
      `SELECT 1 AS ok FROM admin_totp_burns WHERE node_id = $1 AND totp_timestep = $2`,
      [nodeId, timestep],
    );
    return rows[0] !== undefined;
  }

  async claim(nodeId: string, timestep: number): Promise<boolean> {
    try {
      await this.db.query(
        `INSERT INTO admin_totp_burns (node_id, totp_timestep) VALUES ($1, $2)`,
        [nodeId, timestep],
      );
      return true;
    } catch (err) {
      if (isUniqueViolation(err)) return false;
      throw err;
    }
  }
}

/** Wrap a pg Pool (or compatible) as TotpBurnSqlExecutor. */
export function createPoolTotpBurnExecutor(pool: {
  query: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[] }>;
}): TotpBurnSqlExecutor {
  return {
    async query<T extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
    ) {
      const result = await pool.query(sql, params === undefined ? undefined : [...params]);
      return { rows: result.rows as T[] };
    },
  };
}
