// offline-safe completion monitor stub for AWAITING_REDEMPTION sends.
// Landing (EXTERNAL_SEND_LANDED) is Wave 4 dual-control. This stub never submits,
// never invents landing, and parks attention only when explicitly instructed by the poller.

import type { Pool } from "pg";

export interface SendCompletionTickLogger {
  info(message: string): void;
}

/**
 * Offline residual: list AWAITING_REDEMPTION ops and log deferred landing.
 * Never transitions to EXTERNAL_SEND_LANDED without a landing proof (the lander).
 */
export async function tickSendCompletionMonitorOffline(
  pool: Pool,
  logger: SendCompletionTickLogger,
): Promise<number> {
  let result: { rows: Array<{ operation_id: string; transfer_code_sha256: string | null }> };
  try {
    result = await pool.query(
      `SELECT s.operation_id::text AS operation_id,
              p.transfer_code_sha256
         FROM send_operations s
         LEFT JOIN external_send_partials p ON p.operation_id = s.operation_id
        WHERE s.status = 'AWAITING_REDEMPTION'
        ORDER BY s.created_at ASC -- contract-allow:order:frozen structural vocabulary
        LIMIT 25`,
    );
  } catch {
    // Schema not fully applied in unit composition — no-op.
    return 0;
  }
  for (const row of result.rows) {
    const fp = row.transfer_code_sha256 ?? "none";
    logger.info(
      `money-workers: SEND completion deferred (offline stub) op=${row.operation_id} transfer_code_sha256=${fp.slice(0, 12)}… — node never submits SEND`,
    );
  }
  return result.rows.length;
}
