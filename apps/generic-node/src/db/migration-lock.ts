/**
 * Singleton migration advisory lock.
 *
 * Two concurrent boot lanes against the same database must not both run drizzle
 * (journal write + DDL race). A dedicated session advisory lock serialises
 * migrators: the holder runs the pending-only re-read + overlap guard + DDL;
 * a contender fails closed (try-lock, no wait).
 *
 * Distinct from SIGNER_LEADERSHIP_LOCK_ID — leadership is the live-signer
 * exclusion; this lock is migrator exclusion only and is released as soon as
 * the migration connection is returned to the pool (or the process dies).
 *
 * ASCII "GNmg" → 0x474e6d67. Never change it: two instances using different ids
 * would not interlock.
 */

import type { PoolClient } from "pg";

/** Session advisory lock id for the generic-node migrator singleton. */
export const MIGRATION_ADVISORY_LOCK_ID = 0x474e6d67; // "GNmg"

export const TRY_ACQUIRE_MIGRATION_LOCK_SQL =
  "SELECT pg_try_advisory_lock($1) AS locked";
export const ACQUIRE_MIGRATION_LOCK_SQL = "SELECT pg_advisory_lock($1) AS locked";
export const RELEASE_MIGRATION_LOCK_SQL =
  "SELECT pg_advisory_unlock($1) AS released";

export class MigrationLockBusyError extends Error {
  constructor() {
    super(
      `Another generic-node instance holds the migration advisory lock ` +
        `(id=${MIGRATION_ADVISORY_LOCK_ID}). Refusing to run concurrent migrators ` +
        `against the same database. Wait for the other instance to finish, or ` +
        `scale to a single migrator.`,
    );
    this.name = "MigrationLockBusyError";
  }
}

/**
 * Try to acquire the migrator singleton on `client` without blocking.
 * Returns true if this connection now holds the lock.
 */
export async function tryAcquireMigrationLock(
  client: Pick<PoolClient, "query">,
): Promise<boolean> {
  const res = await client.query<{ locked: boolean }>(TRY_ACQUIRE_MIGRATION_LOCK_SQL, [
    MIGRATION_ADVISORY_LOCK_ID,
  ]);
  return res.rows[0]?.locked === true;
}

/**
 * Blocking acquire (honours the connection's lock_timeout). Used when the
 * operator deliberately serialises migrators rather than fail-fast.
 * Default path is {@link tryAcquireMigrationLock} + refuse.
 */
export async function acquireMigrationLock(client: Pick<PoolClient, "query">): Promise<void> {
  await client.query(ACQUIRE_MIGRATION_LOCK_SQL, [MIGRATION_ADVISORY_LOCK_ID]);
}

export async function releaseMigrationLock(client: Pick<PoolClient, "query">): Promise<void> {
  await client.query(RELEASE_MIGRATION_LOCK_SQL, [MIGRATION_ADVISORY_LOCK_ID]);
}

/**
 * Acquire the migrator singleton or throw {@link MigrationLockBusyError}.
 * Call on the SAME pinned connection that will run drizzle so the lock spans
 * the entire migration transaction set and self-releases if that connection dies.
 */
export async function assertMigrationLockAcquired(
  client: Pick<PoolClient, "query">,
): Promise<void> {
  const locked = await tryAcquireMigrationLock(client);
  if (!locked) throw new MigrationLockBusyError();
}
