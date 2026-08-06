// Fail-closed schema-version fence for the lease foundation.
// Boot refuses money-path work when lease_schema_fence is missing/below the required
// version OR when the receive-gate enforcement eligibility guard (function + BEFORE INSERT trigger) is absent.

import { LEASE_FOUNDATION_SCHEMA_VERSION } from "../schema/lease-foundation.contract.js";
import { LeaseError } from "./errors.js";
import { eligibilityGuardPresent } from "./migrate.js";
import { STATEMENTS } from "./statements.js";
import type { SqlExecutor } from "./types.js";

export async function assertLeaseFoundationReady(
  db: SqlExecutor,
  requiredVersion: number = LEASE_FOUNDATION_SCHEMA_VERSION,
): Promise<void> {
  let rows: Array<{ schema_version: number }>;
  try {
    const result = await db.query<{ schema_version: number }>(STATEMENTS.SELECT_FENCE);
    rows = result.rows;
  } catch {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      `lease_schema_fence is missing; required schema_version=${requiredVersion}`,
    );
  }
  const version = rows[0]?.schema_version;
  if (version === undefined || version < requiredVersion) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      `lease foundation schema_version=${version ?? "absent"} < required ${requiredVersion}`,
    );
  }

  if (!(await eligibilityGuardPresent(db))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "lease eligibility guard (lease_foundation_reject_ineligible_lease + " +
        "wallet_active_leases_eligibility_guard) is missing; refusing money-path work",
    );
  }
}
