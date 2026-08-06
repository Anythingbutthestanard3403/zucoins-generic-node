import {
  WALLET_SELECTION_ORDER,
  WALLET_SELECTION_LOCK,
  SELECT_ASSIGNABLE_WALLET_SQL,
} from "./selection.js";
import {
  POOL_CAS_COLUMN,
  RESERVE_WALLET_CAS_SQL,
  REPLENISHMENT_CRASH_SAFETY,
} from "./reservation.js"; // contract-allow:reservation-module-path
import { RETIRE_WALLET_CAS_SQL } from "./retirement.js";
import { SCALE_UP_ADVISORY_LOCK_NAMESPACE, CAP_COUNT_UNDER_LOCK_SQL } from "./scaling.js";
import {
  OPEN_SESSIONS_COUNT_SQL,
  OPEN_SESSIONS_COMPONENTS,
  OPEN_SESSIONS_EXCLUDED_COMPONENTS,
} from "./open-sessions.js";

// the named concern aggregate: the selection / hold / scale-up transaction contract as frozen data.
// SQL text is contract-level and bindable by the DB-domains concern/the named concern; the pure models in the sibling modules
// are the executable semantics. Snapshotted to gen/pool-transactions.json (sync test).
export const poolTransactionsContract = {
  selection: {
    order: WALLET_SELECTION_ORDER, // contract-allow:frozen-contract-field-name
    lock: WALLET_SELECTION_LOCK,
    sql: SELECT_ASSIGNABLE_WALLET_SQL,
  },
  reservation: { // contract-allow:frozen-contract-field-name
    casColumn: POOL_CAS_COLUMN,
    sql: RESERVE_WALLET_CAS_SQL,
    crashSafety: REPLENISHMENT_CRASH_SAFETY,
  },
  retirement: {
    casColumn: POOL_CAS_COLUMN,
    sql: RETIRE_WALLET_CAS_SQL,
  },
  scaleUp: {
    advisoryLockNamespace: SCALE_UP_ADVISORY_LOCK_NAMESPACE,
    capCountSql: CAP_COUNT_UNDER_LOCK_SQL,
    openSessionsSql: OPEN_SESSIONS_COUNT_SQL,
    openSessionsComposition: {
      includes: OPEN_SESSIONS_COMPONENTS,
      excludes: OPEN_SESSIONS_EXCLUDED_COMPONENTS,
    },
  },
} as const;
