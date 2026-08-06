/**
 * Pure, dependency-free parsing helpers over the literal frozen schema contract text.
 * Both the census test and the allowlist subset-parity test read the SQL through these
 * helpers so neither carries its own hand-maintained copy of the wallet_state enum or the
 * MOVE_DESTINATION admitted-state list — the SQL files stay the single source, matched by
 * regex against the real bytes on disk.
 *
 * The two helpers now read DIFFERENT files. custody-eligibility.sql is
 * prerequisite-bound and no longer re-declares data-model's enumerations, so the wallet_state
 * enum is parsed from base-enums-domains.sql (its sole declaring contract); the
 * MOVE_DESTINATION admitted-state list still comes from custody-eligibility.sql, which is
 * where the guard lives.
 */

const WALLET_STATE_ENUM_PATTERN = /CREATE TYPE wallet_state AS ENUM \(([^)]+)\);/;
const SINK_LEASE_STATE_GUARD_PATTERN = /wallet_row\.state NOT IN \(([^)]+)\)/;

const parseQuotedList = (raw: string): string[] => [...raw.matchAll(/'([^']+)'/g)].map((match) => match[1]);

/**
 * The full wallet_state enum, in declaration order, as literally defined in the SQL.
 * Pass base-enums-domains.sql: that is the only contract declaring data-model's
 * enumerations.
 */
export const parseWalletStateEnum = (sql: string): string[] => {
  const match = WALLET_STATE_ENUM_PATTERN.exec(sql);
  if (match === null) {
    throw new Error("base-enums-domains.sql: wallet_state ENUM declaration not found");
  }
  return parseQuotedList(match[1]);
};

/**
 * States the non-RECONCILIATION lease guard admits, parsed from its allowlist clause
 * (`wallet_row.state NOT IN (...)` — the guard rejects everything NOT in this
 * list, so this list IS the admitted set, not a denied-set complement). Shared by
 * sink-role parity tests and custody rule 3 coverage.
 */
export const parseSinkLeaseAdmittedStates = (sql: string): string[] => {
  const match = SINK_LEASE_STATE_GUARD_PATTERN.exec(sql);
  if (match === null) {
    throw new Error(
      "custody-eligibility.sql: non-RECONCILIATION state allowlist guard (wallet_row.state NOT IN (...)) not found",
    );
  }
  return parseQuotedList(match[1]);
};

/** States the non-RECONCILIATION lease guard denies: the full enum minus the admitted set. */
export const parseSinkLeaseDeniedStates = (sql: string): string[] => {
  const enumStates = parseWalletStateEnum(sql);
  const admitted = new Set(parseSinkLeaseAdmittedStates(sql));
  return enumStates.filter((state) => !admitted.has(state));
};
