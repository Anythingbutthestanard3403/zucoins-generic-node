// Terminal Layer-1 operation states — Appendix B / generic-node-contracts states.contract.
//
// Single source of truth for "this operation has reached a terminal status", kept in
// protocol/ because it is consumed from two modules that may not import each other:
// api/ (subscription-handle TTL clock) and workers/ (boot recovery's nonterminal
// partition). apps/generic-node interpolates the same list into the boot-recovery
// operation census SQL. Do not restate the list anywhere — a second copy is exactly the
// drift that caused.

export const TERMINAL_OPERATION_STATES = [
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "EXTERNAL_SEND_LANDED",
  "EXPIRED",
  "REJECTED",
] as const;

// The rest of the operation_status enum (schema/base-enums-domains.sql). Spelled out
// rather than derived so that adding a status to the DDL cannot pass silently: the census in
// test/operation-states.census.test.ts binds the union of the two lists to the enum members,
// so a new status reddens the suite until someone classifies it terminal-or-not here.
export const NONTERMINAL_OPERATION_STATES = [
  "CREATED",
  "READY",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "NEEDS_ATTENTION",
] as const;

export type TerminalOperationState = (typeof TERMINAL_OPERATION_STATES)[number];
export type NonterminalOperationState = (typeof NONTERMINAL_OPERATION_STATES)[number];
export type OperationState = TerminalOperationState | NonterminalOperationState;

export function isTerminalOperationState(state: string): state is TerminalOperationState {
  return (TERMINAL_OPERATION_STATES as readonly string[]).includes(state);
}

// `isTerminalOperationState` answers false for two different things — "nonterminal" and "not a
// status this build has ever heard of". Callers for whom false only widens a recovery scan (boot
// recovery, the subscription TTL clock) may keep collapsing them; a caller for whom false ARMS a
// destructive action must not, and has to fail closed on an unrecognised status instead
// (scripts/remediate-orphaned-lease.mjs).
export function isKnownOperationState(state: string): state is OperationState {
  return (
    isTerminalOperationState(state) ||
    (NONTERMINAL_OPERATION_STATES as readonly string[]).includes(state)
  );
}
