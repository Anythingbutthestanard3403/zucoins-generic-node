/**
 * Public subpath `@zucoins/generic-node-contracts/operator-halt`.
 *
 * Closed operator recovery-action catalog and halt disposition tables from the
 * frozen halt contract. Leaf surface — no net/db/crypto side effects — safe for
 * browser bundles that only need the catalog constants.
 */

export {
  OPERATOR_RECOVERY_ACTIONS,
  RESERVED_RECOVERY_ACTIONS,
  type OperatorRecoveryAction,
  HALT_KINDS,
  type HaltKind,
  HALT_GATED_RECOVERY_ACTIONS,
  HALT_NEVER_GATED_RECOVERY_ACTIONS,
  classifyRecoveryActionHalt,
  type RecoveryActionHaltDisposition,
} from "./halt.contract.ts";

export { OPERATOR_HALT_CONCERN_MANIFEST } from "./manifest.ts";
