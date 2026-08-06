// Concern barrel for the frozen ZKZ amount contract (the amounts scalar/arithmetic scalar/arithmetic + the amounts API/DB enforcement
// API/DB enforcement alignment). This file lives inside the exclusive amounts/ concern dir.
// It is NOT the package root src/index.ts (the concern-manifest registry-owned); the concern-manifest registry wires this concern into the
// package registry.
export {
  AMOUNT_INPUT_TYPE_ERROR_MESSAGE,
  assertPrimitiveAmountString,
} from "./string-boundary.js";
export { CANONICAL_DECIMAL_PATTERN, matchesCanonicalGrammar } from "./grammar.js";
export {
  emitAmount,
  addAmounts,
  subtractAmounts,
  compareAmounts,
  isFiniteAmount,
  numericDecimalPlaces,
  isNumericallyPositive,
  isWithinBalanceMagnitude,
  isWithinOperationMagnitude,
} from "./emitter.js";
export {
  isCanonicalAmount,
  validateBalanceAmount,
  validateOperationAmount,
  type AmountCheck,
} from "./validators.js";
export { inspectForeignAmount, type ForeignAmountInspection } from "./foreign.js";
export {
  amountsContract,
  amountsConcernManifest,
  AMOUNT_REJECTION_REASONS,
  ZKZ_AMOUNT_CHECK_DOMAINS,
  type AmountRejectionReason,
} from "./manifest.js";

// the amounts API/DB enforcement — API/DB enforcement alignment.
export {
  AMOUNT_LAYERS,
  AMOUNT_AUTHORSHIP,
  AMOUNT_FIELD_ROLES,
  amountFieldRole,
  type AmountLayer,
  type AmountAuthorship,
  type AmountFieldRole,
} from "./field-roles.js";
export {
  enforceAmountField,
  type AmountFieldEnforcement,
  type AmountRejection,
} from "./enforcement.js";
export {
  ZKZ_CHECK_DOMAIN_BY_ROLE,
  AMOUNT_WRITE_VIOLATION_POLICY,
  FOREIGN_NO_REJECT,
} from "./db-enforcement.js";
export { amountEnforcementContract } from "./enforcement-manifest.js";

// the amounts vector matrix — published vector matrix (imported by downstream consumers, e.g. the amounts downstream consumer/the fixture-provenance concern).
export {
  AMOUNT_BOUNDARY_VECTORS,
  AMOUNT_ARITHMETIC_VECTORS,
  AMOUNT_EMISSION_VECTORS,
  amountVectors,
  type AmountBoundaryVector,
  type AmountArithmeticVector,
  type AmountEmissionVector,
  type AmountCheckExpectation,
} from "./vectors.js";
