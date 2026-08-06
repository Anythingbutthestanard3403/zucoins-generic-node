import { AMOUNT_FIELD_ROLES } from "./field-roles.js";
import { ZKZ_CHECK_DOMAIN_BY_ROLE, AMOUNT_WRITE_VIOLATION_POLICY } from "./db-enforcement.js";

// the amounts API/DB enforcement aggregate: the frozen application maps that align API and DB amount enforcement.
// Consumes .1's grammar/domains/reason codes; .1 wins on any conflict. Snapshotted to
// gen/amount-enforcement.json (sync test) alongside .1's gen/amounts.json.
export const amountEnforcementContract = {
  fieldRoles: AMOUNT_FIELD_ROLES,
  dbCheckDomainByRole: ZKZ_CHECK_DOMAIN_BY_ROLE,
  writeViolationPolicy: AMOUNT_WRITE_VIOLATION_POLICY,
} as const;
