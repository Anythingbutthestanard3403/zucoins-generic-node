import { validateBalanceAmount, validateOperationAmount } from "./validators.js";
import { inspectForeignAmount } from "./foreign.js";
import { AMOUNT_FIELD_ROLES, type AmountFieldRole, type AmountLayer } from "./field-roles.js";
import { type AmountRejectionReason } from "./manifest.js";
import { assertPrimitiveAmountString } from "./string-boundary.js";

// The single typed rejection contract every node-authored amount failure produces, uniform
// across requests / operations / states / approvals / artifacts / derived balances. Product
// code (a later ticket) maps this shape to its API error response; this concern only freezes
// the shape and the pure verifier — no runtime handler here.
export type AmountRejection = {
  readonly kind: "rejected";
  readonly role: AmountFieldRole;
  readonly layer: AmountLayer;
  readonly reason: AmountRejectionReason;
  readonly value: string;
};

export type AmountFieldEnforcement =
  | { readonly kind: "accepted"; readonly role: AmountFieldRole; readonly canonical: string }
  | AmountRejection
  | {
      // Foreign signed amount: verified over EXACT bytes, never canonicalized and never
      // rejected at ingest (the byte-exact signing rule); a malformed one carries an anomaly, evidence kept.
      readonly kind: "foreign";
      readonly role: AmountFieldRole;
      readonly bytes: string;
      readonly wellFormed: boolean;
      readonly anomaly: string | null;
    };

// One entry, applied the same to every amount-bearing field. The role's frozen
// authorship/layer (field-roles.ts) selects the predicate: strictly-positive operation
// validation, inclusive-zero balance validation, or foreign byte inspection.
export function enforceAmountField(role: AmountFieldRole, amount: unknown): AmountFieldEnforcement {
  assertPrimitiveAmountString(amount);
  const spec = AMOUNT_FIELD_ROLES[role];

  if (spec.authorship === "foreign") {
    const inspection = inspectForeignAmount(amount);
    return {
      kind: "foreign",
      role,
      bytes: inspection.bytes,
      wellFormed: inspection.wellFormed,
      anomaly: inspection.anomaly,
    };
  }

  const check =
    spec.layer === "operation" ? validateOperationAmount(amount) : validateBalanceAmount(amount);

  if (check.ok) {
    return { kind: "accepted", role, canonical: check.canonical };
  }
  return { kind: "rejected", role, layer: spec.layer, reason: check.reason, value: amount };
}
