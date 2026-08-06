// the amounts API/DB enforcement — which amount-bearing field gets which enforcement predicate. Frozen per the amounts-grammar freeze:
// operation amount_zkz + expected-artifact/approval amounts are strictly positive
// (operation layer, 0 < amount < 1e8); balances / post-states / heads keep 0 <= amount < 1e8
// (balance layer). Foreign signed amounts (the byte-exact signing rule) are byte-inspected, never
// layer-validated — canonicalization applies ONLY to node-authored amounts.

export const AMOUNT_LAYERS = {
  balance: "balance",
  operation: "operation",
} as const;
export type AmountLayer = (typeof AMOUNT_LAYERS)[keyof typeof AMOUNT_LAYERS];

export const AMOUNT_AUTHORSHIP = {
  node: "node",
  foreign: "foreign",
} as const;
export type AmountAuthorship = (typeof AMOUNT_AUTHORSHIP)[keyof typeof AMOUNT_AUTHORSHIP];

// Node-authored roles carry the layer they are validated against; foreign roles carry
// `layer: null` because they are inspected over exact bytes, not validated against a layer.
type NodeRole = { readonly authorship: "node"; readonly layer: AmountLayer };
type ForeignRole = { readonly authorship: "foreign"; readonly layer: null };

export const AMOUNT_FIELD_ROLES = {
  // requests / operations / approvals / artifacts — strictly positive money values.
  request_transfer_amount: { authorship: "node", layer: "operation" },
  operation_amount_zkz: { authorship: "node", layer: "operation" },
  expected_artifact_amount: { authorship: "node", layer: "operation" },
  approval_amount: { authorship: "node", layer: "operation" },
  // states / derived balances / heads / genesis — node-computed positions; zero is legal.
  node_post_transfer_state: { authorship: "node", layer: "balance" },
  derived_balance: { authorship: "node", layer: "balance" },
  node_head_amount: { authorship: "node", layer: "balance" },
  genesis_amount: { authorship: "node", layer: "balance" },
  // foreign signed amounts — verified over EXACT bytes, never reformatted (the byte-exact signing rule).
  payer_signed_step_amount: { authorship: "foreign", layer: null },
  recipient_signed_step_amount: { authorship: "foreign", layer: null },
  observed_onchain_step_state: { authorship: "foreign", layer: null },
} as const satisfies Record<string, NodeRole | ForeignRole>;

export type AmountFieldRole = keyof typeof AMOUNT_FIELD_ROLES;

export function amountFieldRole(role: AmountFieldRole): NodeRole | ForeignRole {
  return AMOUNT_FIELD_ROLES[role];
}
