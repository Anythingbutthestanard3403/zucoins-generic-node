// The residual push guardrail, frozen as INERT CONDITIONAL data. It applies ONLY if the operator
// overrides the no-callback removal to re-admit a push channel (which would also reopen the
// PULL-only auth contract). It is recorded so a future re-admission has a frozen contract to
// build against — it is NOT an active surface, and nothing in the frozen no-callback contract
// references it at runtime. CONTRACT_FREEZE.

export const RESIDUAL_GUARDRAIL = {
  // Inert until the operator re-admits push. The census test asserts this stays false.
  active: false,
  appliesOnlyIf: "operator_overrides_no_callback_removal_to_re_admit_push",
  requirements: [
    "pure_wake_carrying_at_most_the_signed_zp_node_event_v1_envelope",
    "never_carries_transfer_code_address_amount_or_t0",
    "never_advances_node_seq_or_any_consumer_cursor",
    "url_guard_validate_at_registration_and_pin_at_connect",
    "refuse_or_revalidate_every_redirect_hop",
    "block_metadata_link_local_rfc1918_loopback",
    "authenticated_to_implementer_with_event_id_dedup",
    "bounded_retry_plus_dead_letter_never_blocks_or_alters_operation_state",
    "carries_explicit_non_authority_statement",
  ],
} as const;
