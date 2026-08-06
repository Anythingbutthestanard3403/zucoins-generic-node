// the reporting-auth register tuple — Reporting-key registration binding, tenant-binding rule, and the revocation
// rotation state machine (the pull-cursor authority rule dual-run hardening points 1 and 2).
//
// Governing contract: signed reporting (tenant scope before object lookup); signing-custody key model; the pull-cursor authority addendum.

// Registration binds `reporting_key_id → (node_id, implementer_id)`. AUTHORIZATION derives from
// this binding, not from the signed tuple: signing the tenant fields is necessary but not
// sufficient. The verifier requires a request tuple's node_id AND implementer_id to EQUAL the
// binding, checked BEFORE object lookup (closes the confused-deputy path).
export interface ReportingKeyBinding {
  readonly reporting_key_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
}

// Per-key_id revocation/rotation state machine. REVOKED is terminal and is rejected even in the
// current slot; RETIRED is the graceful end of a rotation overlap. No transition reactivates a key.
export const REPORTING_KEY_STATES = ["PENDING", "ACTIVE", "RETIRED", "REVOKED"] as const;
export type ReportingKeyState = (typeof REPORTING_KEY_STATES)[number];

export interface KeyStateTransition {
  readonly from: ReportingKeyState;
  readonly to: ReportingKeyState;
}

// The only legal transitions: PENDING → ACTIVE → (RETIRED | REVOKED). RETIRED and REVOKED are
// terminal (no outgoing edge), so a revoked or retired key can never return to ACTIVE.
export const REPORTING_KEY_TRANSITIONS = [
  { from: "PENDING", to: "ACTIVE" },
  { from: "ACTIVE", to: "RETIRED" },
  { from: "ACTIVE", to: "REVOKED" },
] as const satisfies readonly KeyStateTransition[];

export const TERMINAL_KEY_STATES = ["RETIRED", "REVOKED"] as const;

// The frozen verifier check sequence (the pull-cursor authority rule point 2): key status first, tenant equality second
// signature last. Verifying the signature before status/tenant would waste crypto on a revoked or
// cross-tenant key and risks a confused-deputy read.
export const REPORTING_VERIFIER_ORDER = ["key_status", "tenant_equality", "signature"] as const;

// Rotation overlap + revocation-to-zero posture. Reporting (implementer) key rotation uses a
// TIME-BOUNDED current+prior overlap: the successor is enrolled with `supersedes_key_id` = the
// current active key, and during REPORTING_KEY_OVERLAP_WINDOW (24 h, the reporting-key enrolment rule) both keys verify;
// afterward only the successor does. This is a deliberate, recorded departure from the node event
// key's seq-cursor retirement (a read-direction reporting key signs discrete tuples with no
// node-owned monotonic `seq` to anchor a cursor); the event key still retires its prior by
// seq-cursor (the pull-cursor authority rule), NOT by the frozen rule's "first batch verified" trigger, which would stall a
// hash-chained stream. Revoking the current key never auto-reactivates the prior; revoking every
// key is an explicit, ALARMED, fail-closed "no active key" state — loud, never a silent cursor
// stall.
export const ROTATION_MODEL = {
  slots: ["current", "prior"],
  reportingKeyOverlap: "current_plus_prior",
  reportingKeyRotationAnchor: "supersedes_key_id",
  reportingKeyOverlapWindowHours: 24,
  eventKeyRetirementTrigger: "seq_cursor_past_last_prior_signed_seq",
  revokeCurrentReactivatesPrior: false,
  revokeToZero: "ALARMED_FAIL_CLOSED_NO_ACTIVE_KEY",
} as const;

// Restore-from-backup guard (the pull-cursor authority rule point 3): a monotonic reporting epoch / high-water-mark so a
// post-restore seq cannot silently collide on the consumer's dedup, and a hash-chain break on
// ingest is a HARD STOP + reconciliation, never a silent skip.
export const RESTORE_GUARD = {
  monotonicMarker: "reporting_epoch_high_water_mark",
  hashChainBreakOnIngest: "HARD_STOP_RECONCILE",
} as const;

// Bootstrap enrolment trust-root (PERMANENT). A bootstrap
// enrolment is a register tuple with `supersedes_key_id === null` — it binds a FIRST reporting key
// to an `implementer_id`. Proof of possession proves keypair *control*, never *identity*, so "who
// may bind a first key" authors a root of authority. The bootstrap enrolment trust-root decision
// resolved this as Option A, PERMANENT: an implementer's first reporting-key binding requires ALL
// of: (i) the implementer's authenticated onboarding credential, with `implementer_id` taken from
// the authenticated caller and NEVER the request body; (ii) an explicit node-origin operator
// approval of the binding; and (iii) the proof-of-possession signature — fail-closed. Production
// reporting authority is granted under this root. Rotation (`supersedes_key_id` non-null) has an
// existing-key anchor and is proxy-frozen, so it is not gated by this bootstrap trust-root.
export const BOOTSTRAP_TRUST_ROOT = {
  trigger: "supersedes_key_id === null",
  status: "PERMANENT",
  decidedBy: "bootstrap-enrolment-trust-root (Option A)",
  grantsLiveReportingAuthority: true,
  implementerIdSource: "authenticated_caller_never_body",
  requiresAll: [
    "authenticated_onboarding_credential",
    "node_origin_operator_approval",
    "proof_of_possession",
  ],
} as const;
