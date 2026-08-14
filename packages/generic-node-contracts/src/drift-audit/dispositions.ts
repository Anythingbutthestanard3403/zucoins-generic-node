/**
 * Drift-axis disposition record — the closure half of the drift-audit honesty ledger.
 *
 * The residuals ledger enumerated the fifteen drift axes in the audit's scope and left every
 * one `residual-open` with a one-line "not cross-checked" reason. This module records the
 * closing disposition for each of the fifteen: which frozen rules govern it, which spec
 * material it was diffed against, and what the diff concluded.
 *
 * Two rules keep this record from being self-certifying:
 *
 *   1. **Existence.** Every `decisionRefs` entry names a frozen rule that really governs the
 *      axis (a rule cited from nowhere has no authority).
 *   2. **Derivation.** Every `decisionRefs` entry must already appear in the `decisionRefs`
 *      of one of the axis's `governingConcerns` in `CONCERN_REGISTRY`. This record therefore
 *      cites only authority that a concern freeze already claimed; it cannot mint a new
 *      authority link, and no local author may mint a canonical identifier.
 *
 * A `CLOSED_AUTOMATED` status here is a claim that the named cross-document check ran and
 * passed, not a substitute for it. Every axis's residual test/golden obligations are tracked
 * separately — closing a drift axis closes the *documentation* conflict, nothing else.
 */

/**
 * `CLOSED_AUTOMATED` — the axis is machine-cross-checked and the two sides agree.
 *
 * `OPEN_DEFECT` — the governing rules already answer the axis, but a committed artifact
 * contradicts that answer. The disposition is the citation plus a filed defect; the axis
 * stays open.
 *
 * `NEEDS_DECISION` — the diff surfaced a normative question with **no** governing rule. The
 * axis stays open and `escalation` names the tracking item that carries it; nothing is
 * resolved inline here.
 *
 * Both open statuses carry an `escalation`. Neither may be flipped to closed by editing this
 * file: the closing evidence is the named work landing, not a status string.
 */
export type AxisDispositionStatus = "CLOSED_AUTOMATED" | "OPEN_DEFECT" | "NEEDS_DECISION";

export interface AxisDisposition {
  /** One of the fifteen scope-line axis names, spelled as in `AUDIT_RESIDUALS`. */
  readonly axis: string;
  readonly status: AxisDispositionStatus;
  /** Frozen rules that govern the axis. Existence + derivation are asserted. */
  readonly decisionRefs: readonly string[];
  /** Concern directories whose frozen data is the contract side of this axis's diff. */
  readonly governingConcerns: readonly string[];
  /** Spec material that is the doc side of the diff. */
  readonly docCitations: readonly string[];
  /** What the cross-document diff concluded, in one line. */
  readonly closure: string;
  /** Tracking id carrying the axis onward. Present exactly when `status` is not `CLOSED_AUTOMATED`. */
  readonly escalation?: string;
}

/**
 * The fifteen axes, in `SCOPE_LINE_AXES` sequence. No axis may be dropped, merged, or
 * silently renamed.
 */
export const AXIS_DISPOSITIONS: readonly AxisDisposition[] = [
  {
    axis: "destination-label",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["custody-and-sink-eligibility-rule", "three-generic-operations"],
    governingConcerns: ["custody", "api-schema"],
    docCitations: ["data-model destinations DDL", "api-contract destination endpoints"],
    closure:
      "DESTINATION_STATES (PENDING/BLESSED/RETIRED) agree across the data model's destination_state DDL and the api contract's state filter. The `label` property the api contract accepts and returns had no column in the destinations DDL — a genuine one-sided wire field, reconciled by adding `label text NOT NULL` to the DDL (same shape as operator_device_keys.label); no signed tuple carries it, so no golden changes.",
  },
  {
    axis: "terminal-timestamps",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["receive-expiry-prevention-rule", "three-generic-operations"],
    governingConcerns: ["wallet-state", "operations"],
    docCitations: ["state-event reference terminal column", "data-model operations tables"],
    closure:
      "The state-event reference's Terminal column and the frozen TERMINAL_RECEIVE_STATES are the same two-value set (EXPIRED, RECEIVE_LANDED). The terminal timestamp is named `terminal_at` on operations and `terminal_observation_id` on operation_wallets throughout the data model — one spelling each, no competing field.",
  },
  {
    axis: "evidence-role-names",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["observation-dedup"],
    governingConcerns: ["observation"],
    docCitations: ["observation-verification relationship table", "data-model wallet-observation roles"],
    closure:
      "The observation-verification relationship table matches RELATIONSHIP_CLASSIFICATION_RULES row-for-row in sequence, relationship name and state_changed. WALLET_OBSERVATION_ROLES (sender/receiver/genesis) appear verbatim in the data model's CHECK domain.",
  },
  {
    axis: "proof-windows",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["complete-path-adjudication", "observation-dedup"],
    governingConcerns: ["landing-proof", "observation"],
    docCitations: ["observation-verification retention rules", "data-model retention matrix"],
    closure:
      'MANIFEST_RETENTION.accessWindowDefault (TERMINAL_PLUS_30_DAYS) matches observation-verification\'s "terminal plus 30 days" and the data model\'s "terminal plus configured window, default 30 days". Expiry revokes endpoint access only in all three, so the evidence-vs-access separation invariant is not weakened.',
  },
  {
    axis: "settled-body-phases",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["complete-path-adjudication", "expected-artifact-surfaces-freeze"],
    governingConcerns: ["landing-proof", "machine-manifests"],
    docCitations: [
      "observation-verification verdict vocabulary",
      "canonical-fields settled-body table",
      "data-model attempt_phase domain",
    ],
    closure:
      "Settled-body bytes are clean: the ledger text sequence {inner, step_1_signature, step_2_signature} is identical in SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE and the canonical-fields appendix, and observation-verification carries the frozen complete-path verdict vocabulary — byte-contract material read, never rewritten. Phase half: OPERATION_TRANSACTION_PHASES deep-equals the data model's attempt_phase CHECK domain in sequence and borrows no public execution_phase values (NOT_STARTED/SUBMITTED/LANDED).",
  },
  {
    axis: "idempotency-length",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["auth-401-collapse"],
    governingConcerns: ["route-policy", "credential-matrix"],
    docCitations: ["api-contract idempotency rules", "data-model idempotency_key CHECKs"],
    closure:
      "IDEMPOTENCY_KEY_CONTRACT (16–255, code points 0x21–0x7e) matches the api contract and the data model's `^[!-~]{16,255}$`. The operations table carried the weaker `length(idempotency_key) BETWEEN 1 AND 255` — a schema that accepted keys the wire contract rejects; reconciled to the canonical regex. Every POST in ROUTE_POLICIES requires an Idempotency-Key.",
  },
  {
    axis: "discovery",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["three-generic-operations", "compatibility-literals"],
    governingConcerns: ["api-schema", "compat-literals"],
    docCitations: ["api-contract discovery endpoint"],
    closure:
      "DISCOVERY_PATH, all nine DISCOVERY_RESPONSE_FIELDS, and all five DISCOVERY_EXCLUSIONS resolve one-for-one against the api contract's discovery prose under snake_case normalisation, in the doc's own sequence. The `zupay` literal is retained per the compatibility-literal preservation rule.",
  },
  {
    axis: "subscription-handles",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["auth-401-collapse", "three-generic-operations"],
    governingConcerns: ["route-policy", "operations"],
    docCitations: ["api-contract auth modes", "api-contract subscription stream"],
    closure:
      "The single subscription route (GET /v1/operations/:operation_id/subscribe) carries the subscription-handle auth mode in both independently frozen route sets (ROUTE_POLICIES and PUBLIC_ROUTES) and in the api contract; no other route accepts a handle, and the handle authorises no raw body, arm, or verification-complete.",
  },
  {
    axis: "signer-audit",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["vault-storage-model"],
    governingConcerns: ["vault"],
    docCitations: ["signing-custody-security signer boundary", "data-model audit_log"],
    closure:
      "SIGNER_BOUNDARY's two signing purposes (SPLITCHAIN_STEP_1/STEP_2) and its never-returns-private-key rule appear in the signing-custody-security spec; the audit surface is the single append-only `audit_log` of the data model — no second signer-audit table or field spelling exists.",
  },
  {
    axis: "callbacks",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["no-network-egress", "reporting-channel"],
    governingConcerns: ["no-callback"],
    docCitations: ["api-contract delivery model", "operation-flows delivery sections"],
    closure:
      "The no-callback rule's three mandatory strike sites are landed: the api contract and both operation-flow sections each state no node-initiated callback or push channel exists and name the signed pull stream as sole delivery. No node-initiated callback property survives in any numbered generic-node spec; the remaining product-layer references live in the integration docs, which the rule explicitly permits.",
  },
  {
    axis: "pool-membership",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["receive-pool-sizing-freeze", "recovery-gate-rule"],
    governingConcerns: ["pool-policy", "custody"],
    docCitations: ["data-model wallet_state enum", "data-model receive-eligibility predicate"],
    closure:
      "POOL_WALLET_STATES and the custody concern's WALLET_STATES are the same four-value sequence and equal the data model's wallet_state enum; receive-eligibility is node_generated AND recovery_verified_at IS NOT NULL AND state='AVAILABLE', matching the recovery-gate rule with no blessing conjunct.",
  },
  {
    axis: "bearer-admin-storage",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["auth-401-collapse", "three-generic-operations"],
    governingConcerns: ["route-policy", "api-schema"],
    docCitations: ["api-contract auth scopes"],
    closure:
      "All eight IMPLEMENTER_SCOPES and all six BEARER_KEY_EXCLUSIONS resolve in the api contract's scope list; every scope named by a frozen route policy is one of the eight, and no bearer-scoped route reaches an excluded capability. Handles are stored hashed and the operator surface is session+CSRF — three distinct storage rules, no overlap.",
  },
  {
    axis: "totp-burns",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["single-approval-single-sign-rule", "auth-401-collapse"],
    governingConcerns: ["approval", "route-policy"],
    docCitations: ["api-contract auth step-up", "api-contract admin routes"],
    closure:
      "The admin routes whose frozen authMode requires TOTP are exactly the api-contract bullets that require `X-ZP-TOTP`/fresh TOTP (approve, reject, bless, recovery-actions); destination retire requires neither, in both. TOTP_HEADER_NAME matches the api contract, which states the burn is consumed atomically and does not sign bytes — the TOTP-never-signs invariant is intact.",
  },
  {
    axis: "canonical-ledger",
    status: "CLOSED_AUTOMATED",
    decisionRefs: ["observation-dedup", "complete-path-adjudication"],
    governingConcerns: ["observation", "landing-proof"],
    docCitations: ["data-model retention matrix", "observation-verification retention rules"],
    closure:
      "The data model's canonical-wallet-ledger row is `permanent, verbatim` / `append-only`, matching RETENTION_RULE.append_only and observation-verification's permanent list (canonical settled transaction text). Proof-access expiry revokes access only in both — the separation of evidence from access holds.",
  },
  {
    axis: "candidate-intake",
    status: "CLOSED_AUTOMATED",
    decisionRefs: [
      "gateway-transport-contract",
      "sender-head-settlement-confirmation-rule",
      "receive-expiry-prevention-rule",
    ],
    governingConcerns: ["transfer-code", "wallet-state"],
    docCitations: ["operation-flows candidate intake", "protocol-foundation transport"],
    closure:
      "CANDIDATE_RAW_CAPTURE_FIELDS and CANDIDATE_LOCATE_KEYS resolve verbatim in the operation-flows candidate-intake section, which also carries the unarmed-refusal and single-winner rules the frozen booleans assert. The intake adapter is not a fourth public money operation in either side, so the three-generic-operation rule is not widened.",
  },
];

/**
 * The four foundational contract freezes the disposition record singles out.
 *
 * `decisionRefs` reproduce each freeze's own governing rules; nothing is re-derived. Each
 * row's closure still ends in a `Remaining:` clause naming test/golden work that this record
 * does NOT close — a disposition here can never be mistaken for that work being finished.
 */
export interface BlockerDisposition {
  readonly id: string;
  readonly decisionRefs: readonly string[];
  readonly finalDisposition: string;
}

export const BLOCKER_DISPOSITIONS: readonly BlockerDisposition[] = [
  {
    id: "amount-contract",
    decisionRefs: ["zkz-amount-grammar"],
    finalDisposition:
      "Amount contract closed — exclusive upper bound `< 100000000`, ≤32 dp, ROUND_DOWN, canonical decimal text with two CHECK domains. Remaining: boundary/overflow goldens stay open, tracked with the amounts concern.",
  },
  {
    id: "vault-contract",
    decisionRefs: ["vault-storage-model", "vault-aad-hkdf-encoding-freeze"],
    finalDisposition:
      "Vault contract closed (per-wallet AES-256-GCM envelope rows, table `vault`, PK `wallet_id`, `key_version`, per-wallet HKDF, reconstructed AAD, no stored AAD column), refined by the frozen AAD/HKDF byte encodings. Remaining: threat/rotation/restore tests stay open, tracked with the vault concern.",
  },
  {
    id: "reporting-credential",
    decisionRefs: [
      "reporting-channel",
      "reporting-key-enrolment",
      "bootstrap-enrolment-trust-root",
    ],
    finalDisposition:
      "Reporting credential closed (Ed25519-only two-key pull contract, gapless pre-signed sequence, ≤60 s window, single-use nonce, overlap rotation, no HMAC/bearer), with the `zp-reporting-register-v1` enrolment tuple frozen and the bootstrap trust-root made permanent. Remaining: cross-impl goldens stay open.",
  },
  {
    id: "receive-pool",
    decisionRefs: ["receive-pool-sizing-freeze"],
    finalDisposition:
      "Receive pool closed — POOL_FLOOR=5, pool_cap default 50 / ceiling 500, cap counts all non-deleted rows including RETIRED, MINT_BATCH_LIMIT=5, fail-closed FIFO queue with RECEIVE_QUEUE_MAX_WAIT=30 s, logical retirement only. Remaining: capacity tables and pressure tests stay open, tracked with the pool-policy concern.",
  },
];
