/**
 * Drift-audit honesty ledger.
 *
 * `AUTOMATED_AXES` records exactly what this harness machine-verifies today (and what each axis
 * still defers). `AUDIT_RESIDUALS` records every drift axis NOT yet machine-checked, with
 * a one-line reason. Together they make the eventual freeze run honest: no axis is silently
 * assumed clean. The two sets are frozen data and are asserted disjoint + covering by
 * `audit-residuals.test.ts`.
 */

export interface AutomatedAxis {
  readonly axis: string;
  /** What is machine-verified green today. */
  readonly coverage: string;
  /** What this axis still defers to `AUDIT_RESIDUALS` (empty when fully covered). */
  readonly deferred: string;
}

export const AUTOMATED_AXES: readonly AutomatedAxis[] = [
  {
    axis: "event-type-set",
    coverage:
      "DURABLE_EVENTS (operations) equals NEUTRAL_EVENT_TYPES (reporting-tuples) equals the state-event reference's nine-value list, same sequence.",
    deferred: "",
  },
  {
    axis: "route-surface",
    coverage:
      "every frozen PUBLIC_ROUTES and ADMIN_ROUTES path literal is present in the api contract (declared-implies-documented).",
    deferred: "route-surface-reverse",
  },
  {
    axis: "retention-matrix",
    coverage:
      "the data model's retention section parses to a well-formed three-column retention matrix with a stable non-empty row set.",
    deferred: "retention-contract-linkage",
  },
  {
    axis: "field-name-drift",
    coverage:
      "the canonical-fields appendix's zp-node-event-v1 and zp-report-request-v1 field tables match NODE_EVENT_FIELD_ORDER and REPORT_REQUEST_FIELD_ORDER in sequence.",
    deferred: "field-tables-remaining",
  },

  // Fourteen of the fifteen scope-line axes were closed by automating their cross-document
  // diff; the attempt_phase domain restoration then closed `settled-body-phases` too, so all
  // fifteen are automated. Disposition rows live in `dispositions.ts`.
  {
    axis: "destination-label",
    coverage:
      "DESTINATION_STATES resolve in both the data model and the api contract, and the `label` property the api contract carries has a column in the destinations DDL.",
    deferred: "",
  },
  {
    axis: "terminal-timestamps",
    coverage:
      "the state-event reference's Terminal column equals TERMINAL_RECEIVE_STATES as a set, and the data model carries exactly one terminal-timestamp spelling (`terminal_at`).",
    deferred: "",
  },
  {
    axis: "evidence-role-names",
    coverage:
      "the observation-verification relationship table matches RELATIONSHIP_CLASSIFICATION_RULES in sequence (name + state_changed), and WALLET_OBSERVATION_ROLES resolve in the data model's CHECK domain.",
    deferred: "",
  },
  {
    axis: "proof-windows",
    coverage:
      "MANIFEST_RETENTION.accessWindowDefault resolves in observation-verification and the data model, and both state that expiry revokes access without deleting evidence.",
    deferred: "",
  },
  {
    axis: "idempotency-length",
    coverage:
      "IDEMPOTENCY_KEY_CONTRACT's derived `^[!-~]{16,255}$` domain matches every idempotency_key CHECK in the data model and the api contract; every frozen POST route requires an Idempotency-Key.",
    deferred: "",
  },
  {
    axis: "discovery",
    coverage:
      "DISCOVERY_PATH, all ten DISCOVERY_RESPONSE_FIELDS (in sequence) and all five DISCOVERY_EXCLUSIONS resolve against the api contract's discovery prose under snake_case normalisation.",
    deferred: "",
  },
  {
    axis: "subscription-handles",
    coverage:
      "ROUTE_POLICIES and PUBLIC_ROUTES name the same single subscription-handle route, and the api contract carries its hashed-storage and no-raw-material limits.",
    deferred: "",
  },
  {
    axis: "signer-audit",
    coverage:
      "SIGNER_BOUNDARY's purposes and no-key-return rule resolve in the signing-custody-security spec, and the audit surface is the data model's single append-only audit_log with its retention row.",
    deferred: "",
  },
  {
    axis: "callbacks",
    coverage:
      "the no-callback rule's three mandatory strike sites carry no surviving callback surface, both affected specs record the removal and name the signed pull stream as replacement, and no numbered core spec or canonical appendix mentions such a surface at all.",
    deferred: "",
  },
  {
    axis: "pool-membership",
    coverage:
      "POOL_WALLET_STATES equals the custody concern's WALLET_STATES and the data model's wallet_state enum in sequence; the receive-eligibility predicate is the recovery-gate rule's, without the blessing conjunct.",
    deferred: "",
  },
  {
    axis: "bearer-admin-storage",
    coverage:
      "all eight IMPLEMENTER_SCOPES and all six BEARER_KEY_EXCLUSIONS resolve in the api contract's scope list, and no frozen route policy invents a scope outside the closed set.",
    deferred: "",
  },
  {
    axis: "totp-burns",
    coverage:
      "the admin routes whose frozen authMode burns a TOTP are exactly the api contract's TOTP-requiring bullets, and TOTP_HEADER_NAME matches its non-signing step-up.",
    deferred: "",
  },
  {
    axis: "canonical-ledger",
    coverage:
      "the data model's canonical-wallet-ledger row is `permanent, verbatim` / `append-only`, matching RETENTION_RULE, and observation-verification keeps the settled text permanent past access expiry.",
    deferred: "",
  },
  {
    axis: "candidate-intake",
    coverage:
      "CANDIDATE_RAW_CAPTURE_FIELDS and CANDIDATE_LOCATE_KEYS resolve in the operation-flows candidate-intake section, including its capture-before-parse rule.",
    deferred: "",
  },
  {
    axis: "settled-body-phases",
    coverage:
      "SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE equals the canonical-fields appendix; observation-verification carries the complete-path verdict vocabulary; OPERATION_TRANSACTION_PHASES deep-equals the data model's attempt_phase CHECK domain.",
    deferred: "",
  },
] as const;

export interface AuditResidual {
  readonly axis: string;
  readonly reason: string;
}

/**
 * Un-automated drift axes. Each entry is a promise that the final freeze verdict must
 * discharge by hand (or by a later harness slice) — never a silent coverage claim.
 */
export const AUDIT_RESIDUALS: readonly AuditResidual[] = [
  {
    axis: "route-surface-reverse",
    reason:
      "doc-declared /v1 and /admin/v1 paths not present in the frozen route set need structured route extraction from the api-contract prose; forward direction only is automated.",
  },
  {
    axis: "retention-contract-linkage",
    reason:
      "the data model's retention-matrix category labels are prose, not 1:1 keyed to frozen retention-bearing contract data; row-level reconciliation is manual.",
  },
  {
    axis: "field-tables-remaining",
    reason:
      "canonical-fields tuple tables beyond node-event and report-request (register, expected artifacts, approval, fingerprint) are not yet cross-checked against their frozen field sequences.",
  },
  {
    axis: "provisional-manifest-migration",
    reason:
      "some concerns still carry provisional manifest shapes; their frozen facts are enumerated but not audited under the canonical ConcernManifest contract until migrated.",
  },
] as const;
