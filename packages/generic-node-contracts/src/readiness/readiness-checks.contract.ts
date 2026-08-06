/**
 * SOURCE: the node-core leadership section (runtime components + the readiness sentence) and
 * the operations-recovery boot-recovery section (boot recovery, degraded operation), reconciled to
 * the readiness-leadership decoupling rule (canonical: readiness is decoupled from signer-lock ownership).
 *
 * the named concern freezes the readiness CONTRACT: the closed set of readiness checks, which checks
 * gate the ready verdict and which are reported-only, and — for every check — its single
 * stamping authority and its assertion scope (what it asserts and what it explicitly does NOT
 * assert). CONTRACT_FREEZE: frozen data + pure verifiers only; no endpoint, no probe, no I/O.
 */

/** A readiness check as frozen data. `gating` decides whether it participates in the ready verdict. */
export interface ReadinessCheck {
  readonly id: string;
  readonly gating: boolean;
  readonly stampingAuthority: string;
  readonly asserts: string;
  readonly doesNotAssert: readonly string[];
}

/**
 * The closed readiness-check set. Every check names exactly one stamping authority (the only
 * component allowed to set its boolean) and an assertion scope. This structurally removes the
 * v1 `checks.gateway`-stays-false ambiguity (the readiness-leadership decoupling rule/the readiness-leadership decoupling rule): a check can only be false because
 * its single named authority has not stamped it true, never because no authority owns it.
 */
export const READINESS_CHECKS = [
  {
    id: "schema_migrated",
    gating: true,
    stampingAuthority: "MIGRATION_RUNNER",
    asserts: "the persistent schema is at the frozen expected migration version",
    doesNotAssert: [
      "signer leadership is held by this instance",
      "the gateway is reachable",
      "money engines are running",
    ],
  },
  {
    id: "database_reachable",
    gating: true,
    stampingAuthority: "DATABASE_HEALTH_PROBE",
    asserts: "the primary database answers a health query",
    doesNotAssert: ["signer leadership is held by this instance", "the gateway is reachable"],
  },
  {
    id: "vault_available",
    gating: true,
    stampingAuthority: "VAULT_KEY_RING_LOADER",
    asserts: "the boot key-ring is loaded and the vault census is verified",
    doesNotAssert: [
      "signer leadership is held by this instance",
      "a specific wallet lease is owned",
    ],
  },
  {
    id: "observation_read_capable",
    gating: true,
    stampingAuthority: "OBSERVATION_SERVICE",
    asserts: "a validated gateway read succeeded inside the configured failure budget",
    doesNotAssert: ["signer leadership is held by this instance", "any transaction has landed"],
  },
  {
    id: "signer_leadership",
    gating: false,
    stampingAuthority: "LEADERSHIP_LOCK_MANAGER",
    asserts: "this instance currently holds the single process-wide signer leadership lock",
    doesNotAssert: [
      "the node is ready to serve read and admin traffic",
      "a wallet may be signed for without its own C-02 lease",
    ],
  },
] as const satisfies readonly ReadinessCheck[];

export type ReadinessCheckId = (typeof READINESS_CHECKS)[number]["id"];

export const GATING_CHECK_IDS = READINESS_CHECKS.filter((check) => check.gating).map(
  (check) => check.id,
) as readonly ReadinessCheckId[];

export const NON_GATING_CHECK_IDS = READINESS_CHECKS.filter((check) => !check.gating).map(
  (check) => check.id,
) as readonly ReadinessCheckId[];

/**
 * The named concern reconciliation as frozen fact. The v2 draft docs gate readiness on signer
 * leadership; the readiness-leadership decoupling rule (canonical, overrides the proposal) decouples them. These booleans record
 * the resolved semantics; RECONCILIATION below records the superseded draft clauses verbatim.
 */
export const READINESS_LEADERSHIP_SEPARATION = {
  readiness_requires_leadership: false,
  signing_requires_leadership: true,
  leadership_is_node_level_writer_role: true,
  leadership_is_wallet_sequencing_authority: false,
  liveness_may_be_true_while_readiness_false: true,
} as const;

/**
 * The explicit draft-vs-canonical record. Consumed by the census test so the reconciliation is
 * asserted, not merely commented. the readiness-leadership decoupling rule governs on conflict (the decoupling rule is canonical).
 */
export const RECONCILIATION = {
  canonical: "startup-sequence",
  supersedes_draft_clauses: [
    "node-core draft: readiness is false until signer leadership is held by exactly one instance",
    "operations-recovery draft boot step: report readiness only when exactly one signer leader is active",
    "operations-recovery draft degraded mode: readiness is false when the signer is unavailable",
  ],
  resolution:
    "readiness gates on schema, database, vault, and observation checks only; signer_leadership is a reported non-gating check",
  reason: "coupling readiness to leadership re-introduces the overlap-deploy deadlock the decoupling rule fixed",
} as const;
