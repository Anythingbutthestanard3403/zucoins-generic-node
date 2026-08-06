/**
 * This concern freezes the launch-deferral boundary: WALLET_IMPORT and IMPORTED_DRAIN (the pair
 * already frozen absent by ../operations/capabilities.contract.ts) form one indivisible future
 * feature, greenfield launch ships neither, and `key_origin='imported'` survives only as an
 * inert forward-compatibility placeholder until a separate cutover contract lands.
 * Data + pure verifiers only — no I/O, no scanner, no runtime logic.
 */

export const IMPORT_DRAIN_DEFERRAL = {
  wallet_import: "absent",
  imported_drain: "absent",
  jointly_deferred: true,
  activates_behavior: false,
} as const;

export const CUTOVER_GATE = {
  reserved_enum_value: "imported",
  launch_accepts_key_origins: ["node_generated"],
  jointly_deferred: ["WALLET_IMPORT", "IMPORTED_DRAIN"],
  activates_behavior: false,
  requires_explicit_cutover_decision: true,
  cutover_decision_ref: null,
  cutover_prerequisites: [
    "drain approval tuple", // contract-allow:launch-deferral-citation
    "two-wallet lease",
    "signing/submission state machine",
    "recovery tests",
    "threat-model update",
    "exact compatibility fixtures",
    "coordinated schema/API/security amendment",
    "live-chain acceptance authorization",
    "send-source-origin exclusion census — reject key_origin='imported' as an external-send source",
  ],
} as const;

export interface CommandEntry {
  readonly name: string;
  readonly verb: string;
}

/** Closed at zero for launch: no import- or removal-shaped command may join this surface pre-cutover. */
export const LAUNCH_COMMAND_SURFACE: readonly CommandEntry[] = [];

/**
 * The only writers permitted to persist a wallet's `key_origin` at launch, and the only value
 * each may write. Mirrors ../vault/interfaces.contract.ts's `SEALING_API` keyed-entry shape.
 */
export const SCHEMA_WRITER_SURFACE = {
  seed: { writerClass: "WalletSeedWriter", permitted_key_origins: ["node_generated"] },
  migration: { writerClass: "SchemaMigrationWriter", permitted_key_origins: ["node_generated"] },
  vault_writer: { writerClass: "VaultSealingWriter", permitted_key_origins: ["node_generated"] },
} as const;

export const FORBIDDEN_LAUNCH_CAPABILITY_VERBS = ["import", "drain"] as const; // contract-allow:launch-deferral-citation

/**
 * What a running node must independently re-assert at boot/runtime/CI so the launch-deferral
 * freeze cannot be silently bypassed by code that never reads this package.
 */
export const RUNTIME_OBLIGATIONS = [
  {
    obligation:
      "boot-time assertion: live registered route table is a subset of frozen PUBLIC_ROUTES ∪ ADMIN_ROUTES and contains no import-substring path",
    owner_phase: "node-core runtime",
  },
  {
    obligation: "database CHECK/trigger: execution paths write only key_origin='node_generated'",
    owner_phase: "custody enforcement",
  },
  {
    obligation:
      "dependency-boundary scan covers createRequire, require.resolve, and dynamic import()",
    owner_phase: "scan gates",
  },
] as const;

export const SOURCE = "launch-capability-deferral; system-overview launch scope; node-core launch capabilities" as const;
