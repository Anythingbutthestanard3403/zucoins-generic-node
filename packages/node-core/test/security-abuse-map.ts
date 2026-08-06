// Security & abuse suite binding map.
// Each row binds one required abuse item — a security item, a raw-capture item, an
// operation-predicate item, a canonical-field negative vector, or an operator-boundary
// token — to:
//   1. the threat-control-map control row(s) it exercises, and
//   2. existence-checked proof files whose contents must contain load-bearing
//      negative-path markers.
//
// Governing: signing custody; observation verification; canonical fields; operations
// recovery; the API contract; the threat-control map. Verification is local-only.

export type AbuseProofRef = {
  /** Repo-root-relative path to a proof (test or enforcing source). */
  readonly path: string;
  /** Substrings that must appear — each is a load-bearing negative assertion. */
  readonly mustContain: readonly string[];
};

export type AbuseRow = {
  readonly id: string;
  readonly title: string;
  /** Attack categories used for the no-orphan census. */
  readonly categories: readonly AbuseCategory[];
  /** Threat-control-map rows (1–16) this abuse item exercises. Empty when residual. */
  readonly threatMapRows: readonly number[];
  readonly proofs: readonly AbuseProofRef[];
};

export type AbuseCategory =
  | "auth"
  | "parser"
  | "concurrency"
  | "secret"
  | "endpoint"
  | "privilege"
  | "operator"
  | "observation"
  | "gateway"
  | "recovery"
  | "custody"
  | "signer"
  | "lease"
  | "approval"
  | "totp"
  | "ssrf"
  | "event";

/** signing custody items 1–27 (spec lists 1–20 then continues 21–27). */
export const SECURITY_ABUSE_ROWS: readonly AbuseRow[] = [
  {
    id: "SECURITY-01",
    title: "signer rejects missing/wrong-operation/wrong-role/stale-epoch lease capability",
    categories: ["auth", "signer", "lease"],
    threatMapRows: [1],
    proofs: [
      {
        path: "packages/node-core/test/signer-boundary.test.ts",
        mustContain: ["no lease", "operation mismatch", "epoch"],
      },
      {
        path: "packages/node-core/test/custody-attack-suite.test.ts",
        mustContain: ["cannot be signed", "fail"],
      },
    ],
  },
  {
    id: "SECURITY-02",
    title: "source/destination move lease races cannot deadlock or partially acquire",
    categories: ["concurrency", "lease"],
    threatMapRows: [1],
    proofs: [
      {
        path: "packages/node-core/test/lease-foundation.census.test.ts",
        mustContain: ["wallet_active_leases", "CREATE TABLE wallet_active_leases"],
      },
      {
        path: "packages/node-core/src/schema/lease-foundation.sql",
        mustContain: ["wallet_active_leases"],
      },
    ],
  },
  {
    id: "SECURITY-03",
    title: "private-key buffers and TOTP secrets never appear in DB/logs/errors/metrics/events",
    categories: ["secret", "custody", "totp"],
    threatMapRows: [2, 16],
    proofs: [
      {
        path: "packages/node-core/test/safe-log-redaction.test.ts",
        mustContain: ["redact", "secret"],
      },
      {
        path: "packages/node-core/src/schema/vault.sql",
        mustContain: ["ciphertext", "nonce", "auth_tag"],
      },
      {
        path: "packages/node-core/test/backup-archive.test.ts",
        mustContain: ["ciphertext", "private"],
      },
    ],
  },
  {
    id: "SECURITY-04",
    title: "vault AAD/ciphertext/master-key/public-private mismatch fail closed",
    categories: ["endpoint", "custody", "signer"],
    threatMapRows: [2, 3],
    proofs: [
      {
        path: "packages/node-core/test/custody-attack-suite.test.ts",
        mustContain: ["AAD", "fail"],
      },
      {
        path: "packages/node-core/test/vault.test.ts",
        mustContain: ["AAD", "fail"],
      },
    ],
  },
  {
    id: "SECURITY-05",
    title: "imported wallet destination insertion fails at DB and service boundaries",
    categories: ["custody", "endpoint"],
    threatMapRows: [6],
    proofs: [
      {
        path: "packages/node-core/test/custody-attack-suite.test.ts",
        mustContain: ["imported"],
      },
      {
        path: "packages/node-core/test/custody-eligibility.census.test.ts",
        mustContain: ["AUTOMATIC_SINK_CONJUNCTS", "recovery_verified"],
      },
    ],
  },
  {
    id: "SECURITY-06",
    title: "recovery-unverified blessed destination never selected automatically",
    categories: ["custody", "recovery"],
    threatMapRows: [6],
    proofs: [
      {
        path: "packages/node-core/test/custody-eligibility.census.test.ts",
        mustContain: ["recovery_verified"],
      },
      {
        path: "packages/generic-node-contracts/src/custody/predicates.contract.ts",
        mustContain: ["AUTOMATIC_SINK_CONJUNCTS"],
      },
    ],
  },
  {
    id: "SECURITY-07",
    title: "every purpose verifies only under its exact key class and literal purpose",
    categories: ["auth", "parser", "signer"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/test/protocol-suite-census.test.ts",
        mustContain: ["keyClass", "purpose"],
      },
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["cross-purpose", "rejected"],
      },
    ],
  },
  {
    id: "SECURITY-08",
    title: "canonical field reorder/omission/null/Unicode/newline/numeric substitution invalidates signature",
    categories: ["parser"],
    threatMapRows: [11, 13],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["field reorder", "rejected"],
      },
      {
        path: "packages/node-core/src/verifier/transaction-verify.test.ts",
        mustContain: ["fail", "preimage"],
      },
    ],
  },
  {
    id: "SECURITY-09",
    title: "TOTP-only approval binds one guarded immutable mutation without device signature",
    categories: ["approval", "totp", "auth"],
    threatMapRows: [7, 10],
    proofs: [
      {
        path: "packages/node-core/test/csrf-totp-chain.test.ts",
        mustContain: ["TOTP", "reject"],
      },
      {
        path: "packages/generic-node-contracts/src/approval/sign-intent.census.test.ts",
        mustContain: ["approval", "intent"],
      },
    ],
  },
  {
    id: "SECURITY-10",
    title: "additive device policy requires both valid TOTP and valid device signature",
    categories: ["approval", "totp", "auth"],
    threatMapRows: [10, 11],
    proofs: [
      {
        path: "packages/node-core/test/device-recovery-threat.test.ts",
        mustContain: ["device", "reject"],
      },
      {
        path: "packages/generic-node-contracts/src/approval/approval-tuple.census.test.ts",
        mustContain: ["device", "purpose"],
      },
    ],
  },
  {
    id: "SECURITY-11",
    title: "TOTP is burned on signer/DB/delivery/gateway failure and cannot be replayed",
    categories: ["totp", "auth", "concurrency"],
    threatMapRows: [10],
    proofs: [
      {
        path: "packages/node-core/test/csrf-totp-chain.test.ts",
        mustContain: ["replay", "TOTP"],
      },
      {
        path: "packages/node-core/src/schema/approval-stores.sql",
        mustContain: ["operation_approvals_totp_single_use", "totp_timestep"],
      },
    ],
  },
  {
    id: "SECURITY-12",
    title: "crash at every external-formation boundary yields no partial or the exact one persisted",
    categories: ["recovery", "signer"],
    threatMapRows: [7, 8],
    proofs: [
      {
        path: "packages/node-core/test/send-crash-recovery.test.ts",
        mustContain: ["partial", "crash"],
      },
      {
        path: "packages/node-core/test/crash-replay.exactness.test.ts",
        mustContain: ["preimage", "exact"],
      },
    ],
  },
  {
    id: "SECURITY-13",
    title: "persisted/delivered/expired partial can never be replaced under the old approval",
    categories: ["recovery", "approval"],
    threatMapRows: [8, 9],
    proofs: [
      {
        path: "packages/node-core/test/external-send-partial-uniqueness.pg.test.ts",
        mustContain: ["partial", "operation_id"],
      },
      {
        path: "packages/node-core/test/crash-replay.exactness.test.ts",
        mustContain: ["immutable", "partial"],
      },
    ],
  },
  {
    id: "SECURITY-14",
    title: "SEND_EXTERNAL code paths contain no gateway submit dependency",
    categories: ["gateway", "endpoint", "operator"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/core/receive-submit-once.ts",
        mustContain: ["submit"],
      },
      {
        path: "packages/node-core/src/send/landing-verify.ts",
        mustContain: ["no retry", "ACK"],
      },
    ],
  },
  {
    id: "SECURITY-15",
    title: "gateway ack + unchanged/unrelated/regressed/malformed/unverifiable head does not settle",
    categories: ["gateway", "observation"],
    threatMapRows: [12, 13],
    proofs: [
      {
        path: "packages/node-core/src/protocol/reconcile/landing-adjudicator.test.ts",
        mustContain: ["INDETERMINATE", "REJECTED"],
      },
      {
        path: "packages/node-core/src/send/landing-verify.ts",
        mustContain: ["ACK", "INDETERMINATE"],
      },
    ],
  },
  {
    id: "SECURITY-16",
    title: "node event alone cannot set platform trusted state",
    categories: ["event", "observation", "privilege"],
    threatMapRows: [14],
    proofs: [
      {
        path: "packages/node-core/src/reporting/event-verifier.test.ts",
        mustContain: ["reject", "event"],
      },
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["fail", "reject"],
      },
    ],
  },
  {
    id: "SECURITY-17",
    title: "platform observer endpoint/config independent from node-supplied material",
    categories: ["observation", "gateway", "ssrf"],
    threatMapRows: [5, 14],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/instruction-origin/identity-pin.census.test.ts",
        mustContain: ["substitution", "reject"],
      },
      {
        path: "packages/generic-node-contracts/src/instruction-origin/identity-pin.contract.ts",
        mustContain: ["verifyIdentityPin"],
      },
    ],
  },
  {
    id: "SECURITY-18",
    title: "any-depth ancestor fixtures accept only complete gap-free exact-body paths",
    categories: ["observation", "gateway", "recovery"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/verifier/landing-path-oracle.test.ts",
        mustContain: ["LANDED_COMPLETE_PATH", "INDETERMINATE"],
      },
      {
        path: "packages/node-core/src/verifier/landing-path-oracle.ts",
        mustContain: ["LANDED_DIRECT_SUCCESSOR shortcut is not used"],
      },
    ],
  },
  {
    id: "SECURITY-19",
    title: "customer instruction verification fails when node identity key differs from independent pin",
    categories: ["ssrf", "auth", "privilege"],
    threatMapRows: [5],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/instruction-origin/identity-pin.census.test.ts",
        mustContain: ["fingerprint_mismatch", "pubkey_mismatch"],
      },
    ],
  },
  {
    id: "SECURITY-20",
    title: "live-chain tests subject to dual control and external amount cap",
    categories: ["operator", "recovery"],
    threatMapRows: [],
    proofs: [
      {
        path: "packages/node-core/test/live-chain/types.ts",
        mustContain: ["never a private key"],
      },
    ],
  },
  {
    id: "SECURITY-21",
    title: "wrong-key-state/cross-tenant/malformed/wrong-body/bad-sig reporting requests create no nonce row",
    categories: ["auth", "parser", "event"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["nonce", "reject"],
      },
    ],
  },
  {
    id: "SECURITY-22",
    title: "concurrent admit/rotate/revoke lock restore state + one lifecycle head",
    categories: ["concurrency", "auth"],
    threatMapRows: [1, 10],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite-lifecycle.test.ts",
        mustContain: ["overlap", "rejects"],
      },
    ],
  },
  {
    id: "SECURITY-23",
    title: "reporting schema rejects private-key/seed/secret/vault-reference fields",
    categories: ["secret", "parser", "event"],
    threatMapRows: [16],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["private", "reject"],
      },
    ],
  },
  {
    id: "SECURITY-24",
    title: "event/head projection mismatch and illegal transitions rejected",
    categories: ["event", "observation"],
    threatMapRows: [14],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite-events.test.ts",
        mustContain: ["reject", "event"],
      },
    ],
  },
  {
    id: "SECURITY-25",
    title: "bootstrap/rotation key-binding mismatch and overlong lifetime rejected",
    categories: ["auth", "recovery"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite-lifecycle.test.ts",
        mustContain: ["reject", "rotat"],
      },
    ],
  },
  {
    id: "SECURITY-26",
    title: "mutation evidence mismatch / retention downgrade / incomplete evidence rejected",
    categories: ["observation", "recovery"],
    threatMapRows: [13, 14],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["evidence", "reject"],
      },
    ],
  },
  {
    id: "SECURITY-27",
    title: "restore_hold or lifecycle auth_hold rejects admission",
    categories: ["auth", "recovery", "operator"],
    threatMapRows: [1],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite-lifecycle.test.ts",
        mustContain: ["hold", "reject"],
      },
    ],
  },
] as const;

/** observation verification raw capture and dedup (7). */
export const CAPTURE_ABUSE_ROWS: readonly AbuseRow[] = [
  {
    id: "CAPTURE-01",
    title: "exact byte-identical verified A,A appends once and increments sighting",
    categories: ["observation", "gateway"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/src/observation/dedup.property.test.ts",
        mustContain: ["exact bytes are authority", "appends"],
      },
    ],
  },
  {
    id: "CAPTURE-02",
    title: "same head with whitespace or key reordering appends twice as EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    categories: ["observation", "parser"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/src/schema/base-enums-domains.contract.ts",
        mustContain: ["EQUIVALENT_STATE_DIFFERENT_ENVELOPE"],
      },
      {
        path: "packages/node-core/src/observation/quarantine.test.ts",
        mustContain: ["EQUIVALENT_STATE_DIFFERENT_ENVELOPE"],
      },
    ],
  },
  {
    id: "CAPTURE-03",
    title: "A,B,C,A four-append; final A is REGRESSION and quarantines",
    categories: ["observation", "gateway"],
    threatMapRows: [12, 13],
    proofs: [
      {
        path: "packages/node-core/src/observation/quarantine.test.ts",
        mustContain: ["REGRESSION", "quarantine"],
      },
      {
        path: "packages/node-core/src/observation/dedup.property.test.ts",
        mustContain: ["REGRESSION"],
      },
    ],
  },
  {
    id: "CAPTURE-04",
    title: "identical malformed response twice appends twice with two anomalies",
    categories: ["observation", "gateway"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/src/gateway/capture.test.ts",
        mustContain: ["sha256", "bytes"],
      },
    ],
  },
  {
    id: "CAPTURE-05",
    title: "digest collision simulation still performs exact byte comparison",
    categories: ["observation", "parser"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/src/gateway/capture.test.ts",
        mustContain: ["byte", "sha256"],
      },
    ],
  },
  {
    id: "CAPTURE-06",
    title: "concurrent reads of one stream receive contiguous unique wallet_seq",
    categories: ["concurrency", "observation"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/test/observation-ledger.census.test.ts",
        mustContain: ["observation_relationship", "sequence included"],
      },
    ],
  },
  {
    id: "CAPTURE-07",
    title: "same response in node and platform ledgers is two independent observations",
    categories: ["observation", "event"],
    threatMapRows: [14],
    proofs: [
      {
        path: "packages/node-core/src/schema/observation-ledger.sql",
        mustContain: ["gateway_observations"],
      },
    ],
  },
] as const;

/** observation verification operation predicates (9). */
export const PREDICATE_ABUSE_ROWS: readonly AbuseRow[] = [
  {
    id: "PREDICATE-01",
    title: "receive accepts exact previous_step_2 == S0 and exact B1-B0",
    categories: ["observation", "custody"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/verifier/landing-path-oracle.test.ts",
        mustContain: ["proveReceiveLanding", "amount"],
      },
    ],
  },
  {
    id: "PREDICATE-02",
    title: "move requires matching transaction signature on source/destination + exact dual delta",
    categories: ["observation", "concurrency"],
    threatMapRows: [1, 12],
    proofs: [
      {
        path: "packages/node-core/src/verifier/move-path-verify.test.ts",
        mustContain: ["failures", "delta"],
      },
    ],
  },
  {
    id: "PREDICATE-03",
    title: "spawned move requires previous_step_1 == parent_receive.step_2_signature",
    categories: ["observation", "lease"],
    threatMapRows: [1],
    proofs: [
      {
        path: "packages/node-core/test/child-move-create.test.ts",
        mustContain: ["parent", "rejects when parent receive has not landed"],
      },
    ],
  },
  {
    id: "PREDICATE-04",
    title: "send requires persisted partial identity, source delta, destination binding, valid recipient step 2",
    categories: ["observation", "approval"],
    threatMapRows: [8, 9],
    proofs: [
      {
        path: "packages/node-core/src/send/landing-verify.test.ts",
        mustContain: ["verifyExternalSendLanding", "partial"],
      },
    ],
  },
  {
    id: "PREDICATE-05",
    title: "node acknowledgement without accepted head never lands any operation",
    categories: ["gateway", "observation"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/send/landing-verify.ts",
        mustContain: ["ACK", "cannot land"],
      },
      {
        path: "packages/node-core/src/protocol/reconcile/landing-adjudicator.test.ts",
        mustContain: ["INDETERMINATE", "never not-landed"],
      },
    ],
  },
  {
    id: "PREDICATE-06",
    title: "unchanged/gap/regression/malformed/unrelated heads create no blind-retry authority",
    categories: ["gateway", "recovery", "operator"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/send/landing-verify.ts",
        mustContain: ["no retry", "INDETERMINATE"],
      },
      {
        path: "packages/node-core/src/operator/recovery-inspection.ts",
        mustContain: ["RETRY_SUBMIT"],
      },
    ],
  },
  {
    id: "PREDICATE-07",
    title:
      "direct-successor settlement requires every guard; the unsupported one-hop LANDED_DIRECT_SUCCESSOR shortcut is rejected",
    categories: ["observation", "gateway"],
    threatMapRows: [12, 15],
    proofs: [
      {
        path: "packages/node-core/src/send/buried-unknown-completions.test.ts",
        mustContain: ["LANDED_DIRECT_SUCCESSOR", "one-hop"],
      },
      {
        path: "packages/node-core/src/send/landing-verify.ts",
        mustContain: ["unrecognized path proof kind"],
      },
      {
        path: "packages/node-core/src/schema/send-external-landing.contract.ts",
        mustContain: ["LANDED_DIRECT_SUCCESSOR shortcut has no representation"],
      },
    ],
  },
  {
    id: "PREDICATE-08",
    title: "two-hop complete path yields LANDED_COMPLETE_PATH; missing intermediate → INDETERMINATE",
    categories: ["observation"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/node-core/src/verifier/landing-path-oracle.test.ts",
        mustContain: ["LANDED_COMPLETE_PATH", "GAP"],
      },
    ],
  },
  {
    id: "PREDICATE-09",
    title: "node event without platform direct observation cannot set trusted business state",
    categories: ["event", "observation"],
    threatMapRows: [14],
    proofs: [
      {
        path: "packages/node-core/src/reporting/event-verifier.test.ts",
        mustContain: ["reject"],
      },
    ],
  },
] as const;

/** canonical fields required negative vectors (1–17 general) + reporting-register specifics. */
export const CANONICAL_FIELD_NEGATIVE_ROWS: readonly AbuseRow[] = [
  {
    id: "NEGATIVE-01",
    title: "field reorder / missing / unexpected / omitted-instead-of-null",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["field reorder", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-02",
    title: "prefix purpose / payload purpose mismatch",
    categories: ["parser", "auth"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["purpose mismatch", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-03",
    title: 'canonical_version as string "1" rejected',
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["A.9 #3", "canonical_version as string", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-04",
    title: "UUID uppercase / non-canonical spelling rejected",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["uppercase", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-05",
    title: "unpadded key/signature or invalid decoded length rejected",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["unpadded", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-06",
    title: "amount as JSON number / exponent / signed / leading-zero / >32 decimals rejected",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/verifier/transaction-verify.scalar-fuzz.test.ts",
        mustContain: ["amount", "reject"],
      },
    ],
  },
  {
    id: "NEGATIVE-07",
    title: "timestamp without exactly three fractional digits or Z rejected",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/verifier.ts",
        mustContain: ["issued_at", "fractional"],
      },
    ],
  },
  {
    id: "NEGATIVE-08",
    title: "newline/BOM/whitespace appended to preimage rejected",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/verifier.ts",
        mustContain: ["appended whitespace", "non-canonical byte layout"],
      },
    ],
  },
  {
    id: "NEGATIVE-09",
    title: "NFC/NFD substitution rejected (or byte-identity preserved without normalize-then-sign)",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/scripts/emit-receive-golden.ts",
        mustContain: ["NFC/NFD", "normalization"],
      },
    ],
  },
  {
    id: "NEGATIVE-10",
    title: "cross-purpose signature verification rejected",
    categories: ["parser", "auth"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["cross-purpose", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-11",
    title: "transfer-code hash after decode/padding repair rejected (exact input-string hash only)",
    categories: ["parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/scripts/emit-receive-golden.ts",
        mustContain: ["padding repair"],
      },
    ],
  },
  {
    id: "NEGATIVE-12",
    title: "reporting request method/path/body change or nonce replay rejected",
    categories: ["auth", "parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["nonce", "reject"],
      },
    ],
  },
  {
    id: "NEGATIVE-13",
    title: "TOTP accepted as if it were a tuple signature rejected",
    categories: ["totp", "auth", "parser"],
    threatMapRows: [10, 11],
    proofs: [
      {
        path: "packages/node-core/test/csrf-totp-chain.test.ts",
        mustContain: ["TOTP"],
      },
    ],
  },
  {
    id: "NEGATIVE-14",
    title: "device signature without mandatory fresh TOTP rejected",
    categories: ["totp", "auth", "approval"],
    threatMapRows: [10, 11],
    proofs: [
      {
        path: "packages/node-core/test/device-recovery-threat.test.ts",
        mustContain: ["TOTP", "reject"],
      },
    ],
  },
  {
    id: "NEGATIVE-15",
    title: "reconstruction of SplitChain preimages from JSONB rejected",
    categories: ["parser", "observation"],
    threatMapRows: [13],
    proofs: [
      {
        path: "packages/node-core/src/gateway/capture.ts",
        mustContain: ["raw", "bytes"],
      },
      {
        path: "packages/node-core/src/gateway/capture.test.ts",
        mustContain: ["exact response bytes", "sha256Hex"],
      },
    ],
  },
  {
    id: "NEGATIVE-16",
    title: "golden fixture key used when live-chain mode enabled rejected",
    categories: ["operator", "recovery"],
    threatMapRows: [],
    proofs: [
      {
        path: "packages/node-core/test/live-chain/types.ts",
        mustContain: ["never a private key"],
      },
    ],
  },
  {
    id: "NEGATIVE-17",
    title: "funded sender empty genesis predecessor rejected at preflight",
    categories: ["observation", "parser"],
    threatMapRows: [12],
    proofs: [
      {
        path: "packages/generic-node-contracts/scripts/emit-receive-golden.ts",
        mustContain: ["funded-sender-genesis-predecessor", "vector 17"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-01",
    title: "zp-reporting-register-v1: supersedes_key_id omitted instead of null rejected",
    categories: ["parser", "auth"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["supersedes_key_id omitted", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-02",
    title: "zp-reporting-register-v1: unpadded/wrong-length new_reporting_public_key rejected",
    categories: ["parser", "auth"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["unpadded", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-03",
    title: "zp-reporting-register-v1: enrolment window >300s rejected",
    categories: ["auth", "parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts",
        mustContain: ["enrolment window over 300", "rejected"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-04",
    title: "zp-reporting-register-v1: PoP by key other than in-tuple public key rejected",
    categories: ["auth", "parser"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/reporting-auth/verifier.ts",
        mustContain: ["new_reporting_public_key"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-05",
    title: "zp-reporting-register-v1: nonce replay for same (implementer_id, node_id) rejected",
    categories: ["auth", "concurrency"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite.test.ts",
        mustContain: ["nonce", "replay"],
      },
    ],
  },
  {
    id: "NEGATIVE-REG-06",
    title: "zp-reporting-register-v1: revoked or post-overlap key still accepted rejected",
    categories: ["auth", "recovery"],
    threatMapRows: [11],
    proofs: [
      {
        path: "packages/node-core/src/reporting/reporting-attack-suite-lifecycle.test.ts",
        mustContain: ["revok", "reject"],
      },
    ],
  },
] as const;

/** operations recovery — actions that must never exist on the operator surface. */
export const FORBIDDEN_OPERATOR_ACTIONS = [
  "RETRY_SUBMIT",
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "EDIT_TRANSACTION",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "REFORM_EXTERNAL_SEND",
  "NODE_SUBMIT_EXTERNAL_SEND",
  "DELETE_EVIDENCE",
  "SKIP_VERIFICATION",
] as const;

export const OPERATOR_BOUNDARY_PROOFS: readonly AbuseProofRef[] = [
  {
    path: "packages/node-core/src/operator/recovery-inspection.ts",
    mustContain: [...FORBIDDEN_OPERATOR_ACTIONS],
  },
  {
    path: "packages/node-core/src/operator/recovery-actions.ts",
    mustContain: ["FORCE_LANDED", "RETRY_SUBMIT", "SKIP_VERIFICATION"],
  },
  {
    path: "packages/generic-node-contracts/src/operator-halt/halt.census.test.ts",
    mustContain: ["RETRY_SUBMIT", "not.toContain"],
  },
  {
    path: "packages/node-core/src/protocol/reconcile/invariant-breach.test.ts",
    mustContain: ["FORCE_LANDED", "FORCE_RELEASE", "DELETE_EVIDENCE"],
  },
];

/** Web-surface / derived threat classes from the map. */
export const WEB_AND_DERIVED_ROWS: readonly AbuseRow[] = [
  {
    id: "WEB-SSRF",
    title: "SSRF / instruction-origin forgery rejected via independent pin + CORS defaults",
    categories: ["ssrf", "auth"],
    threatMapRows: [5],
    proofs: [
      {
        path: "packages/generic-node-contracts/src/instruction-origin/identity-pin.census.test.ts",
        mustContain: ["substitution", "reject"],
      },
      {
        path: "packages/node-core/test/security-headers.test.ts",
        mustContain: ["CORS", "CSP"],
      },
    ],
  },
  {
    id: "WEB-XSS",
    title: "XSS blocked by CSP / HttpOnly session cookies",
    categories: ["auth", "privilege"],
    threatMapRows: [],
    proofs: [
      {
        path: "packages/node-core/test/security-headers.test.ts",
        mustContain: ["CSP", "HttpOnly"],
      },
      {
        path: "packages/node-core/test/admin-session.test.ts",
        mustContain: ["session", "cookie"],
      },
    ],
  },
  {
    id: "WEB-CSRF",
    title: "CSRF mutations require CSRF token + fresh TOTP",
    categories: ["auth", "totp", "privilege"],
    threatMapRows: [10],
    proofs: [
      {
        path: "packages/node-core/test/csrf-totp-chain.test.ts",
        mustContain: ["CSRF", "TOTP"],
      },
      {
        path: "packages/node-core/test/admin-auth-abuse.test.ts",
        mustContain: ["reject", "auth"],
      },
    ],
  },
  {
    id: "RESOURCE-DOS",
    title: "DoS / backpressure: receive-pool hard caps + degraded mode",
    categories: ["endpoint", "operator"],
    threatMapRows: [],
    proofs: [
      {
        path: "packages/node-core/test/degraded-mode.fault.test.ts",
        mustContain: ["degraded", "fail"],
      },
      {
        path: "packages/node-core/src/operator/storage-backpressure.ts",
        mustContain: ["backpressure", "cap"],
      },
    ],
  },
  {
    id: "SUPPLY-CHAIN",
    title: "supply-chain: frozen-path / platform import forbidden in node-core",
    categories: ["privilege", "custody"],
    threatMapRows: [4],
    proofs: [
      {
        path: "packages/node-core/test/boundaries.test.ts",
        mustContain: ["apps/platform", "FORBIDDEN_DEPENDENCY_FRAGMENTS"],
      },
      {
        path: "packages/node-core/test/boundary-rules.ts",
        mustContain: ["FORBIDDEN_DEPENDENCY_FRAGMENTS", "apps/node", "apps/platform"],
      },
    ],
  },
] as const;

export const ALL_ABUSE_ROWS: readonly AbuseRow[] = [
  ...SECURITY_ABUSE_ROWS,
  ...CAPTURE_ABUSE_ROWS,
  ...PREDICATE_ABUSE_ROWS,
  ...CANONICAL_FIELD_NEGATIVE_ROWS,
  ...WEB_AND_DERIVED_ROWS,
];

/** Required threat classes — every one must have ≥1 non-orphan row. */
export const REQUIRED_THREAT_CLASSES = [
  "custody",
  "signer",
  "lease",
  "approval",
  "totp",
  "ssrf",
  "event",
  "observation",
  "gateway",
  "recovery",
] as const;

export type RequiredThreatClass = (typeof REQUIRED_THREAT_CLASSES)[number];
