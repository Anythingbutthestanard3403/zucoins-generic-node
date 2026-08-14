# Custody predicates — CONTRACT_FREEZE

This concern freezes the `custody-classification-policy`, with the `custody-evidence-requirements`
and `custody-binding-obligations` recovery gate kept binding. It is contract data and a pure
verifier only: no keys, database writes, signing, submission, or ZKZ movement occurs here.

Internal custody is exactly `key_origin = node_generated` and destination state `BLESSED`.
Recovery status never changes that classification. Automatic-sink eligibility additionally requires a
present, parseable `recovery_verified_at` and wallet state `AVAILABLE` or `PINNED`. Imported, missing,
unknown, malformed, quarantined, retired, and future values fail closed.

`WORKER` is a node-owned send-worker sink, not internal custody. It is admitted by the send
scaler, never by the blessing ceremony. Worker-sink eligibility is `key_origin = node_generated`
plus destination state `WORKER` plus wallet state `AVAILABLE` or `PINNED` — no recovery stamp,
no blessing artifact. Composition top-up may land on either an automatic sink or a worker sink.
Client-facing `MOVE_INTERNAL` / `after_landing` stay automatic-sink only.

`CUSTODY_EVIDENCE_REQUIREMENTS` freezes what origin, blessing, and audited-recovery evidence must prove.
`CUSTODY_BINDING_OBLIGATIONS` separately freezes immutability, structural rejection, monotonic recovery,
execution-time recheck, and fail-closed obligations. Neither is represented by caller-supplied booleans;
the verifier accepts only authoritative raw wallet and destination facts.

Authority: the freeze gate's custody rule, the data model's custody section, and signing custody.
The `.contract.ts` source is authority; `gen/custody.json` is a deterministic review snapshot pinned
by the concern manifest.

## Selection/commit boundary and tenant isolation

`CUSTODY_BINDING_OBLIGATIONS.selectionRecheck = "RECHECK_ALL_CONJUNCTS_AT_EXECUTION_TIME"` is
proven concrete by `selection-commit-boundary.test.ts`: a verdict computed from selection-time
facts confers nothing at commit time — the verifier is re-invoked with commit-time facts, and a
wallet quarantined, retired, destination-retired, or recovery-stripped between the two calls is
denied with the exact frozen denial reason. A select-time PASS is never carried forward.

The pure predicate is deliberately tenant-blind: `CustodyPredicateFacts` carries exactly
`keyOrigin`, `destinationState`, `recoveryVerifiedAt`, `walletState` and no tenant identity, so
wrong-tenant denial is not expressible here (proven by test: extra tenant fields do not change
the verdict, and the fact shape is pinned). Tenant isolation is owned by two other layers, both
binding: (1) structurally — the custody schema contract (`packages/node-core/src/schema/
custody-eligibility.sql`) rejects any destination row whose `node_id` differs from its wallet's
(`CUSTODY_TENANT_MISMATCH_REJECTED`); (2) at selection — every eligibility query MUST be scoped
`WHERE node_id = <current node>` per the data model's custody section. A caller that selects across
tenants has violated this obligation even if every per-wallet conjunct passes.
