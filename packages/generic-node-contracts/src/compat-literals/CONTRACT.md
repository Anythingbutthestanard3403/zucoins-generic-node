# compat-literals — CONTRACT

Governing sources: canonical fields A.2-A.7 (`zp-*-v1` purpose family, `zp1:` receive-message
prefix, `X-ZP-*`/`X-ZuPay-*` header families, `zupay`/`zupayments` compatibility names); the
state-event reference's forbidden state/event aliases and globs; the API contract's
`/.well-known/zupay-node` route; signing custody; the freeze-gate retained-literal rule.

Decision: `compat-literal-preservation`.

## What is frozen

- **`compat-literals.contract.ts`.** The byte authority for every literal this concern freezes.
  The full `zp-*-v1` signed-purpose family at exactly ten values (A.3.1-A.3.3 expected artifacts,
  A.4.1-A.4.3 approval/custody tuples, A.5's two reporting tuples, A.6 node event, A.7
  wallet-head fingerprint — the one member of the family that is hashed, not signed), plus the
  `zp1:` prefix, the `X-ZP-*`/`X-ZuPay-*` header families, and the `zupay`/`zupayments`
  compatibility names (including the legacy `zupay-reporting-*-v1` signed domain prefixes, the
  `/sdk/zupayments.js` route, and the `@zupayments/` package-scope prefix). Literals that are
  byte-authoritative elsewhere (vault.2, reporting.1/.2, transfer-code, the operations route
  table) are imported/derived, never retyped, so this module is never a second source of truth
  for those bytes.
- **`forbidden-aliases.contract.ts`.** The state-event reference's closed reject-list. The
  state-alias and event-name-alias halves are re-exported unchanged from the operations concern's
  `operations/states.contract.ts` and `operations/events.contract.ts` (their byte-authoritative
  home, each with its own scanner exemption already counted in `forbidden-terms.ts`'s
  `FROZEN_EXEMPTION_COUNT`) — this concern does not re-freeze or re-mark them. The event-name
  GLOB half (`reservation.*`/`payment.*`/`checkout.*`/`refund.*`) is not frozen anywhere else in
  this package; this module is its first freeze. The two documented exceptions
  (`SUBMIT_STARTED` as an execution-phase value only; `HOLD` as `after_landing.kind` only,
  sourced from the operations concern's `AFTER_LANDING_KINDS`) are recorded as
  `FORBIDDEN_ALIAS_EXCEPTIONS`.
- **`kinds.ts`.** The closed four-way taxonomy (`signed-purpose`/`wire-prefix`/`header`/`name`)
  that splits every retained literal. Scaffolding for `inventory.contract.ts`.
- **`replacement-policy.ts`.** The replacement-policy sentence ("a replacement requires
  an explicitly versioned migration and compatibility plan; a repository-wide branding
  substitution is forbidden") frozen as data, not just prose.
- **`inventory.contract.ts`.** The repository-wide, machine-readable audit census: all 29
  literals across the four kinds, each row importing its `literal` value from
  `compat-literals.contract.ts` (or a sibling concern) rather than retyping it, with per-row
  `definingContract`, `caseSensitive`, `byteSensitive`, and `machineFrozenAt` metadata.
- **`construction-sites.contract.ts`.** The construction RULE for each of the eight
  retained-literal families, frozen as data — never a second implementation of a
  serializer/signer another concern already owns.
- **`verify.ts`.** Pure lookup functions (`isKnownCompatibilityLiteral`,
  `findCompatibilityLiteral`, `findCompatibilityLiteralCaseInsensitive`) over the inventory.
  CONTRACT_FREEZE-legal: no network/DB/fs/crypto seams.

## Scan-exemption mechanism

Two classes of `D99_ALLOWLIST` entry beyond the retained-literal seed exist, both because
this concern does not own `scan/forbidden-terms.ts`'s `FROZEN_EXEMPTION_COUNT` and cannot add
new `contract-allow`-marked lines there:

1. **Event-name globs** (`reservation.*`/`payment.*`/`checkout.*`/`refund.*`, cited by
   `forbidden-aliases.contract.ts`) — these are the state-event reference's own frozen "must
   never appear" data, quoted as a value, not as prose.
2. **`apps/node/src/checkout/sdk-route.ts`** (cited by `compat-literals.contract.ts`,
   `inventory.contract.ts`, and `compatibility-gate.test.ts` as the real, existing v1 route-mount
   location of `/sdk/zupayments.js`) — an accidental "checkout" substring inside an unrelated, <!-- contract-allow:allowlist-justification-citation -->
   pre-existing file path, not new product vocabulary.

`neutrality-gate.test.ts` proves every `D99_ALLOWLIST` entry is justified as one of: a
compat literal (or family-prefix) this concern's own inventory recognizes, one of the four
forbidden event-name globs, or the one documented path citation above — nothing else is
permitted to enter that list silently.

## Scope boundary

CONTRACT_FREEZE only — no runtime code. Nothing here validates an incoming request against these
sets or globs; that wiring is a later implementation slice.

## Relationship to the artifacts concern

The artifacts concern owns the full field-sequence/shape freeze for the three A.3
expected-artifact tuples (`zp-receive-expected-v1`, `zp-move-internal-expected-v1`,
`zp-send-external-expected-v1`). `compat-literals.contract.ts` freezes only their bare purpose
strings, independent of that shape freeze — the strings are stable regardless of how the shapes
evolve, and neither module retypes the other's bytes.

## canonical_version pinning

**`canonical-version.contract.ts`.** Pins `canonical_version` for all ten `zp-*-v1` purposes.
Nine purposes carry a literal `1`; `zp-reporting-register-v1` imports
`REPORTING_REGISTER_CANONICAL_VERSION` from `reporting-auth/register-tuple.ts` —
never a second source of truth. The `CANONICAL_VERSION_FOR_PURPOSE` map is the single lookup
for any downstream consumer that needs to know what canonical_version a given purpose carries.

**`canonical-version.gate.test.ts`.** Cross-checks the pin map against the real A.8 golden
preimages for the 7 purposes that have golden fixtures (A.8.2):
`zp-send-external-approval-v1`, `zp-destination-bless-v1`, `zp-device-enrol-v1`,
`zp-report-request-v1`, `zp-reporting-register-v1`, `zp-node-event-v1` (golden A),
`zp-wallet-head-fingerprint-v1`. Each golden preimage is reconstructed byte-exactly, its
SHA-256 is verified against the A.8 pinned digest, and its `canonical_version` field is
cross-checked against the pin map.

### Golden-less purposes

The three A.3 expected-artifact purposes — `zp-receive-expected-v1`,
`zp-move-internal-expected-v1`, `zp-send-external-expected-v1` — have A.8 golden preimages
defined but no authoritative frozen fixture in this concern (the artifacts concern owns the full
field-sequence/shape freeze). Inventory assertion tests in `canonical-version.gate.test.ts`
document their `canonical_version` pinning and prove the golden + golden-less sets together
cover all 10 purposes.

### Negative immutability test

`canonical-version.gate.test.ts` includes a negative test that fails if any
`canonical_version` value in the pin map is mutated away from `1`, or if the map grows
beyond the 10-entry closed set. This ensures any version bump is a deliberate, test-updating
act — not a silent edit.

## Architectural constraints

- `zp1:` is imported from `transfer-code.contract.ts`'s `RECEIVE_MESSAGE_PREFIX`, never declared
  as a bare literal here — the transfer-code concern owns that byte.
- The manifest follows the package-wide `defineConcernManifest` / shared-emitter convention. A
  concern-local `buildLiteralsManifest()` + `gen/literals.json` pattern is deliberately NOT used:
  a second, incompatible manifest shape would fragment the package convention.
- This concern never edits `scan/forbidden-terms.ts`. Both exemption needs above are met by
  `D99_ALLOWLIST` growth instead (see "Scan-exemption mechanism"), so `FROZEN_EXEMPTION_COUNT`
  stays owned by the scan concern alone.
