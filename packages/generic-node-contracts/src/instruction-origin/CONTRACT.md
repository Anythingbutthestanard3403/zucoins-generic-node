# instruction-origin — CONTRACT

Freeze slices: the identity pinning surface, the verifier capability packaging, and the
presentation handoff freeze — together the node-controlled instruction-origin boundary. Gate:
`CONTRACT_FREEZE`. Dependency: the `artifacts` concern (expected-artifact schemas, signing
contract).

## Scope boundary (read first)

The frozen `instruction-origin-identity` rule selects the **implementer-controlled-origin** model: a
compromised hosted platform is inside the threat model, so customer instructions are presented
and verified on an origin the platform cannot silently alter, checked against a node identity
key pinned through a channel independent of the hosted platform. The generic core's role is
narrow and is frozen exactly at that boundary: it supplies node identity publication/rotation
evidence, the three `artifacts` signed expected artifacts, and verification capabilities. It supplies
**no** customer-facing UI, **no** origin policy decision, **no** pin-distribution channel, and
**no** key-rotation UX — those are a product/implementer responsibility.

This is a data-and-pure-predicates freeze. There is no discovery server, no durable node/
identity-key registry (that remains a later identity-registry slice), and no runtime handoff
transport — only the frozen shapes and pure functions a later implementation slice must satisfy.

## What is frozen

- **`origin-classes.contract.ts`.** The closed set `ORIGIN_CLASSES` = `node-origin`,
  `implementer-controlled-origin`, `platform-hosted` — only the two independently-pinnable origins
  of the selected model plus the rejected baseline; there is no wallet-bound class.
  `ORIGIN_CLASS_CLAIMS` freezes, per class, whether it may EVER claim to defeat the
  compromised-platform substitution threat. `platform-hosted` is frozen at `false`
  **unconditionally** — `isSubstitutionProof("platform-hosted", true)` still returns `false`.
- **`identity-pin.contract.ts`.** `NodePublishedIdentity` / `PublishedIdentityKeyEntry`
  freeze what the node publishes: node id, the `/.well-known/zupay-node` discovery path (the API
  contract: discovery and proof surfaces; already frozen as a route in the `operations` route
  contract), and an append-only, monotonic rotation evidence chain built from the `artifacts`
  concern's own `NodeIdentityKeyStatus`/`NodeIdentityKeyRecord` — imported, never redeclared.
  Each entry also carries `supersedesKeyId` (the A.7 `supersedes_key_id` linkage — the key id it
  rotates, or `null` at bootstrap); `isRotationEvidenceChainCoherent` extends
  `isRotationEvidenceChainMonotonic` with a check that every entry's `supersedesKeyId` correctly
  links to the immediately preceding entry's `keyId` — minimal revocation-chain evidence only, no
  richer revocation record (a durable identity registry's territory).
  `NodeIdentityPin` freezes the implementer's independently-established pin (key id + public key
  + `fingerprintSha256` + validity window). `identityKeyFingerprint` is the lowercase-hex
  SHA-256 of the exact UTF-8 bytes of a 44-char padded base64 public-key string. `verifyIdentityPin`
  is the pure predicate binding pin to resolved key: it checks the pin match — key id, public
  key, and fingerprint, in that sequence — **before** delegating to the `artifacts` concern's
  `isKeyAcceptedForVerification`, so a substituted-but-otherwise-valid key is caught by
  `key_id_mismatch`/`pubkey_mismatch`/`fingerprint_mismatch`, never silently accepted.
- **`capability-manifest.contract.ts`.** `CAPABILITY_MANIFEST` freezes the exact
  verification capabilities the core exports to products: `ARTIFACT_VERIFICATION` (from
  `artifacts`, imported), `IDENTITY_PIN_CHECK` (imported), and `PROOF_MATERIAL_ACCESS` — frozen as a
  reserved category only (see Deferred below). `NON_CAPABILITIES` freezes the disjoint,
  explicit exclusion set (`CUSTOMER_INSTRUCTION_UI`, `ORIGIN_POLICY_DECISION`,
  `PIN_DISTRIBUTION_CHANNEL`, `KEY_ROTATION_UX`) the core never exports.
- **`presentation-handoff.contract.ts`.** `PresentationHandoff` freezes the exact,
  closed, sequence-frozen data shape (`PRESENTATION_HANDOFF_FIELDS`) the core hands a product for
  customer instruction presentation — the signed artifact envelope, the resolved identity pin
  state, the discovery path, and the origin class the presentation is rendered on.
  `isValidPresentationHandoffShape` rejects any value outside that closed set, structurally
  (a whitelist, not a keyword denylist), which is what makes a wallet-key-material field
  (C-05) fail by construction. `SUBSTITUTION_THREAT_TABLE` encodes the decision table as data:
  for each origin class × independent-pin-verified combination, whether the presentation defeats
  the compromised-platform substitution scenario, with `isThreatTableRowConsistent` proving the
  table can never silently diverge from the frozen `isSubstitutionProof` function it documents.
- **`manifest.ts`.** `INSTRUCTION_ORIGIN_CONCERN_MANIFEST` — the concern-manifest registry
  leave-behind registration for this whole group. No golden byte refs (no raw signed bytes
  originate in this concern); the one golden literal this concern pins —
  `identityKeyFingerprint` of the A.8 node-identity public key — is derived from
  `node-identity.pub.b64`.

## Mandatory negatives (at least one per manifest)

- **origin-classes** — `platform-hosted` claiming substitution-proof (even with a verified pin)
  is rejected; an undeclared 4th origin class throws.
- **identity-pin** — the exact substitution attack this concern exists to defeat: an attacker's
  own key that is itself `ACTIVE` and would otherwise pass ordinary acceptance is rejected on
  `key_id_mismatch` because it does not match the independently-established pin. Every other
  reject reason (`pubkey_mismatch`, `fingerprint_mismatch`, `pin_not_yet_valid`, `pin_expired`,
  `underlying_key_not_accepted`) is independently exercised. A swapped (out-of-sequence)
  rotation chain is rejected by both `isRotationEvidenceChainMonotonic` and
  `isRotationEvidenceChainCoherent`; a bootstrap entry with a non-null `supersedesKeyId`, and a
  later entry whose `supersedesKeyId` does not match the preceding entry's `keyId`, are each
  independently rejected by `isRotationEvidenceChainCoherent`.
- **capability-manifest** — a frozen non-capability can never be claimed as a capability
  (`isCapabilityId` rejects every `NON_CAPABILITIES` entry); an undeclared 4th capability id
  throws.
- **presentation-handoff** — a handoff carrying wallet key material (an extra field) is rejected
  (C-05); a field missing from the closed set is also rejected (exact-set check, not a superset
  check); a fabricated table row claiming `platform-hosted` defeats the substitution threat
  fails `isThreatTableRowConsistent`.

## Recorded deferral — discovery response body

The full discovery response wire body (`api_version`, `supported_operation_types`,
`canonical_suite_versions`, `event_signing_keys`) and the API contract's RFC3339-ms wire encoding
are intentionally **not** frozen here. This concern's exit criterion — pin and verify identity and
artifacts without trusting platform-served JS — is fully met by `verifyIdentityPin` +
`verifyExpectedArtifact`; the residual wire-body fields are coupled to the deferred discovery
server implementation and to the event-signing key concern, neither of which is a dependency of
this concern.

## Deferred (owned elsewhere)

- **`PROOF_MATERIAL_ACCESS`** (operation proofs — the any-depth landed-operation proof manifests
  of `complete-path-adjudication`) → the `landing-proof` concern, which is not a declared
  dependency of this one (only `artifacts` is). `capability-manifest.contract.ts` reserves the
  capability id and marks it `DEFERRED` with an empty exported-symbol set rather than fabricating
  an interface. Promoting this entry to `FROZEN_AVAILABLE` and importing `landing-proof`'s real
  exports is a follow-up amendment, and the silence is called out explicitly rather than papered
  over.
- Durable node/identity-key registry, publication, and rotation execution → a later
  identity-registry slice; this concern only freezes the shapes such a registry must publish and a
  verifier must consume.
- Discovery server implementation, customer instruction UI, origin-policy decision engine,
  pin-distribution channel, and key-rotation UX → an implementer product, never this package
  (frozen as `NON_CAPABILITIES`).
- Package index/registry (`src/index.ts`, `src/registry.ts`) → the concern-manifest registry
  assembly.

## Judgment calls

- **J1 — only the selected model's two origins are frozen.** `ORIGIN_CLASSES` has no wallet-bound
  member. Only the implementer-controlled-origin model is frozen by `instruction-origin-identity`;
  adding a wallet-verification origin class is a separate future freeze, not implied by this
  freeze.
- **J2 — `PROOF_MATERIAL_ACCESS` is a reserved category, not a fabricated interface.** See
  Deferred above. The alternative (inventing a shape now) risks a second, competing freeze once
  `landing-proof` lands; reserving the id and citing the exact reason is the conservative choice.
- **J3 — the presentation-handoff shape is a whitelist, not a denylist.** C-05's negative
  (no wallet key material) is proven by rejecting anything outside a closed, named field set,
  rather than by enumerating forbidden field names — a denylist can miss a name nobody thought
  of; a whitelist cannot.

## Evolving a frozen fact

Edit the fact in its owning `*.contract.ts` file, update the corresponding entry in
`manifest.ts`'s `frozenValues`, and add/adjust the census test in the same commit.
`gen/instruction-origin.json` (emitted from `INSTRUCTION_ORIGIN_CONCERN_MANIFEST.frozenValues`
via the shared `scripts/emit-json.ts`) is a review-diff convenience snapshot, never byte
authority — the `.contract.ts` sources are authority, and `gen/json-sync.test.ts` fails if this
concern's manifest is edited without re-running `pnpm --filter @zucoins/generic-node-contracts
emit-json`. The census tests remain the primary reviewed diff surface.
