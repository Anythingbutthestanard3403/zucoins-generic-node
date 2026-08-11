# @zucoins/generic-node-contracts — package conventions

This document is the package-wide companion to the per-concern `CONTRACT.md` files already
present under each `src/<concern>/` directory (e.g. `src/amounts/CONTRACT.md`, cited by the
`zkz-amount-grammar` decision). Those files freeze one concern's decision-derived bytes and
values; this file documents the conventions that apply _across every concern_ — how a manifest
is encoded at three tiers, how the drift-gate scanner works, the `ConcernManifest`
self-registration shape, and how digest-pinned goldens are produced and quarantined from CI.

It is the target the package's cross-cutting source citations resolve to. Each such citation
points at either this file (package convention), a named decision slug (the drift-gate
substance rules `three-generic-operations` / `drift-gate-scanner`), or
`canonical-fields: A.8` (byte content), depending on what the citing line actually needs. A
named decision always overrides this file on a substance conflict. The package is a set of
pure-leaf concern directories with zero runtime dependencies; this file assumes that structure.

## Manifest encoding (3 tiers)

Every frozen contract in this package is encoded at up to three tiers. Only tier 1 is byte
authority; tiers 2 and 3 exist for human review and for wire-format artifacts that are not
plain TypeScript values.

1. **Tier 1 — `.contract.ts` `as const` source.** The frozen value lives once, as an exported
   `as const` TypeScript literal (e.g. `src/operations/operations.contract.ts`). This is the
   sole byte/value authority. Every other tier is derived from it and can never disagree with
   it without failing a test.
2. **Tier 2 — `gen/*.json` review-diff convenience.** `scripts/emit-json.ts` serializes a set of
   tier-1 manifest modules to `gen/<name>.json` via `JSON.stringify(toSortedPlainObject(...), null, 2)`
   (deterministic key order, trailing newline). This snapshot exists purely so a review diff shows
   the effective contract value; it is **never** byte authority. `gen/json-sync.test.ts`
   fails the moment a committed `gen/*.json` file diverges from a fresh emit of its source
   `.contract.ts` module. Regenerate with `pnpm --filter @zucoins/generic-node-contracts emit-json`.
3. **Tier 3 — digest-pinned raw byte artifacts.** Where the frozen value is not a plain JSON-safe
   object but exact wire bytes (a base64url transfer code, a JSON preimage string, an HKDF/AAD
   byte string), the raw bytes are committed as their own file (e.g. under `goldens/`), carry
   **no trailing newline**, and are pinned by a `sha256` digest asserted in a test (see
   [Golden regeneration and quarantine](#golden-regeneration-and-quarantine) below). `.prettierignore`
   excludes `packages/generic-node-contracts/goldens/**` for exactly this reason — a formatter
   silently appending or normalizing whitespace would change the pinned bytes.

`CONTRACT_FREEZE` slices (see [Import and dependency boundary](#import-and-dependency-boundary-contract_freeze))
are restricted to producing only these three tiers, plus the pure verifier functions and tests
that check them — never a runtime handler, migration, or side effect.

## Drift-gate scanner (forbidden vocabulary)

`src/scan/forbidden-terms.ts` is the whole-word forbidden-vocabulary scanner. Its purpose and
scope are decision-derived (`three-generic-operations` — the three-generic-operation model that
makes checkout/payment/sweep/treasury/etc. implementer-projection concepts, not core vocabulary
— and `drift-gate-scanner`, which froze the scan at the broad 3-directory scope with
tolerate-absent globbing and frozen the current exemption count); this section documents the
mechanism, i.e. what the scanner actually does at the code level.

- **Forbidden-term list** (`FORBIDDEN_TERMS`): sixteen stems — `payment`, `refund`, `sweep`,
  `treasury`, `checkout`, `payout`, `withdrawal`, `order`, `merchant`, `reservation`,
  `outbound`, `drain`, `ZUC`, `finalised`, `fulfilled`, `treasury settlement`. The count in
  this prose is descriptive only; the authoritative length is `FORBIDDEN_TERMS.length` in
  `src/scan/forbidden-terms.ts`.
- **Scan scope** (`SCAN_SCOPE`): `packages/generic-node-contracts/src`, `packages/node-core/src`,
  `apps/generic-node/src`, `apps/generic-node/admin/src` — the broad scope `drift-gate-scanner`
  frozen, extended to the operator SPA (`.ts` / `.tsx` / `.md`). `src/scan/**` (this module's own
  directory) is never itself a scan target, the same way a lint rule's definition file is not
  linted against the pattern it forbids.
- **Tokenization and suffix-stripping** (`matchForbiddenTerm`): a candidate is matched as a
  whole word (`\w+`) first against the literal term list, then — if no direct match — against
  five suffix strips tried longest/most-specific first: `ies` (restoring the elided `y`, e.g.
  `treasuries` → `treasury`), `ing`, `ed`, `es`, `s` (straight truncations). This is deliberately
  not a full stemmer; irregular forms (e.g. `swept`) are out of scope. Because matching is
  whole-word, a compound token like `zupayments` is compared to the term list as one unbroken
  token (`zupayments`/`zupayment` post-strip) and never matches `payment` as a substring
  (`compatibility-literals`).
- **Stem allowlist** (`STEM_EXEMPT_TOKENS`): a closed list of whole tokens whose only
  route to a listed term is the suffix stripper and whose sense is structural, not a product
  projection — the `ordering`/`reordering`/`unordered` family and `draining`. It applies at the
  STEM step only: a direct hit on a listed term is never exempt, so the base words and their
  plurals still flag. Adding an inflection is an edit to that list, reviewed like any other.
- **`contract-allow:<reason>` exemption marker** (`EXEMPTION_MARKER_PREFIX`): any line containing
  this literal prefix is exempted from scanning entirely, regardless of what forbidden terms it
  contains. It marks either a historical quote of retired/forbidden vocabulary with zero
  authority, or frozen contract bytes (a SQL fragment, a snapshot-synced field name, a concern's
  own module path) whose exact content a concern's own decision freezes and which cannot be
  reworded without changing byte authority. `FROZEN_EXEMPTION_COUNT` pins the current live marker
  count; any change adding or removing a marker must update this constant in the same commit or
  `forbidden-terms.test.ts`'s live-count test fails.
- **Named-term markers and suppression accounting**: a marker payload of the form
  `<term>[,<term>...]` followed by the reason, all colon-separated, narrows the exemption to the
  named terms — every other listed term on that line still flags. A payload whose leading field is
  not a known term stays the whole-line form above, so a typo never silently stops exempting, and
  a multi-word term (whose name cannot survive the whitespace-terminated payload) always uses it.
  A marker's own bytes are excluded from detection. Because the whole-line form remains, the line
  count alone cannot see an already-marked line being extended with fresh product vocabulary:
  `FROZEN_SUPPRESSED_VIOLATION_COUNT` pins the number of hits the markers actually suppress across
  `SCAN_SCOPE`, so that edit moves a frozen number and fails the gate. Both constants must be
  updated in the same commit as the marker that moves them.
- **Allowlisted spans** (`isWithinAllowlistedSpan`): independent of the marker prefix, a caller
  may pass an `allowlist` of literal strings (e.g. a `compatibility-literals` compatibility name); a match whose
  span falls entirely within an allowlisted literal is exempted, guarding against a future
  allowlist literal that happens to contain a forbidden stem.
- **Violation shape** (`ScanViolation`): `{ file, line, term, excerpt }` — one entry per matched,
  non-exempted token.

## Import and dependency boundary (CONTRACT_FREEZE)

`src/scan/dependency-boundary.test.ts` enforces the other half of what a `CONTRACT_FREEZE` slice
is allowed to be: legal artifacts are `as const` manifests, pure stateless verifier functions,
tests/fixtures, scanners, and type declarations. Forbidden: network I/O, database access,
durable state, workers, private key material, or a `main()`/process-entry seam.

- **Forbidden import specifiers, all modules** (`FORBIDDEN_IMPORT_SPECIFIERS`): `node:net`,
  `node:http`, `node:https`, `node:dgram`, `node:tls`, `node:worker_threads`/`worker_threads`,
  `node:child_process`/`child_process`, `undici`, `pg`, `postgres`.
- **Forbidden import specifiers, contract/manifest modules only**
  (`CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS`): `node:crypto`/`crypto`, `node:fs`/`fs`.
  A contract or manifest module is any `manifest.ts` or `*.contract.ts` file that is not a test
  and is not under one of the tier-two permitted directories (`testkit`, `scan`, `scripts` —
  `TIER_TWO_PERMITTED_DIR_SEGMENTS`), which are allowed to touch the filesystem/crypto because
  they are the emitters and test harness, not the frozen contracts themselves.
- **Transitive reachability** (`reachableForbiddenEdges`): the two lists above are also
  enforced through the relative-import graph, not only against each file's own text.
  `FORBIDDEN_IMPORT_SPECIFIERS` is unconditional — no tier may hold them, so any chain reaching one
  is a violation. The crypto/fs list is enforced from contract/manifest roots along chains that
  pass through a tier-two permitted directory: that grant exists for the emitters and the test
  harness, and a frozen contract must not inherit it one import away. A contract reaching crypto
  through a NON-tier-two peer module is out of this rule; `instruction-origin/identity-key-hash.ts`
  is the sanctioned case, and a fixture pins that both ways. Runtime loaders
  (`createRequire`, `process.getBuiltinModule`, dynamic `import`/`require`) count as acquiring a
  specifier even when the loader and the specifier sit in different statements.
- **Banned internal loader seams** (`findBannedLoaderSeams`): `process.binding` and
  `Module._load` reach native bindings / the CommonJS loader without the forms above. Fail closed
  on direct member access (dot/bracket/acquisition), destructure extraction
  (`const { binding } = process`, `const { _load } = Module`, `const { _load } = require("module")`),
  and process/module aliases that then reach `.binding` / `._load` (assignment, default import,
  namespace import). These seams have no legitimate place in a frozen contract package.
- **Forbidden environment variable reads** (`FORBIDDEN_ENV_NAMES`): `SPLITCHAIN_GATEWAY_URLS`,
  `VAULT_MASTER_KEY`, `DATABASE_URL`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`.
- As with the forbidden-vocabulary scanner, `src/scan/**` is excluded from its own check — its
  specifier/env-name lists and self-test fixtures necessarily contain the literal forbidden
  strings.

## ConcernManifest schema (the concern-manifest registry leave-behind)

`src/testkit/concernManifest.ts` defines the `ConcernManifest` shape every concern directory
self-registers as its own `manifest.ts` export (e.g. `OPERATIONS_CONCERN_MANIFEST`,
`OPERATOR_HALT_CONCERN_MANIFEST`, `TRANSFER_CODE_CONCERN_MANIFEST`). This is the
concern-manifest registry "leave-behind": each concern registers its own manifest at build time
so the registry assembly (`src/registry.ts`) can iterate, count, and verify every concern's
disposition without archaeology. Registering a manifest is a registration import only — a
concern never reaches into the registry itself.

```ts
interface ConcernManifest {
  readonly concernId: string; // e.g. "amounts"
  readonly decisionRefs: readonly string[]; // canonical decision slugs, e.g. ["zkz-amount-grammar"]
  readonly frozenValues: Readonly<Record<string, unknown>>; // every tier-1 export this concern freezes
  readonly goldenRefs: readonly {
    readonly path: string;
    readonly sha256: string;
  }[]; // tier-3 artifacts, if any
  readonly scanRules: readonly string[]; // drift-gate rules this concern is covered by
  readonly sourceDocCitations: readonly string[]; // self-contained doc citations, e.g. ["data-model: node_events"]
}
```

`defineConcernManifest` is the identity function used to construct one — it exists purely so a
concern's manifest declaration reads as a typed, self-documenting call site rather than a bare
object literal.

## Golden regeneration and quarantine

Tier-3 raw byte artifacts (see [Manifest encoding](#manifest-encoding-3-tiers)) are never
produced by a committed test. The rule — informally called "A8" in this package's comments and
golden provenance metadata — is: **no committed test writes a golden.** A test may only read a
golden file and assert its digest; it must never generate or overwrite one as a side effect of
running, because a test with write access to its own fixture can silently launder a byte-format
regression into a new "passing" golden.

- **Production**: a golden is produced by a scratch, out-of-repo golden-writer tool — never a
  script that ships in this package or runs in CI — then hand-reviewed and committed as a raw
  byte file (e.g. `goldens/transfer-code/receive-code.v1.b64url.txt`), with **no trailing
  newline**.
- **Pinning**: the committed byte file's `sha256` digest is hard-coded as a constant in the
  consuming test (e.g. `transfer-code-vectors.test.ts`'s `RECEIVE_B64URL_SHA256`). The test
  reads the golden file at run time, recomputes its digest, and asserts it equals the pinned
  constant — it never recomputes the golden's _content_. A change to any golden must be a
  reviewed, deliberate byte-contract change that updates the pinned digest constant in the same
  commit.
- **Provenance metadata**: a sibling `*.meta.json` file (e.g.
  `goldens/transfer-code/receive-code.v1.meta.json`) records how the golden was produced —
  encode pipeline, the external wallet-mirror source lines it was verified against, governing
  decisions, and a `regenerated_by` note identifying the scratch tool and citing this
  no-committed-test-writes-a-golden rule. The `.meta.json` file is documentation only; no test
  parses or depends on it.
- **Reproduction/change procedure**: to change a golden, regenerate it with the scratch
  golden-writer against the new frozen inputs, hand-verify the new bytes (including any required
  cross-implementation parity, e.g. against the wallet mirror), commit the new raw byte file with
  no trailing newline, update the `.meta.json` provenance note, and re-pin every digest constant
  in the consuming test in the same commit. A golden change is always a reviewed, deliberate
  byte-contract change — never a routine "regenerate on failure."
