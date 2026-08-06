# Amounts concern — frozen contract

Canonical ZKZ amount contract. Binding sources: the `zkz-amount-grammar` decision and its
numeric-positivity hardening addendum, `amount-bounds-authority-split`, and
`amount-column-precision-widening`. A named decision is canonical and overrides any
descriptive text here on conflict.

## Frozen facts

- Canonical grammar: `^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$`. Rejects sign, exponent,
  separators, leading zeros, trailing dot, `-0`, Unicode digits, and >32 dp. The 8-digit
  integer cap makes the grammar structurally enforce `< 1e8` (a 9-digit integer never
  matches), so `100000000` and above are grammar-rejected without a separate numeric check.
- Bound: exclusive `< 100000000` (1e8); greatest legal value `99999999.` + 32 nines.
- Precision / rounding: ≤ 32 decimal places, `ROUND_DOWN`.
- Emitter byte-lock: `.toFixed()` with **no argument** on an isolated pinned BigNumber clone
  `{ DECIMAL_PLACES: 32, ROUNDING_MODE: ROUND_DOWN, EXPONENTIAL_AT: [-33, 33] }`. `.toFixed(dp)`
  (zero-pads) and `.toString()` / template coercion (exponent risk) are byte defects.
- Layer split: balances / post-states / heads are `0 <= amount < 1e8` (a swept-payer
  balance, genesis, and a landed payer partial are legitimately `"0"`); operation /
  expected-artifact / approval amounts are `0 < amount < 1e8`.
- Positivity is a **NUMERIC** predicate (`> 0`), never a string comparison. This closes the
  recorded `<> '0'` bypass: `'0.0'`, `'0.00'`, `'0.' + 32 zeros` match the regex and are
  `<> '0'` as strings while being mathematically zero.
- Canonical-equality: `emit(parse(input)) === input`. Rejects grammar-legal but
  non-canonical forms (`"2.50"`, `"0.0"`) at the API contract.
- Foreign-signed-bytes carve-out (the byte-exact signing rule): canonicalization applies ONLY to
  node-authored amounts. Foreign amounts (payer step-1, recipient step-2, observed on-chain
  `step_*_state.amount`) are verified over EXACT original bytes, never reformatted; malformed
  foreign amounts are flagged as anomalies, never rewritten or dropped.
- Every public amount API accepts only primitive strings — construction / emission (`emitAmount`),
  arithmetic (`addAmounts`, `subtractAmounts`, `compareAmounts`), and every inspection / validation
  root alike. Any other runtime value throws
  `TypeError("ZKZ amount input must be a primitive string")` before coercion, property access,
  proxy observation, or field-role lookup, via the single `string-boundary.ts` guard.

## Numeric positivity in place of a string comparison (intentional)

The original `zkz_amount_positive_text` shape was `regex AND VALUE <> '0'`. This concern
instead records `regex AND VALUE::numeric > 0`, per the **numeric-positivity hardening
addendum** to `zkz-amount-grammar` (the string form is bypassable by non-canonical decimal
zeros). This is additive hardening frozen alongside `zkz-amount-grammar`, not a reversal of it.

## Clause → code traceability

| Clause | Code |
|---|---|
| Canonical grammar regex | `grammar.ts` `CANONICAL_DECIMAL_PATTERN`, `matchesCanonicalGrammar` |
| Exclusive `< 1e8`, ≤32 dp, ROUND_DOWN, EXPONENTIAL_AT | `emitter.ts` pinned clone + magnitude predicates |
| Emitter byte-lock (`.toFixed()` no-arg) | `emitter.ts` `emitAmount`; defect proof `emitter-misuse.test.ts` |
| Arithmetic (add / subtract / compare, no JS number) | `emitter.ts` primitive-string public signatures + runtime guards; `emitter.test.ts` compile/runtime negatives |
| Canonical-equality | `validators.ts` `isCanonicalAmount`, `canonicalFailure` |
| Layer split (balance `0<=` / operation `0<`) | `emitter.ts` `isWithinBalanceMagnitude` / `isWithinOperationMagnitude`; `validators.ts` |
| NUMERIC positivity (bypass closure) | `emitter.ts` `isNumericallyPositive`; `validators.test.ts` zero-form regression |
| Foreign-bytes carve-out | `foreign.ts` `inspectForeignAmount` |
| Primitive-string inspection boundary | `string-boundary.ts` `assertPrimitiveAmountString` |
| Two DB CHECK domains (SQL text as data) | `manifest.ts` `ZKZ_AMOUNT_CHECK_DOMAINS` |

This primitive-string boundary is enforced identically at every helper, before BigNumber
construction, through the single `string-boundary.ts` guard; numbers, boxed strings, BigNumber
objects, bigint, and coercible objects fail with `TypeError`. It is a representation boundary
only: canonical grammar, positivity, magnitude, and field-role authority remain in the
layer-specific validators, so generic arithmetic deliberately may emit a negative or
out-of-domain intermediate string.

## Downstream integration guidance

This section is guidance for downstream consumers. It does not change the frozen exports,
validators, manifest text, vectors, or goldens described above.

### Post-grammar numeric helpers are not validation gates

The exported `isNumericallyPositive`, `isWithinBalanceMagnitude`,
`isWithinOperationMagnitude`, `isFiniteAmount`, and `numericDecimalPlaces` functions are
post-grammar helpers. They assume the input has already passed `matchesCanonicalGrammar()`;
none is a standalone validation gate for untrusted amount text. Downstream callers must either:

- run `matchesCanonicalGrammar()` before calling one of these helpers; or
- use a grammar-gated entrypoint such as `validateBalanceAmount`, `validateOperationAmount`,
  or `enforceAmountField`.

The current node-authored validation and enforcement paths in this package already apply the
grammar gate before numeric predicates. This warning prevents misuse by future consumers; it
does not identify a vulnerability in the current node-authored paths.

### PostgreSQL CHECK attachment must guard the numeric cast

Under `zkz-amount-grammar`, `manifest.ts` freezes the positive-domain SQL shape as regex matching combined
with `VALUE::numeric > 0`. PostgreSQL does not guarantee evaluation sequence between CHECK
subexpressions, so an `AND` expression cannot be relied on to test the regex before evaluating
the numeric cast. Malformed input may therefore raise SQLSTATE `22P02`
(`invalid_text_representation`) instead of producing the intended SQLSTATE `23514`
(`check_violation`).

A schema that attaches this contract to a column must use a `CASE`/regex-guarded expression,
or an equivalent frozen wrapper, that evaluates `VALUE::numeric > 0` only after the grammar
match succeeds. This is integration guidance; it does not authorize changing the frozen
`manifest.ts` shape here.

## Golden / parity provenance

`__vectors__/emission.golden.json` is the byte-frozen emission parity set. Its input→output
pairs are copied from the SplitChain amount emitter's own wire-emission test cases
(`packages/splitchain/src/amount.test.ts`, `toAmountString`). `parity.golden.test.ts` pins the file's
sha256 and asserts `emitAmount` reproduces every pair — the same byte contract splitchain's
`Amount` emitter holds. The emitter config here is identical to
`packages/splitchain/src/amount.ts` (`Amount`).

## Regeneration

- `gen/amounts.json` is a committed snapshot of the `amountsContract` as-const manifest;
  `manifest.test.ts` fails on drift. Regenerate by serializing `amountsContract`
  (`JSON.stringify(amountsContract, null, 2)`) into `gen/amounts.json`.
- `__vectors__/emission.golden.json` is digest-pinned in `parity.golden.test.ts`. To change
  it, edit the file (keep no trailing newline) and re-pin `GOLDEN_SHA256` to the new
  `shasum -a 256` value.
- `__vectors__/{boundary,arithmetic,emission}.vectors.json` are generated from the
  `vectors.ts` as-const arrays via `JSON.stringify(data, null, 2)` (no trailing newline) and
  digest-pinned in `vectors.test.ts` (`PINS`). To change a vector: edit the as-const, regenerate
  the JSON, and re-pin the new `shasum -a 256`. The sync test fails if the JSON drifts from the
  as-const; the correctness test fails if any vector disagrees with the live contract.

## API / DB enforcement alignment (frozen)

Aligns which predicate every amount-bearing field gets, exposes one typed rejection contract,
and maps DB columns to the scalar contract's CHECK domains — as data + pure verifiers + tests
only. No runtime API handler, no migration. Consumes the scalar contract's grammar /
validators / domains / reason codes; the scalar contract wins on any conflict.

- **Field-role application map** (`field-roles.ts` `AMOUNT_FIELD_ROLES`): each amount field →
  `{ authorship, layer }`. Node-authored operation fields (request / operation `amount_zkz` /
  expected-artifact / approval) → operation layer (`0 < amount`); node-authored positions
  (post-state / derived balance / head / genesis) → balance layer (`0 <= amount`); foreign
  signed amounts (payer step-1, recipient step-2, observed on-chain step state) → byte
  inspection, `layer: null`.
- **One typed rejection contract** (`enforcement.ts`): `enforceAmountField(role, value)` is the
  single entry applied the same to every field. Node failures all produce
  `{ kind: "rejected", role, layer, reason, value }` (`reason` from `AMOUNT_REJECTION_REASONS`);
  foreign amounts produce `{ kind: "foreign", bytes, wellFormed, anomaly }` and are never
  rejected (the byte-exact signing rule, evidence preserved). Product code maps `rejected` to its API error.
- **DB CHECK-domain application map** (`db-enforcement.ts` `ZKZ_CHECK_DOMAIN_BY_ROLE`):
  operation roles → `zkz_amount_positive_text`, balance roles → `zkz_balance_text`, foreign
  roles → `FOREIGN_NO_REJECT` (no evidence-dropping CHECK). `request_transfer_amount` is
  API-only, no column. `AMOUNT_WRITE_VIOLATION_POLICY`: a write-time bound violation is
  SQLSTATE 23514 (`check_violation`, never 22003 numeric overflow — the DB amount-domain
  enforcement rule) routed to operator hold / quarantine, never a crash-loop, never a resubmit
  (the never-blind-retry rule).
- **Boundary semantics** proven consistent across all node roles (`enforcement.test.ts`): zero
  rejected for every operation role and accepted for every balance role; exact bound, overflow,
  exponent, excess precision, non-canonical, and negative rejected consistently; greatest legal
  value accepted. Snapshot `gen/amount-enforcement.json` gated by a sync test.

## Published vector matrix (frozen)

The canonical ZKZ amount vectors downstream consumers import to test their own amount handling
against this contract. Three tiers: importable as-const arrays (`vectors.ts`), byte-frozen
digest-pinned JSON snapshots (`__vectors__/*.vectors.json`), and tests that verify every vector
against the live scalar + enforcement contract.

- **Boundary matrix** (`AMOUNT_BOUNDARY_VECTORS`): every checklist class — zero, smallest unit
  (10^-32), greatest-below-bound, greatest integer, exact bound, above bound, exponent, leading
  zero, trailing dot, negative, `-0`, excess precision (33 dp), non-canonical — each carrying
  its expected `validateBalanceAmount` and `validateOperationAmount` outcome (so the layer split
  is encoded per vector). `vectors.test.ts` asserts each matches the live validators.
- **Arithmetic matrix** (`AMOUNT_ARITHMETIC_VECTORS`): add/subtract worked examples (subtract-to-
  zero, genesis, float-drift avoidance, 32-dp edge) verified against `addAmounts`/`subtractAmounts`.
- **Emission matrix** (`AMOUNT_EMISSION_VECTORS`): canonicalization pairs, a superset of the
  scalar contract's `emission.golden.json`, verified against `emitAmount` and byte-identical to
  splitchain's `toAmountString`.
- **Property tests** (`property.test.ts`): a seeded, reproducible PRNG generates canonical
  amounts and asserts emit idempotence, `(a+b)-b === a`, add commutativity, the no-rounding /
  <=32 dp invariant, operation positivity, and negatives (trailing-zero breaks canonicality,
  33-dp is grammar-rejected). No new dependency (fast-check absent).

## Scope boundary

The scalar + arithmetic contract, the enforcement alignment, and the published vectors freeze
contracts / verifiers / vectors / tests only (CONTRACT_FREEZE): no runtime API handler, no
migration, no product logic. The API route and DB schema that CONSUME these contracts live
outside this package.
