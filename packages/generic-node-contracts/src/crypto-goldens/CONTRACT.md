# CONTRACT.md — crypto-goldens

## Purpose

Unified cryptographic golden-vector fixture set freezing ALL deterministic goldens from
canonical fields A.8 (SplitChain A.8.1 + suite tuples A.8.2) and cataloguing ALL A.9 negative
vectors with documented rejection reasons.

## Governing sources

- Canonical fields A.1.1, A.1.2, A.8, A.9
- Decisions: `artifacts-freeze`, `compatibility-literals`, `two-timer-separation`,
  `reporting-key-enrolment`

## Frozen surface

### A.8.1 SplitChain goldens

| Artifact | SHA-256 |
|---|---|
| SEND partial step-1 | `f0e12e993cc4d6b452162cd49b2699b9f912d7a2bf3d8ddd418e3a29c6bbf0b7` |
| Predecessor step-1 | `9bda00a6bbb423a2ea3a9ee2660742dded80562ad58acde106097e2be0583bec` |
| Predecessor step-2 | `07c6dd592f1dd3aa4e70c58f6ab2f92beaa4153d988ae240e6266c41afa22ce5` |
| Predecessor settled | `51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b` |
| Target step-1 | `ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51` |
| Target step-2 | `163d8ef498c09a58d621ed2673c50ed89e79272fcfd14251661c36940e1bb9d0` |
| Target settled | `5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf` |

### A.8.2 Suite tuple goldens (11 preimages)

All nine `zp-*-v1` purposes plus two chained `zp-node-event-v1` goldens (A and B).
Each reproduces its SHA-256 and Ed25519 signature independently from the A.8 test-only seeds.

### A.9 Negative vectors

- 17 general rejection cases (A.9 #1 through #17)
- 6 `zp-reporting-register-v1`-specific rejection cases
- 23 total, each with a documented rejection reason and source reference

## Verification

The freeze test (`crypto-goldens.freeze.test.ts`) independently reproduces every golden using
only `node:crypto` and the A.8 filled-byte Ed25519 seeds. It does NOT share a code path with
any generator script — the reproduction is from first principles.

## Relationship to sibling concerns

- `receive-golden/` — owns the A.8.1 RECEIVE artifact files and their freeze gate
- `reporting-tuples/` — owns the zp-report-request-v1 and zp-node-event-v1 tuple definitions
- `reporting-auth/` — owns the zp-reporting-register-v1 tuple definition
- `compat-literals/` — owns the compatibility literal definitions
- `transfer-code/` — owns the transfer-code vectors

This concern aggregates and independently verifies the same golden bytes without replacing
any sibling's authority. It is a cross-cutting freeze gate, not a second source of truth.

## Test-only keys

All Ed25519 keys are derived from 32-byte seeds filled with a single byte (0x00–0x05).
These keys MUST NEVER be used with live ZKZ (A.8 preamble, the live-chain test cap).
