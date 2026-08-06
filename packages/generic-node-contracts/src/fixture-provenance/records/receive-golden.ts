import type { FixtureProvenanceRecord } from "../types.ts";

/**
 * Receive-golden fixtures (the positive RECEIVE golden + negative vectors) — the
 * canonical-constructor provenance case. Provenance generalizes the directory-scoped
 * `manifest.json` provenance blocks; the generator script is quarantined from the committed
 * test path ("no committed test writes a golden", CONTRACT.md).
 */
const RECEIVE_GOLDEN_GENERATOR = "packages/generic-node-contracts/scripts/emit-receive-golden.ts";

const RECEIVE_GOLDEN_WALLET_VERSION = "n/a — offline canonical constructor; no wallet capture";

const RECEIVE_GOLDEN_CONSTRUCTOR_REFS =
  "the SplitChain v2 constructors and the canonical suite-tuple module — " +
  "referenced by provenance record only; not imported";

export const RECEIVE_GOLDEN_FIXTURE_RECORDS: readonly FixtureProvenanceRecord[] = [
  {
    fixtureId: "receive-golden/attack-vectors",
    byteClass: "signed-preimage",
    indexPath: "src/receive-golden/attack-vectors/manifest.json",
    files: [
      { path: "src/receive-golden/attack-vectors/duplicate-entries.envelope.json", sha256: "9b43d04806148f8772aeb83bedf7a1dcc97e5a3ba91780b4ab213250d6a57925" },
      { path: "src/receive-golden/attack-vectors/invalid-utf8.envelope.bin", sha256: "3c9b6268d7f9f3c732a53d6232cd9e646272dbea03f5680def398484476dd61f" },
      { path: "src/receive-golden/attack-vectors/key-reorder.settled.json", sha256: "4b5d0454701087704fd24bde9db5ff556bbc0e7b4349250d09930071f78ca24b" },
      { path: "src/receive-golden/attack-vectors/malformed-key.settled.json", sha256: "16b46187a90a102703e0579111406d4e4f0fe93669c56767581d7d419a3448c1" },
      { path: "src/receive-golden/attack-vectors/manifest.json", sha256: "043338b801143de1db975dd13528c81e474f350c24f3b5186615d446032922da" },
      { path: "src/receive-golden/attack-vectors/mutated-step-1-signature.settled.json", sha256: "7519581658dc86fc206b85ee0c632e7e97fd19105190cf721852d39a2b37f1f8" },
      { path: "src/receive-golden/attack-vectors/mutated-step-2-signature.settled.json", sha256: "05ad11821b195ccd500dbeba651931aca7adfc2e49f98c91d0e54f4ebbb1cb4c" },
      { path: "src/receive-golden/attack-vectors/numeric-amount.settled.json", sha256: "7e68e3a03eb83fc0de46e1220d1eecd00b37fa5398693a3e1eda1eb68a01d723" },
      { path: "src/receive-golden/attack-vectors/partial-entry-empty-step-2.envelope.json", sha256: "7f05975d251941c4dac72f1d2509a990abb0c798ba0d2e4b9d53f2c9fc9d296b" },
      { path: "src/receive-golden/attack-vectors/partial-entry-missing-step-2.envelope.json", sha256: "f5c41a416f2102d388bf5c977fc0cb14ca40a3e5808ec5d35dbbee2bb3746b7d" },
      { path: "src/receive-golden/attack-vectors/self-transfer.settled.json", sha256: "8eff65a67585368190e0101291afe25c1db44023e07b2e8af17f9d49ce63e911" },
      { path: "src/receive-golden/attack-vectors/unknown-inner-field.settled.json", sha256: "c437024129c409b9b1225c2698a0e2e290968c95c7322d8b4527bef27274c52b" },
      { path: "src/receive-golden/attack-vectors/unpadded-key.settled.json", sha256: "ff11f3893bf04698961b072c811522d5a2178e756fa6460ece6b2419302222f7" },
      { path: "src/receive-golden/attack-vectors/whitespace-preimage.settled.json", sha256: "e198e0014bacca53fd40d6f70ae2d5d43dbc055ce2144dd9f8c39fbb906e7ca6" },
      { path: "src/receive-golden/attack-vectors/wrong-action-data.envelope.json", sha256: "6055532f3ec278cd946c4208e145fb3c0a11639316ca2db07ad32042ef6dac47" },
      { path: "src/receive-golden/attack-vectors/wrong-action-wrapper.envelope.json", sha256: "5121acbb5c0ebf76d3132514390ff47a8d4e7fc66993d4abe257af64726961d6" },
      { path: "src/receive-golden/attack-vectors/wrong-signer-key.settled.json", sha256: "b0dd029799412a18d5e472ba91c357c946089d9b319872792e031ba2c9cc0f05" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Scratch one-shot mutation script (deleted after freeze) produced each fixture as a single documented " +
        "mutation of the frozen RECEIVE golden gen/target.settled.json; objects serialized in insertion sequence only " +
        "with JSON.stringify; re-signing uses the public deterministic test-only filled-byte seeds 02/03/05 " +
        "(golden keys never live); no gateway capture, import, live submit, or live-chain switch",
      captureDate: "2026-07-21",
      walletVersion: RECEIVE_GOLDEN_WALLET_VERSION,
      source:
        "scratch one-shot mutation script (deleted after freeze); offline mutation of the frozen RECEIVE golden " +
        "gen/target.settled.json; no gateway capture, import, live submit, or live-chain switch",
      keyMaterial:
        "deterministic test-only 32-byte filled Ed25519 seeds 02, 03, and 05 used for re-signing mutated " +
        "vectors (golden keys never live); MUST never be used with live ZKZ",
      specCitations: [
        "protocol foundation: negative vector 7 (mutated signed bytes)",
        "observation-verification: adversarial receive suite, malformed-envelope class",
        "observation-verification: adversarial receive suite, mutated-signature class",
      ],
      decisionRefs: ["expected-artifact-surfaces-freeze"],
      details: {
        generator: "scratch one-shot mutation script (deleted after freeze)",
        construction:
          "objects serialized in insertion sequence only with JSON.stringify; re-signing uses the public A.8 " +
          "deterministic test-only filled-byte seeds 02/03/05",
        baseline_settled_sha256: "5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf",
        purpose:
          "frozen adversarial suite attacking the receive envelope parser and the " +
          "receive transaction verifier; proves unknown or malformed authoritative fields fail closed " +
          "before state promotion",
        constructor_refs: RECEIVE_GOLDEN_CONSTRUCTOR_REFS,
      },
    },
  },
  {
    fixtureId: "receive-golden/gen",
    byteClass: "signed-preimage",
    indexPath: "src/receive-golden/gen/manifest.json",
    files: [
      { path: "src/receive-golden/gen/manifest.json", sha256: "86b6851f1344a89789fbf96aa99d911b7485dded5d78458a0b4f16d79a52acfe" },
      { path: "src/receive-golden/gen/predecessor.settled.json", sha256: "51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b" },
      { path: "src/receive-golden/gen/predecessor.step-1.json", sha256: "9bda00a6bbb423a2ea3a9ee2660742dded80562ad58acde106097e2be0583bec" },
      { path: "src/receive-golden/gen/predecessor.step-2.json", sha256: "07c6dd592f1dd3aa4e70c58f6ab2f92beaa4153d988ae240e6266c41afa22ce5" },
      { path: "src/receive-golden/gen/receiver-head-fingerprint.txt", sha256: "d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a" },
      { path: "src/receive-golden/gen/target.settled.json", sha256: "5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf" },
      { path: "src/receive-golden/gen/target.step-1.json", sha256: "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51" },
      { path: "src/receive-golden/gen/target.step-2.json", sha256: "163d8ef498c09a58d621ed2673c50ed89e79272fcfd14251661c36940e1bb9d0" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Offline canonical constructor emitted the finite two-transaction RECEIVE fixture; " +
        "objects built with keys fixed in construction sequence and serialized only with JSON.stringify; " +
        "no gateway capture, import, or submission; " +
        "the generator script is quarantined from the committed test path (no committed test writes a golden)",
      captureDate: "2026-07-19",
      walletVersion: RECEIVE_GOLDEN_WALLET_VERSION,
      source: RECEIVE_GOLDEN_GENERATOR,
      keyMaterial:
        "deterministic test-only 32-byte filled Ed25519 seeds 02, 03, and 05 (05 is the disposable predecessor " +
        "counterparty at the pre-existing funded boundary B=\"10\"); MUST never be used with live ZKZ",
      specCitations: [
        "canonical-fields reference: deterministic two-transaction RECEIVE fixture",
        "protocol foundation: signed-preimage byte class",
        "build-test plan: expected bytes are stored frozen, never regenerated by the implementation under test",
      ],
      decisionRefs: ["expected-artifact-surfaces-freeze"],
      details: {
        generator: RECEIVE_GOLDEN_GENERATOR,
        construction: "keys fixed in construction sequence; serialized only with JSON.stringify",
        constructor_refs: RECEIVE_GOLDEN_CONSTRUCTOR_REFS,
      },
    },
  },
  {
    fixtureId: "receive-golden/negative-vectors",
    byteClass: "signed-preimage",
    indexPath: "src/receive-golden/negative-vectors/manifest.json",
    files: [
      { path: "src/receive-golden/negative-vectors/manifest.json", sha256: "861a155031aac93ed737ec878fdf24f267ac43f6413aaecee1ebe8bb84bd4c76" },
      { path: "src/receive-golden/negative-vectors/funded-sender-genesis-predecessor.inner.json", sha256: "f0e12e993cc4d6b452162cd49b2699b9f912d7a2bf3d8ddd418e3a29c6bbf0b7" },
      { path: "src/receive-golden/negative-vectors/funded-sender-genesis-predecessor.step-1-signature.txt", sha256: "8bf6901904b76450b9562d2a6fc8ed4a85ac5c9a44d7b9613f69759268bb1095" },
      { path: "src/receive-golden/negative-vectors/wrong-receiver-balance.inner.json", sha256: "9d4d5f1c906333657fc06f0a6c0775fd1764a5652f9e6147ed90597ef6584ba9" },
      { path: "src/receive-golden/negative-vectors/wrong-receiver-balance.step-1-signature.txt", sha256: "a8da2f62dacdb9e9d97c2ddc3fea34cbeb480ba665db7a7bb9050a98ee4fba31" },
      { path: "src/receive-golden/negative-vectors/wrong-sender-balance.inner.json", sha256: "162abee42053bd7933f237cad5edea901b275f63a63b7a111998822cfb93245c" },
      { path: "src/receive-golden/negative-vectors/wrong-sender-balance.step-1-signature.txt", sha256: "7dd1a03f0fad85609835e8dc0c2df697984f679994ac507a06d3776fd9031706" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Offline canonical constructor emitted static adversarial RECEIVE targets — each candidate is a " +
        "validly re-signed but invalid RECEIVE target (canonical negative-vector classification; economic " +
        "conservation); runtime rejection is DEFERRED to the external-partial intake work (no reusable pre-sign semantic validator exists yet)",
      captureDate: "2026-07-19",
      walletVersion: RECEIVE_GOLDEN_WALLET_VERSION,
      source: RECEIVE_GOLDEN_GENERATOR,
      keyMaterial:
        "deterministic test-only 32-byte filled Ed25519 seed 02 (step-1 signer); MUST never be used with live ZKZ",
      specCitations: [
        "canonical-fields reference: required negative vectors",
        "operation flows: candidate intake and economic conservation",
        "build-test plan: expected bytes are stored frozen, never regenerated by the implementation under test",
      ],
      decisionRefs: ["expected-artifact-surfaces-freeze"],
      details: {
        generator: RECEIVE_GOLDEN_GENERATOR,
        runtime_enforcement: "DEFERRED — owned by the external-partial intake, co-sign, and single-submit work",
        constructor_refs: RECEIVE_GOLDEN_CONSTRUCTOR_REFS,
      },
    },
  },
];
