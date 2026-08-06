import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  EXPECTED_ARTIFACT_PURPOSES,
  CANONICAL_VERSION,
  ARTIFACT_SIGNING_KEY_ROLE,
  SUITE_PREIMAGE_CONSTRUCTION,
  ARTIFACT_FIELD_TYPES,
  ARTIFACT_FIELD_ROLES,
  RECEIVE_EXPECTED,
  MOVE_INTERNAL_EXPECTED,
  SEND_EXTERNAL_EXPECTED,
} from "./expected-artifacts.contract.ts";
import {
  NODE_IDENTITY_KEY_STATUSES,
  KEY_VALIDITY_RULES,
  KEY_REJECT_REASONS,
} from "./signing-contract.ts";

const GOLDEN_DIR = "goldens/artifacts";

/**
 * The artifacts concern's self-registered ConcernManifest.
 * Registration import only — the concern-manifest registry assembles `src/registry.ts`. `goldenRefs`
 * digest-pins every raw byte artifact; the three `*.preimage.txt` file digests equal their
 * artifacts' pinned SHA-256 (A.8) by construction.
 */
export const ARTIFACTS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "artifacts",
  decisionRefs: ["artifacts-freeze"],
  frozenValues: {
    EXPECTED_ARTIFACT_PURPOSES,
    CANONICAL_VERSION,
    ARTIFACT_SIGNING_KEY_ROLE,
    SUITE_PREIMAGE_CONSTRUCTION,
    ARTIFACT_FIELD_TYPES,
    ARTIFACT_FIELD_ROLES,
    RECEIVE_EXPECTED,
    MOVE_INTERNAL_EXPECTED,
    SEND_EXTERNAL_EXPECTED,
    NODE_IDENTITY_KEY_STATUSES,
    KEY_VALIDITY_RULES,
    KEY_REJECT_REASONS,
  },
  goldenRefs: [
    { path: `${GOLDEN_DIR}/zp-receive-expected-v1.preimage.txt`, sha256: "f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498" },
    { path: `${GOLDEN_DIR}/zp-receive-expected-v1.digest.hex`, sha256: "8d2380efddc58bc1cf1ed40d4c2cd6421604618e8aee5f65b5d973245e7ca9cb" },
    { path: `${GOLDEN_DIR}/zp-receive-expected-v1.sig.b64`, sha256: "513c9c00d0deeae6597e60f144de3ad3944de80aabeebdbb3f4f5604abeabbc4" },
    { path: `${GOLDEN_DIR}/zp-move-internal-expected-v1.preimage.txt`, sha256: "ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14" },
    { path: `${GOLDEN_DIR}/zp-move-internal-expected-v1.digest.hex`, sha256: "cdb975c40bd68f9585b3285c403585fbebb73551638faa668ea78259636b0472" },
    { path: `${GOLDEN_DIR}/zp-move-internal-expected-v1.sig.b64`, sha256: "62b5fcccdc4d7d17ee48a9e416bca4f64db5d62b9d482c026134db98eb8bf0d0" },
    { path: `${GOLDEN_DIR}/zp-send-external-expected-v1.preimage.txt`, sha256: "f094f981f833c908fae1fa661cb6d9f6c3cdf29bab792f2660b866c588f22cb5" },
    { path: `${GOLDEN_DIR}/zp-send-external-expected-v1.digest.hex`, sha256: "3bbed6945721e4cd33a1f17ed9e920ad0941a333c221e33b8655e25004d35af6" },
    { path: `${GOLDEN_DIR}/zp-send-external-expected-v1.sig.b64`, sha256: "b08f34d7ece5a11c12bca40c392f9c529c8699be2969b18002843b73a03ab343" },
    { path: `${GOLDEN_DIR}/node-identity.pub.b64`, sha256: "8eb7cca2ecabb7fb12e9d6f356ff4c204c64cb94f0db87b0ccad4649f69c7de0" },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
    "byte-golden:packages/generic-node-contracts/goldens/artifacts",
  ],
  sourceDocCitations: [
    "expected-artifact byte contract A.1, A.3",
    "byte goldens A.8-A.9",
    "observation verification",
    "artifacts-freeze",
  ],
});
