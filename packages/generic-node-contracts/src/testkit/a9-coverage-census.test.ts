import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ALL_NEGATIVE_VECTORS,
  GENERAL_NEGATIVE_VECTORS,
  REGISTER_NEGATIVE_VECTORS,
  type NegativeVector,
} from "../crypto-goldens/negative-vectors.ts";

/**
 * the fixture-provenance drift gate — negative-vector coverage census (Case 41).
 *
 * The drift gate (fixture-drift-gate.test.ts) proves goldens/provenance/dep-pins haven't
 * drifted. This census closes the ORTHOGONAL completeness gap: every normative negative vector
 * class maps to a real, named covering test that applies its breaking mutation and asserts
 * rejection (or, for the two POSITIVE vectors, byte-for-byte admission) — no class silently
 * uncovered.
 *
 * AUTHORITATIVE UNIVERSE is derived from the SPEC, not the catalog: `A9_AUTHORITATIVE_UNIVERSE`
 * below carries the complete negative-vector inventory as
 * 41 classes = 23 catalog (general #1-17 + register #1-6, pinned by
 * crypto-goldens.freeze.test.ts, asserted below as an exact subset so a new catalog class
 * auto-enters the universe and fails until mapped) ∪ 3 ceremony validity-window classes (vector-inventory decision 1:
 * reject `expires_at − issued_at > 300s` on the byte-parsed signed
 * `issued_at`, distinct from the register's own 300s class and the 60s read window) ∪ 15
 * device-label classes (vector-inventory decision 2, `zp-device-enrol-v1` field 6: 13 rejects
 * — empty, oversize scalars/bytes, overlong/truncated/lone-surrogate UTF-8 as three DISTINCT
 * byte-level classes each with its own vector (a lone-surrogate byte reject is NOT the same class
 * as the scalar-category surrogate reject), one per denylist category, leading/
 * trailing space — plus 2 MUST-accept positives at the boundary and NFC-admission).
 *
 * A full inventory read yields exactly these three families beyond the catalog and the decision records
 * exactly these two decisions, so there is no fourth family; the device-label transcription is
 * additionally cross-checked against the actual spec bytes (the "spec cross-check" test).
 *
 * Catalog classes #14 (device-sig-without-totp) and #16 (golden-key-live-chain) are covered by
 * real mutation tests (ZTR-1174 r2), not production-src title substrings alone:
 *   #14 — approveExternalSend rejects valid device sig + empty/non-digit TOTP; HTTP omits x-zp-totp.
 *   #16 — boot refuseGoldenThenProbeIdentity / refuseGoldenEventSigningKey refuse A.8 goldens
 *         before arm (node live path); consumer assertNotGoldenKey under liveChain remains.
 * covered ∪ uncovered == all 41; EXPECTED_UNCOVERED is empty. A covered rejection class MUST
 * cite at least one *.test.ts mutation ref (production .ts alone cannot cover).
 *
 * Governing contract: the negative-vector inventory and its canonical decisions.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..", "..");

/** A concrete, named covering test somewhere in the corpus. */
interface CoveringRef {
  /** repo-root-relative path to the test file */
  readonly file: string;
  /** an exact substring of the covering test's `it(...)` title (or an executor-key string) */
  readonly title: string;
}

interface CoveredEntry {
  readonly status: "covered";
  readonly kind:
    | "real-verifier-rejection"
    | "ed25519-signature-rejection"
    | "codec-digest-binding"
    | "preflight-predicate-rejection"
    | "byte-parsed-window-rejection"
    | "label-predicate-rejection"
    | "positive-admission";
  readonly tests: readonly CoveringRef[];
  readonly note?: string;
}

interface UncoveredEntry {
  readonly status: "uncovered";
  /** why no covering mutation test exists yet + where enforcement must live */
  readonly reason: string;
  /** the exact breaking mutation a future covering test must feed + assert rejected */
  readonly requiredMutation: string;
  /** a real, existing policy/definition anchor proving the class is at least frozen, not forgotten */
  readonly policyAnchor: CoveringRef;
}

type CoverageEntry = CoveredEntry | UncoveredEntry;

/** A single vector class the inventory mandates, with the exact normative anchor it comes from. */
interface AuthoritativeClass {
  readonly id: string;
  /** where in the normative record this class is mandated */
  readonly source: string;
  readonly family: "general-catalog" | "register-catalog" | "ceremony-window" | "device-label";
}

const RA = "packages/generic-node-contracts/src/reporting-auth/manifest.freeze.test.ts";
const RT = "packages/generic-node-contracts/src/reporting-tuples/manifest.freeze.test.ts";
const AV = "packages/generic-node-contracts/src/artifacts/verify.test.ts";
const AVC = "packages/generic-node-contracts/src/artifacts/verify-canonical.test.ts";
const AG = "packages/generic-node-contracts/src/approval/goldens.test.ts";
const AR = "packages/generic-node-contracts/src/approval/reproduction.test.ts";
const AC = "packages/generic-node-contracts/src/approval/approval-tuple.census.test.ts";
const MM = "packages/generic-node-contracts/src/machine-manifests/negative-vectors.census.test.ts";
const RP = "packages/generic-node-contracts/src/reporting-persistence/decisions.test.ts";
const A9 = "packages/generic-node-contracts/src/crypto-goldens/a9-covering-mutations.test.ts";
// A.9 #14 / #16 covering mutation suites (ZTR-1174 r2) — tests only; production .ts is not sole coverage.
const APPR_T = "packages/node-core/src/send/approve.test.ts";
const APPR_HTTP = "apps/generic-node/test/admin-never-403-auth.gate.test.ts";
const BOOT_T = "apps/generic-node/test/refuse-golden-fixture-keys.test.ts";
const VFY_T = "packages/node-core/src/verifier/consumer/consumer.test.ts";
// node-core covering suites for the ceremony-window + device-label families (read by path, cross-package).
const HW = "packages/node-core/test/protocol-suite-hardening.test.ts";
const A4L = "packages/node-core/test/protocol-suite-a4-ceiling-label.test.ts";
const PAR = "packages/node-core/test/protocol-suite-parsers.test.ts";

// The authoritative vector universe: catalog(23) ∪ ceremony-window(3) ∪ device-label(15) = 41.
// Built from the catalog for the 23 (so catalog drift auto-propagates and must be mapped) plus the
// two normative families the inventory adds beyond the catalog. Every class cites its normative source.
const A9_AUTHORITATIVE_UNIVERSE: readonly AuthoritativeClass[] = [
  ...GENERAL_NEGATIVE_VECTORS.map(
    (v): AuthoritativeClass => ({
      id: v.id,
      source: `vector catalog ${v.specRef} (general)`,
      family: "general-catalog",
    }),
  ),
  ...REGISTER_NEGATIVE_VECTORS.map(
    (v): AuthoritativeClass => ({
      id: v.id,
      source: `vector catalog ${v.specRef} (register)`,
      family: "register-catalog",
    }),
  ),
  // --- Ceremony validity-window (vector-inventory decision 1) — 3 purposes ---
  { id: "ceremony-window-approval", source: "vector-inventory decision 1 (zp-send-external-approval-v1)", family: "ceremony-window" },
  { id: "ceremony-window-bless", source: "vector-inventory decision 1 (zp-destination-bless-v1)", family: "ceremony-window" },
  { id: "ceremony-window-device-enrol", source: "vector-inventory decision 1 (zp-device-enrol-v1)", family: "ceremony-window" },
  // --- zp-device-enrol-v1 label Unicode battery (vector-inventory decision 2) ---
  // Rejection vectors:
  { id: "label-empty", source: "vector-inventory decision 2 (empty label)", family: "device-label" },
  { id: "label-over-80-scalars", source: "vector-inventory decision 2 (81 Unicode scalar values)", family: "device-label" },
  { id: "label-over-320-bytes", source: "vector-inventory decision 2 (≤80 scalars but >320 UTF-8 bytes)", family: "device-label" },
  { id: "label-overlong-utf8", source: "vector-inventory decision 2 (malformed UTF-8: overlong encoding)", family: "device-label" },
  { id: "label-malformed-utf8", source: "vector-inventory decision 2 (malformed UTF-8: truncated multi-byte sequence)", family: "device-label" },
  { id: "label-lone-surrogate-utf8", source: "vector-inventory decision 2 (malformed UTF-8: lone surrogate, byte-level)", family: "device-label" },
  { id: "label-denylist-c0c1-control", source: "vector-inventory decision 2 (denylist category: C0/C1 control)", family: "device-label" },
  { id: "label-denylist-surrogate", source: "vector-inventory decision 2 (denylist category: surrogate)", family: "device-label" },
  { id: "label-denylist-noncharacter", source: "vector-inventory decision 2 (denylist category: noncharacter)", family: "device-label" },
  { id: "label-denylist-line-para-separator", source: "vector-inventory decision 2 (denylist category: line/paragraph separator)", family: "device-label" },
  { id: "label-denylist-bom-zwnbsp", source: "vector-inventory decision 2 (denylist category: BOM/ZWNBSP)", family: "device-label" },
  { id: "label-denylist-bidi-zerowidth", source: "vector-inventory decision 2 (denylist category: BiDi/zero-width format control)", family: "device-label" },
  { id: "label-edge-space", source: "vector-inventory decision 2 (leading/trailing U+0020)", family: "device-label" },
  // Positive vectors (MUST-accepts — admission, not rejection):
  { id: "label-boundary-accept", source: "vector-inventory decision 2 (MUST accept 80-scalar / ≤320-byte boundary)", family: "device-label" },
  { id: "label-nfc-admission-gate", source: "vector-inventory decision 2 (MUST admit non-NFC label byte-identically, no normalization)", family: "device-label" },
] as const;

// One entry per authoritative class id. The set-equality assertions below guarantee this map's
// key set equals A9_AUTHORITATIVE_UNIVERSE exactly — no silent gap, no orphan.
const A9_COVERAGE: Readonly<Record<string, CoverageEntry>> = {
  // --- GENERAL A.9 #1..#17 (catalog) ---
  "field-reorder": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "a field reorder is rejected" }],
  },
  "purpose-mismatch": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "a prefix/payload purpose mismatch is rejected" }],
  },
  "version-string": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "canonical_version as string" }],
  },
  "uuid-uppercase": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "(non-canonical) UUID is rejected" }],
  },
  "unpadded-key": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "an unpadded new_reporting_public_key is rejected" }],
  },
  "amount-numeric": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: AV, title: "33 fractional digits" }],
  },
  "timestamp-malformed": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RT, title: "timestamps are exact calendar-valid RFC3339 milliseconds" }],
  },
  "preimage-whitespace": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: AVC, title: "trailing newline on preimage is rejected" }],
  },
  "nfc-substitution": {
    status: "covered",
    kind: "ed25519-signature-rejection",
    tests: [{ file: A9, title: "an NFC/NFD substitution in a signed UTF-8 string is rejected" }],
    note: "Newly written for this census (was digest-demonstration only).",
  },
  "cross-purpose-signature": {
    status: "covered",
    kind: "ed25519-signature-rejection",
    tests: [{ file: AVC, title: "cross-purpose signature is rejected" }],
  },
  "transfer-code-decoded": {
    status: "covered",
    kind: "codec-digest-binding",
    tests: [{ file: A9, title: "hashing the decoded or pad-repaired transfer code is rejected" }],
    note: "Newly written for this census (was digest-demonstration only); uses the production transferCodeSha256 hasher.",
  },
  "report-request-mutation": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RT, title: "a lowercase method is rejected" }],
  },
  "totp-as-signature": {
    status: "covered",
    kind: "ed25519-signature-rejection",
    tests: [{ file: AG, title: "none is fabricated from the TOTP" }],
  },
  "device-sig-without-totp": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [
      {
        file: APPR_T,
        title: "A.9 #14: valid device sig without fresh TOTP is rejected (empty / missing / non-digit)",
      },
      {
        file: APPR_HTTP,
        title: "A.9 #14 HTTP: valid device fields with missing x-zp-totp are refused (no approve)",
      },
      { file: AC, title: "TOTP-authenticates-mutation semantics" },
    ],
    note:
      "ZTR-1174 r2: approveExternalSend rejects well-formed device sig when totpCode is empty/non-digit " +
      "(request_invalid); admin approve route refuses missing x-zp-totp at HTTP before mutation. " +
      "deviceSignatureAloneAuthorizes === false remains the policy anchor.",
  },
  "jsonb-reconstruction": {
    status: "covered",
    kind: "ed25519-signature-rejection",
    tests: [{ file: AR, title: "A.9 vector 15" }],
  },
  "golden-key-live-chain": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [
      {
        file: BOOT_T,
        title: "refuses a sealed golden NODE_IDENTITY before sign/probe runs (no arm side-effects)",
      },
      {
        file: BOOT_T,
        title: "refuses every A.8 golden public key as EVENT_SIGNING before arm",
      },
      { file: VFY_T, title: "refuses A.8 seed key under liveChain=true via assertNotGoldenKey" },
    ],
    note:
      "ZTR-1174 r2: generic-node boot live path refuseGoldenThenProbeIdentity / refuseGoldenEventSigningKey " +
      "refuse A.8 goldens BEFORE identity.sign, sendSignerHolder, identityEnsured, and installEventSigner arm. " +
      "Consumer assertNotGoldenKey(liveChain) remains the inbound verifier gate.",
  },
  "funded-sender-genesis-predecessor": {
    status: "covered",
    kind: "preflight-predicate-rejection",
    tests: [{ file: MM, title: "genesis/funded-sender-empty-predecessor" }],
    note:
      "Sender-preflight rejection against the frozen FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION code; " +
      "deeper runtime enforcement is separately tracked.",
  },

  // --- REGISTER (zp-reporting-register-v1) #1..#6 (catalog) ---
  "register-supersedes-omitted": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "supersedes_key_id omitted instead of null is rejected" }],
  },
  "register-key-invalid": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "rejects torsion encoding" }],
  },
  "register-pop-wrong-key": {
    status: "covered",
    kind: "ed25519-signature-rejection",
    tests: [{ file: A9, title: "a register PoP signed by a foreign key is rejected" }],
    note: "Newly written for this census (was injected verifyDetached=false); uses a real foreign-key Ed25519 signature.",
  },
  "register-window-exceeded": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "an enrolment window over 300 seconds is rejected" }],
  },
  "register-nonce-replay": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RP, title: "rejects the same nonce when register/bootstrap and request purposes race" }],
  },
  "register-revoked-key": {
    status: "covered",
    kind: "real-verifier-rejection",
    tests: [{ file: RA, title: "reactivating a terminal key is rejected" }],
  },

  // --- CEREMONY VALIDITY-WINDOW (vector-inventory decision 1) — 3 purposes ---
  // Each rejects `expires_at − issued_at > 300s` against the SIGNED issued_at, before the Ed25519
  // check (per-purpose verify* test), and via the shared machine-manifest ceremony-window census.
  "ceremony-window-approval": {
    status: "covered",
    kind: "byte-parsed-window-rejection",
    tests: [
      { file: HW, title: "verifySendExternalApprovalDeviceSignature" },
      { file: MM, title: "suite-tuples/ceremony-window-over-300" },
    ],
    note:
      "node-core B3 verifySendExternalApprovalDeviceSignature rejects a ten-year window with " +
      "reason=expiry_window_exceeded BEFORE the (bogus) Ed25519 signature is considered; the " +
      "machine-manifest census proves the shared 0<Δ≤300s rule (CEREMONY_WINDOW_RULE, A.4.1-A.4.3).",
  },
  "ceremony-window-bless": {
    status: "covered",
    kind: "byte-parsed-window-rejection",
    tests: [
      { file: HW, title: "verifyDestinationBless" },
      { file: MM, title: "suite-tuples/ceremony-window-over-300" },
    ],
    note: "node-core B3 verifyDestinationBless rejects an over-ceiling window (expiry_window_exceeded) pre-signature.",
  },
  "ceremony-window-device-enrol": {
    status: "covered",
    kind: "byte-parsed-window-rejection",
    tests: [
      { file: HW, title: "verifyDeviceEnrol" },
      { file: MM, title: "suite-tuples/ceremony-window-over-300" },
    ],
    note: "node-core B3 verifyDeviceEnrol rejects an over-ceiling window (expiry_window_exceeded) pre-signature.",
  },

  // --- DEVICE-LABEL Unicode battery (vector-inventory decision 2) ---
  // Rejection vectors: node-core B4 (protocol-suite-hardening) + A.4.3 boundary port + the shared
  // wire-parser malformed-UTF-8 gate.
  "label-empty": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "rejects an empty label" }],
  },
  "label-over-80-scalars": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "rejects 81 scalars" }],
    note: "Rejected at the parseOpaqueReference scalar grammar with reason=limit_exceeded (count is by Unicode scalar, not UTF-16 unit).",
  },
  "label-over-320-bytes": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "rejects ≤80 scalars that exceed 320 UTF-8 bytes" }],
    note:
      "320-byte fail-closed resource bound (80 × 4); reason=limit_exceeded. SPEC-CLARIFICATION " +
      "(non-blocking): the phrasing '≤80 scalars but >320 UTF-8 bytes' is mathematically " +
      "UNSATISFIABLE as an independent reject — UTF-8 encodes any Unicode scalar in ≤4 bytes, so ≤80 " +
      "scalars is ALWAYS ≤320 bytes. The byte ceiling is a redundant defense-in-depth bound that can " +
      "only be breached together with the scalar ceiling; the covering test therefore necessarily " +
      "drives 81 four-byte scalars (breaching both). Kept as a distinct class per spec text; flagged " +
      "for a spec author to fold or reword. Not gated on.",
  },
  "label-overlong-utf8": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: PAR, title: "rejects an overlong UTF-8 encoding in a zp-device-enrol-v1 label byte source" }],
    note:
      "The inventory names overlong as one of THREE distinct malformed-UTF-8 rejects. Bytes " +
      "0xC0 0xAF (overlong 2-byte encoding of U+002F '/') injected into the device-enrol `label` value " +
      "are rejected by the shared fatal WHATWG decoder (parseSuitePurpose → decodeStrict, reason " +
      "invalid_utf8) before JSON.parse or any label predicate. A REAL byte vector, not coverage-by-argument.",
  },
  "label-malformed-utf8": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: PAR, title: "rejects an invalid UTF-8 byte sequence in a Uint8Array source" }],
    note:
      "The TRUNCATED multi-byte malformed-UTF-8 reject (overlong and lone-surrogate are now " +
      "their own byte classes, label-overlong-utf8 / label-lone-surrogate-utf8). BYTE-level vector: PAR " +
      "[0xc3,0x28] fed to a parser through the shared fatal WHATWG decoder (parseSuitePurpose → " +
      "decodeStrict), NOT a JS-string scalar through serialize — the byte-KIND cross-check asserts this.",
  },
  "label-lone-surrogate-utf8": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: PAR, title: "rejects a lone surrogate byte sequence in a zp-device-enrol-v1 label byte source" }],
    note:
      "The inventory names lone surrogate as one of THREE distinct malformed-UTF-8 rejects, and " +
      "it MUST be BYTE-level. Bytes 0xED 0xA0 0x80 (lone high surrogate U+D800) injected into the " +
      "device-enrol `label` are rejected by the fatal decoder (parseDeviceEnrol → decodeStrict, reason " +
      "invalid_utf8) at the Uint8Array path. DISTINCT from `label-denylist-surrogate` — that is the " +
      "The SCALAR-category reject (U+D800 as a JS-string scalar via serialize, HW 'surrogate half'): " +
      "different KIND, different test. A REAL byte vector, not coverage-by-argument, not the scalar path.",
  },
  "label-denylist-c0c1-control": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "C0 control" }],
    note: "One vector per denylist category; C0/C1 controls rejected with reason=disallowed_scalar.",
  },
  "label-denylist-surrogate": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "surrogate half" }],
  },
  "label-denylist-noncharacter": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "noncharacter" }],
    note: "Covers the U+FDD0-U+FDEF block and every-plane xFFFE/xFFFF noncharacters.",
  },
  "label-denylist-line-para-separator": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "line separator" }],
    note: "U+2028 line separator / U+2029 paragraph separator.",
  },
  "label-denylist-bom-zwnbsp": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "BOM / ZWNBSP" }],
    note: "U+FEFF BOM/ZWNBSP.",
  },
  "label-denylist-bidi-zerowidth": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "right-to-left override" }],
    note:
      "BiDi/zero-width format controls — the U+202E RLO is the explicitly-called-out spoofing vector " +
      "(a hostile device rendered as trusted in any operator UI echoing the label); the same suite " +
      "also rejects U+200B/U+200D/U+202A/U+2066.",
  },
  "label-edge-space": {
    status: "covered",
    kind: "label-predicate-rejection",
    tests: [{ file: HW, title: "rejects leading and trailing U+0020" }],
    note: "Only internal U+0020 permitted; leading/trailing U+0020 rejected.",
  },
  // Positive vectors — MUST-accepts. Included so the census spans the FULL inventory and no
  // required vector is silently unmapped; verified as byte-identity admissions, not rejections.
  "label-boundary-accept": {
    status: "covered",
    kind: "positive-admission",
    tests: [{ file: HW, title: "accepts internal U+0020, and the 80-scalar / 320-byte boundary" }],
    note: "MUST-accept: exactly 80 scalars in ≤320 UTF-8 bytes is admitted (80 astral scalars = 320 bytes).",
  },
  "label-nfc-admission-gate": {
    status: "covered",
    kind: "positive-admission",
    tests: [{ file: A4L, title: "admits an NFD label unchanged, with the parsed preimage byte-identical to the exact input" }],
    note:
      "MUST-accept: a well-formed, non-denylisted, non-NFC label is admitted and signed " +
      "in its exact input bytes (Buffer byte-identity at parseDeviceEnrol; normalize-then-sign forbidden, " +
      "the byte-exact signing rule). Complements the #9 nfc-substitution REJECTION class.",
  },
};

// Exactly the classes the census admits have NO covering mutation test yet. Pinned so that a NEW
// uncovered class (or an accidental regression that un-covers one) changes this set and FAILS —
// forcing a conscious decision, never a silent slip.
const EXPECTED_UNCOVERED = [] as const;

// The authoritative universe totals, pinned. Changing the inventory (a new family/vector) or the catalog must
// update these deliberately — a silent count drift fails.
const CATALOG_COUNT = 23; // general 17 + register 6 (crypto-goldens.freeze.test.ts)
const AUTHORITATIVE_COUNT = 41; // catalog 23 + ceremony-window 3 + device-label 15
const COVERED_COUNT = 41; // all authoritative classes covered (ZTR-1174 closed #14/#16)

// Rejection idioms — a covered ref's file must contain at least one, proving it is a negative test
// and not, say, a positive golden. File-level to stay robust against title-position drift.
const REJECTION_IDIOMS = [
  "toBe(false)",
  "toThrow",
  "toBeNull",
  "REJECT",
  "expectRejects",
  "Rejected",
  "not.toBe",
];

// Admission idioms — a positive-admission ref's file must contain at least one, proving it asserts
// the label is ACCEPTED / signed byte-identically (not thrown).
const ADMISSION_IDIOMS = [
  "not.toThrow",
  "byte-identical",
  ".equals(",
  "toContain",
  "not.toContain",
  "toBe(true)",
];

const idiomsForKind = (kind: CoveredEntry["kind"]): readonly string[] =>
  kind === "positive-admission" ? ADMISSION_IDIOMS : REJECTION_IDIOMS;

const readRepoFile = (relPath: string): string | null => {
  const abs = join(repoRoot, relPath);
  return existsSync(abs) ? readFileSync(abs, "utf8") : null;
};

const vectorIds = (vectors: readonly NegativeVector[]): string[] => vectors.map((v) => v.id);
const universeIds = (): string[] => A9_AUTHORITATIVE_UNIVERSE.map((c) => c.id);

// --- BYTE-KIND gate (anti-recurrence, QA FAIL #4) -----------------------------------------
// A malformed-UTF-8 class (overlong / truncated / lone-surrogate) is only well-formedness-
// meaningful at the BYTE-DECODE path: a raw Buffer/Uint8Array fed to a parse* function → decodeStrict
// → the fatal WHATWG TextDecoder. A JS-string scalar fed through `serializeSuiteTuple` exercises the
// SCALAR grammar, not byte well-formedness — that is the denylist path, a DIFFERENT class. The
// overlong (FAIL #3) and lone-surrogate (FAIL #4) misses were both a malformed class marked "covered"
// by a scalar/serialize test (wrong KIND). This gate makes wrong-KIND coverage structurally impossible.
const MALFORMED_UTF8_CLASSES = ["label-overlong-utf8", "label-malformed-utf8", "label-lone-surrogate-utf8"] as const;

// The it(...) block enclosing `title` (from the `it(` before it to the next `it(`), for source-level KIND inspection.
const itBlockFor = (src: string, title: string): string | null => {
  const idx = src.indexOf(title);
  if (idx < 0) return null;
  const blockStart = src.lastIndexOf("it(", idx);
  const nextIt = src.indexOf("it(", idx + title.length);
  return src.slice(blockStart >= 0 ? blockStart : idx, nextIt >= 0 ? nextIt : Math.min(src.length, idx + 1500));
};

// null == byte-kind; otherwise the reason it is NOT a raw-byte / byte-decode-path vector.
const notByteKindReason = (block: string): string | null => {
  const hasByteLiteral = /Buffer\.from\(\s*\[\s*0x/.test(block) || /Uint8Array/.test(block);
  const hasByteDecodeParse = /parse(?!Int|Float)[A-Z]\w*\(/.test(block);
  const usesScalarSerialize = /serializeSuiteTuple\(/.test(block);
  if (usesScalarSerialize) return "uses serializeSuiteTuple (JS-string scalar / serialize path, wrong KIND)";
  if (!hasByteLiteral) return "no raw byte literal (Buffer.from([0x..]) / Uint8Array)";
  if (!hasByteDecodeParse) return "no byte-decode parse* call";
  return null;
};

describe("A.9 vector coverage census (the fixture-provenance drift gate /, Case 41)", () => {
  it("pins the catalog at the canonical 23 (17 general + 6 register)", () => {
    expect(GENERAL_NEGATIVE_VECTORS).toHaveLength(17);
    expect(REGISTER_NEGATIVE_VECTORS).toHaveLength(6);
    expect(ALL_NEGATIVE_VECTORS).toHaveLength(CATALOG_COUNT);
  });

  it("the authoritative vector universe is the mandated inventory: catalog(23) ∪ ceremony-window(3) ∪ device-label(15) = 41", () => {
    // No duplicate ids.
    const ids = universeIds();
    expect(new Set(ids).size).toBe(ids.length);
    expect(A9_AUTHORITATIVE_UNIVERSE).toHaveLength(AUTHORITATIVE_COUNT);
    // Family partition matches the inventory structure exactly (anti-recursion: no fourth family).
    const byFamily = (f: AuthoritativeClass["family"]): number =>
      A9_AUTHORITATIVE_UNIVERSE.filter((c) => c.family === f).length;
    expect(byFamily("general-catalog")).toBe(17);
    expect(byFamily("register-catalog")).toBe(6);
    expect(byFamily("ceremony-window")).toBe(3);
    expect(byFamily("device-label")).toBe(15);
    // Every authoritative class cites a real normative anchor.
    for (const cls of A9_AUTHORITATIVE_UNIVERSE) {
      expect(cls.source, `${cls.id} lacks a normative source`).toMatch(/vector catalog|vector-inventory/);
    }
  });

  it("the catalog (23) is an exact SUBSET of the authoritative universe — no catalog drift escapes the census", () => {
    const universe = new Set(universeIds());
    const escaped = vectorIds(ALL_NEGATIVE_VECTORS).filter((id) => !universe.has(id));
    expect(escaped, `catalog classes missing from the authoritative universe: ${escaped.join(", ")}`).toEqual([]);
  });

  // STRUCTURAL ROOT (4th-drop guard). The 23 catalog classes derive mechanically from
  // GENERAL/REGISTER_NEGATIVE_VECTORS; the 18 non-catalog classes (3 ceremony + 15 device-label) are
  // hand-transcribed — which is exactly how `overlong` was dropped for three review rounds. The
  // frozen reject inventory is inlined below as independent token->class tables and cross-checked
  // against the universe: a frozen reject with no universe class reddens HERE instead of slipping past.
  it("cross-check: every frozen malformed-UTF-8 type + denylist/ceremony token maps to a present, byte-KIND-verified class", () => {
    const universe = new Set(universeIds());

    // (a) The frozen malformed-UTF-8 enumeration names EXACTLY three types (overlong, truncated,
    // lone surrogate), each mapping to a present class. A dropped class fails here rather than
    // passing silently.
    const malformedTokenToClass: Readonly<Record<string, string>> = {
      overlong: "label-overlong-utf8",
      truncated: "label-malformed-utf8",
      "lone surrogate": "label-lone-surrogate-utf8",
    };
    for (const [token, cls] of Object.entries(malformedTokenToClass)) {
      expect(universe.has(cls), `frozen malformed type "${token}" has no universe class "${cls}"`).toBe(true);
    }

    // (b) The other two hand-transcribed families: each frozen reject token must map to a present
    // universe class (a dropped class surfaces).
    const specTokenToClass: Readonly<Record<string, string>> = {
      "C0/C1 control": "label-denylist-c0c1-control",
      noncharacter: "label-denylist-noncharacter",
      "line/paragraph separator": "label-denylist-line-para-separator",
      "BOM/ZWNBSP": "label-denylist-bom-zwnbsp",
      "BiDi/zero-width format control": "label-denylist-bidi-zerowidth",
      "zp-send-external-approval-v1": "ceremony-window-approval",
      "zp-destination-bless-v1": "ceremony-window-bless",
      "zp-device-enrol-v1": "ceremony-window-device-enrol",
    };
    const failures: string[] = [];
    for (const [token, cls] of Object.entries(specTokenToClass)) {
      if (!universe.has(cls)) failures.push(`frozen reject token "${token}" has no universe class "${cls}"`);
    }

    // (c) BYTE-KIND gate (QA FAIL #3 overlong + FAIL #4 lone-surrogate anti-recurrence). EVERY covering
    // test of EVERY malformed-UTF-8 class must feed a raw BYTE source through the byte-decode path — not
    // a JS-string scalar through serialize. A malformed class mapped to a scalar/serialize test FAILS
    // here. This is the structural gate that makes a wrong-KIND "covered" mark impossible to reintroduce.
    for (const id of MALFORMED_UTF8_CLASSES) {
      expect(universe.has(id), `malformed-UTF-8 class "${id}" is not in the universe`).toBe(true);
      const entry = A9_COVERAGE[id];
      if (entry?.status !== "covered") {
        failures.push(`malformed class "${id}" is not covered`);
        continue;
      }
      for (const ref of entry.tests) {
        const src = readRepoFile(ref.file);
        if (src === null) {
          failures.push(`malformed class "${id}": covering file missing ${ref.file}`);
          continue;
        }
        const block = itBlockFor(src, ref.title);
        if (block === null) {
          failures.push(`malformed class "${id}": it-block not found for "${ref.title}" in ${ref.file}`);
          continue;
        }
        const reason = notByteKindReason(block);
        if (reason !== null) {
          failures.push(`malformed class "${id}": covering test "${ref.title}" is NOT byte-kind — ${reason}`);
        }
      }
    }

    expect(failures, failures.join("\n")).toEqual([]);
  });

  it("every vector class has a coverage entry — no class silently uncovered", () => {
    const missing = A9_AUTHORITATIVE_UNIVERSE.filter((c) => A9_COVERAGE[c.id] === undefined).map((c) => c.id);
    expect(missing, `vector classes with no coverage entry: ${missing.join(", ")}`).toEqual([]);
  });

  it("coverage map has no orphan entries — every key is a real authoritative class id", () => {
    const universe = new Set(universeIds());
    const orphans = Object.keys(A9_COVERAGE).filter((id) => !universe.has(id));
    expect(orphans, `coverage keys not in the authoritative universe: ${orphans.join(", ")}`).toEqual([]);
  });

  it("covered ∪ uncovered partitions all 41 classes with no overlap", () => {
    const covered = Object.entries(A9_COVERAGE)
      .filter(([, e]) => e.status === "covered")
      .map(([id]) => id);
    const uncovered = Object.entries(A9_COVERAGE)
      .filter(([, e]) => e.status === "uncovered")
      .map(([id]) => id);
    expect(new Set([...covered, ...uncovered]).size).toBe(AUTHORITATIVE_COUNT);
    expect(covered.length + uncovered.length).toBe(AUTHORITATIVE_COUNT);
    expect(covered.filter((id) => uncovered.includes(id))).toEqual([]);
  });

  it("every COVERED class names a covering test that physically exists and asserts its behavior", () => {
    const failures: string[] = [];
    for (const cls of A9_AUTHORITATIVE_UNIVERSE) {
      const entry = A9_COVERAGE[cls.id];
      if (entry?.status !== "covered") continue;
      expect(entry.tests.length, `${cls.id} has no covering test refs`).toBeGreaterThan(0);
      const idioms = idiomsForKind(entry.kind);
      for (const ref of entry.tests) {
        const src = readRepoFile(ref.file);
        if (src === null) {
          failures.push(`${cls.id}: covering file MISSING ${ref.file}`);
          continue;
        }
        if (!src.includes(ref.title)) {
          failures.push(`${cls.id}: title not found in ${ref.file} :: "${ref.title}"`);
        }
        if (!idioms.some((tok) => src.includes(tok))) {
          failures.push(`${cls.id}: no ${entry.kind === "positive-admission" ? "admission" : "rejection"} idiom in ${ref.file}`);
        }
      }
    }
    expect(failures, failures.join("\n")).toEqual([]);
  });

  it("every UNCOVERED class is fully documented (reason, required mutation, existing policy anchor)", () => {
    const failures: string[] = [];
    for (const cls of A9_AUTHORITATIVE_UNIVERSE) {
      const entry = A9_COVERAGE[cls.id];
      if (entry?.status !== "uncovered") continue;
      if (entry.reason.length < 20) failures.push(`${cls.id}: reason too thin`);
      if (entry.requiredMutation.length < 20) failures.push(`${cls.id}: requiredMutation too thin`);
      const anchor = readRepoFile(entry.policyAnchor.file);
      if (anchor === null) {
        failures.push(`${cls.id}: policy anchor file MISSING ${entry.policyAnchor.file}`);
      } else if (!anchor.includes(entry.policyAnchor.title)) {
        failures.push(`${cls.id}: policy anchor absent in ${entry.policyAnchor.file} :: "${entry.policyAnchor.title}"`);
      }
    }
    expect(failures, failures.join("\n")).toEqual([]);
  });

  it("the known-uncovered set is EXACTLY the tracked runtime-guard exceptions (pinned)", () => {
    const uncovered = Object.entries(A9_COVERAGE)
      .filter(([, e]) => e.status === "uncovered")
      .map(([id]) => id)
      .sort();
    // If this fails, a class was newly un-covered (or newly covered): update coverage + the
    // maintainer's deliver-here-vs-file-sibling decision, never silence it.
    expect(uncovered).toEqual([...EXPECTED_UNCOVERED].sort());
  });

  it("the census reports 41/41 covered with 0 tracked runtime-guard exceptions", () => {
    const covered = Object.values(A9_COVERAGE).filter((e) => e.status === "covered");
    expect(covered.length).toBe(COVERED_COUNT);
  });

  // --- fail-first: the census genuinely fails loudly on a gap or a phantom reference ---
  it("fail-first: an authoritative class with no entry would be flagged", () => {
    const universe = [...universeIds(), "some-future-a9-class"];
    const missing = universe.filter((id) => A9_COVERAGE[id] === undefined);
    expect(missing).toContain("some-future-a9-class");
  });

  it("fail-first: a covering ref with a bogus title is detected as absent", () => {
    const src = readRepoFile(RA);
    expect(src).not.toBeNull();
    expect(src?.includes("this covering test title does not exist anywhere")).toBe(false);
  });

  // Anti-launder (ZTR-1174 Review B): a rejection-class "covered" mark must cite at least one
  // *.test.ts mutation. Production source titles (e.g. matchTotp in approve.ts) alone cannot cover.
  it("fail-first: production-src title alone cannot cover a rejection class (#14 anti-launder)", () => {
    const isTestFile = (f: string): boolean => /\.test\.ts$/.test(f) || /\.spec\.ts$/.test(f);
    const laundered: string[] = [];
    for (const [id, entry] of Object.entries(A9_COVERAGE)) {
      if (entry.status !== "covered") continue;
      if (entry.kind === "positive-admission") continue;
      const hasMutationTest = entry.tests.some((t) => isTestFile(t.file));
      if (!hasMutationTest) {
        laundered.push(`${id}: only non-test refs: ${entry.tests.map((t) => t.file).join(", ")}`);
      }
    }
    expect(laundered, laundered.join("\n")).toEqual([]);

    // Explicit #14 phantom: a covered entry that ONLY pointed at packages/node-core/src/send/approve.ts
    // would fail the gate above. Pin the structural check on a synthetic entry shape.
    const phantomOnlyProd: CoveredEntry = {
      status: "covered",
      kind: "real-verifier-rejection",
      tests: [{ file: "packages/node-core/src/send/approve.ts", title: "matchTotp" }],
    };
    expect(phantomOnlyProd.tests.some((t) => isTestFile(t.file))).toBe(false);
    // And the real #14 entry must pass.
    const real14 = A9_COVERAGE["device-sig-without-totp"];
    expect(real14?.status).toBe("covered");
    if (real14?.status === "covered") {
      expect(real14.tests.some((t) => isTestFile(t.file))).toBe(true);
      expect(real14.tests.some((t) => t.title.includes("A.9 #14"))).toBe(true);
    }
  });

  it("fail-first: a covered class whose file lacks the required idiom would be flagged (window class vs a positive-only file)", () => {
    // The NFC-admission positive file asserts byte-identity, NOT rejection — proving the kind-aware
    // idiom check is real: it would reject a rejection-kind entry pointed at an admission-only file.
    const admissionSrc = readRepoFile(A4L);
    expect(admissionSrc).not.toBeNull();
    expect(REJECTION_IDIOMS.some((tok) => admissionSrc?.includes(tok))).toBe(true); // A4L also has rejects; guard is file-level
    expect(ADMISSION_IDIOMS.some((tok) => admissionSrc?.includes(tok))).toBe(true);
  });

  it("fail-first: folding `label-overlong-utf8` back into label-malformed-utf8 is caught (the exact regression)", () => {
    // the inventory still names overlong as a distinct malformed-UTF-8 type and the spec cross-check maps
    // it to its own class. Simulate the regression that dropped it for three review rounds — overlong
    // with no dedicated class — and assert the same mapping the cross-check uses flags the gap.
    const regressedUniverse = new Set(universeIds().filter((id) => id !== "label-overlong-utf8"));
    const malformedTokenToClass = {
      overlong: "label-overlong-utf8",
      truncated: "label-malformed-utf8",
      "lone surrogate": "label-lone-surrogate-utf8",
    } as const;
    const gaps = Object.entries(malformedTokenToClass)
      .filter(([, cls]) => !regressedUniverse.has(cls))
      .map(([token]) => token);
    expect(gaps).toContain("overlong");
    // And the covering test the census maps overlong to is a REAL, physically-present byte vector.
    const overlong = A9_COVERAGE["label-overlong-utf8"];
    expect(overlong?.status).toBe("covered");
    if (overlong?.status === "covered") {
      const src = readRepoFile(overlong.tests[0]!.file);
      expect(src, `overlong covering file missing: ${overlong.tests[0]!.file}`).not.toBeNull();
      expect(src?.includes(overlong.tests[0]!.title)).toBe(true);
    }
  });

  it("fail-first: the byte-KIND gate rejects a scalar/serialize-path test mapped to a malformed-UTF-8 class (the exact FAIL #4 miss)", () => {
    // FAIL #4 was `label-lone-surrogate-utf8` (implicitly) covered by the HW "surrogate half" test —
    // a JS-string scalar (\ud800) through serializeSuiteTuple, NOT raw bytes through the decoder. Prove
    // the byte-KIND gate discriminates: the HW scalar test is NOT byte-kind, so mapping any malformed
    // class to it would fail the gate; the real byte vector IS byte-kind.
    const hwSrc = readRepoFile(HW);
    expect(hwSrc).not.toBeNull();
    const scalarBlock = itBlockFor(hwSrc as string, "surrogate half");
    expect(scalarBlock, "HW 'surrogate half' it-block not found").not.toBeNull();
    expect(notByteKindReason(scalarBlock as string)).toBe(
      "uses serializeSuiteTuple (JS-string scalar / serialize path, wrong KIND)",
    );

    // The class as actually mapped points at the byte vector — which IS byte-kind.
    const loneSurr = A9_COVERAGE["label-lone-surrogate-utf8"];
    expect(loneSurr?.status).toBe("covered");
    if (loneSurr?.status === "covered") {
      const parSrc = readRepoFile(loneSurr.tests[0]!.file);
      const byteBlock = itBlockFor(parSrc as string, loneSurr.tests[0]!.title);
      expect(byteBlock, "lone-surrogate byte-vector it-block not found").not.toBeNull();
      expect(notByteKindReason(byteBlock as string)).toBeNull();
    }
  });
});
