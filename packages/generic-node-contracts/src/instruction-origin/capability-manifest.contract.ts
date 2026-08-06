/**
 * The frozen capability manifest of the generic core (discovery/proof surfaces;
 * instruction-origin identity).
 *
 * the presentation-scope concern.2 CONTRACT_FREEZE: packages, as a single frozen surface, the verification capabilities
 * the generic core exports to implementer products (R-07: "the generic core supplies discovery,
 * identity-key history, exact artifacts/proofs, rotation/revocation evidence, and verifier code
 * only"). Every FROZEN_AVAILABLE capability here IMPORTS its concrete implementation from the
 * concern that owns it — the artifacts concern for artifact verification, the presentation-scope concern.1 for the identity pin check
 * — nothing is redeclared. `PROOF_MATERIAL_ACCESS` corresponds to R-07's "operation proofs":
 * the landing-proof concern (any-depth landed-operation proof manifests) owns that surface, is NOT a
 * the presentation-scope concern dependency, and has not merged onto this concern's freeze base at freeze time. Its
 * capability id is frozen here as a reserved category ONLY — no interface is fabricated for it.
 * This silence is reported in the presentation-scope concern handoff, not silently papered over.
 *
 *  CONTRACT_FREEZE amendment: the artifacts concern artifact verification now takes its Ed25519/SHA-256
 * crypto as an injected `ArtifactVerificationCrypto` (the artifacts concern-owned, re-exported here) instead of
 * reaching the TEST-ONLY `testkit/independentCrypto` oracle at module load. The frozen verification
 * RESULTS on Appendix A's goldens are byte-identical; only the injection seam is added.
 */
import {
  verifyExpectedArtifact,
  type ArtifactEnvelope,
  type ArtifactVerificationCrypto,
  type VerifyInput,
  type VerifyResult,
  VERIFY_REJECT_REASONS,
} from "../artifacts/verify.ts";
import {
  verifyIdentityPin,
  type NodeIdentityPin,
  type PinVerdict,
  PIN_REJECT_REASONS,
} from "./identity-pin.contract.ts";

// Referenced so this module's frozen exported-symbol list is checked against real imports by
// `tsc`, not just spelled as free-standing strings — a rename/removal upstream fails the build.
export type { ArtifactEnvelope, ArtifactVerificationCrypto, VerifyInput, VerifyResult, NodeIdentityPin, PinVerdict };
export { verifyExpectedArtifact, VERIFY_REJECT_REASONS, verifyIdentityPin, PIN_REJECT_REASONS };

export const CAPABILITY_IDS = [
  "ARTIFACT_VERIFICATION",
  "IDENTITY_PIN_CHECK",
  "PROOF_MATERIAL_ACCESS",
] as const;
export type CapabilityId = (typeof CAPABILITY_IDS)[number];

export const CAPABILITY_STATUSES = ["FROZEN_AVAILABLE", "DEFERRED"] as const;
export type CapabilityStatus = (typeof CAPABILITY_STATUSES)[number];

export interface CapabilityDescriptor {
  readonly id: CapabilityId;
  readonly status: CapabilityStatus;
  readonly ownerConcern: string;
  readonly exportedSymbols: readonly string[];
  readonly description: string;
}

/** The three named capability categories assigned to the generic core, in their frozen
 *  listing sequence (discovery/identity-key history -> exact artifacts -> operation proofs). */
export const CAPABILITY_MANIFEST: readonly CapabilityDescriptor[] = [
  {
    id: "ARTIFACT_VERIFICATION",
    status: "FROZEN_AVAILABLE",
    ownerConcern: "artifacts",
    exportedSymbols: [
      "verifyExpectedArtifact",
      "VerifyInput",
      "VerifyResult",
      "VERIFY_REJECT_REASONS",
      "ArtifactEnvelope",
      "ArtifactVerificationCrypto",
    ],
    description:
      "Pure, stateless verification of the three signed expected-action artifacts against a resolved node identity key, with the wallet-libsodium Ed25519/SHA-256 crypto dependency-injected by the caller.",
  },
  {
    id: "IDENTITY_PIN_CHECK",
    status: "FROZEN_AVAILABLE",
    ownerConcern: "identity-pin",
    exportedSymbols: ["verifyIdentityPin", "NodeIdentityPin", "PinVerdict", "PIN_REJECT_REASONS"],
    description:
      "Pure predicate binding an implementer's independently-established node identity pin to a resolved key, defeating the compromised-platform substitution scenario.",
  },
  {
    id: "PROOF_MATERIAL_ACCESS",
    status: "DEFERRED",
    ownerConcern: "landing-proof",
    exportedSymbols: [],
    description:
      "Any-depth landed-operation proof manifests. Reserved capability category only — landing-proof is not an instruction-origin dependency and has not merged onto this freeze base; no interface is fabricated here.",
  },
] as const;

const CAPABILITY_BY_ID = new Map(CAPABILITY_MANIFEST.map((c) => [c.id, c] as const));

export const capabilityDescriptor = (id: CapabilityId): CapabilityDescriptor => {
  const descriptor = CAPABILITY_BY_ID.get(id);
  if (!descriptor) {
    throw new Error(`no frozen capability descriptor for: ${id}`);
  }
  return descriptor;
};

export const isCapabilityId = (id: string): id is CapabilityId =>
  (CAPABILITY_IDS as readonly string[]).includes(id);

export const isFrozenAvailable = (id: CapabilityId): boolean =>
  capabilityDescriptor(id).status === "FROZEN_AVAILABLE";

/**
 * Explicit non-capabilities: named things the generic core does NOT export and
 * never will under this freeze. A product owns every one of these; the core holds no data to
 * answer with (no UI, no origin-policy record, no pin-distribution channel, no rotation UX).
 * Frozen as its own closed set — disjoint from `CAPABILITY_IDS` by census (never merely implied
 * by omission), so nothing can silently promote one into a capability without a new,
 * reviewed freeze.
 */
export const NON_CAPABILITIES = [
  "CUSTOMER_INSTRUCTION_UI",
  "ORIGIN_POLICY_DECISION",
  "PIN_DISTRIBUTION_CHANNEL",
  "KEY_ROTATION_UX",
] as const;
export type NonCapability = (typeof NON_CAPABILITIES)[number];

export const isNonCapability = (id: string): id is NonCapability =>
  (NON_CAPABILITIES as readonly string[]).includes(id);

export const SOURCE = "capability manifest; implementer-controlled-origin model; instruction-origin-identity" as const;
