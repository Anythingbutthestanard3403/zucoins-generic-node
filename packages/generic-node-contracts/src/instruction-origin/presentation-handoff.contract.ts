/**
 * The presentation-handoff contract (threat/mitigation table; instruction-origin identity).
 *
 * the presentation scope audit CONTRACT_FREEZE: freezes (1) the exact data shape the generic core hands to an
 * implementer product for customer instruction presentation, and (2) the substitution-threat
 * decision table proving why an independently-pinned node/implementer-controlled origin (Q7
 * option 2) defeats the compromised-platform substitution scenario while platform-hosted
 * presentation never can, however the check is performed. Every type here is imported from the
 * concern that owns it (the artifacts concern artifacts, the presentation-scope concern.1 identity/origin) — never redeclared.
 *
 * C-05 ("platform has zero wallet-key custody") governs the mandatory negative: a handoff shape
 * carrying wallet key material is outside the frozen closed field set and is rejected by
 * `isValidPresentationHandoffShape`, structurally — not by a keyword denylist that could miss a
 * new field name.
 */
import type { ArtifactEnvelope } from "../artifacts/verify.ts";
import type { ExpectedArtifactPurpose } from "../artifacts/expected-artifacts.contract.ts";
import { DISCOVERY_PATH, type NodeIdentityPin } from "./identity-pin.contract.ts";
import { isSubstitutionProof, ORIGIN_CLASSES, type OriginClass } from "./origin-classes.contract.ts";

export { DISCOVERY_PATH };

const ORIGIN_CLASS_SET: ReadonlySet<string> = new Set(ORIGIN_CLASSES);

/**
 * Exact, frozen field sequence of the handoff object. A value with any field outside this
 * closed set — including any wallet key material — is rejected by
 * `isValidPresentationHandoffShape` (C-05). This is a whitelist, not a keyword denylist: an
 * unanticipated field name (e.g. a future `walletPrivateKey`) is caught by construction, not by
 * guessing every forbidden name in advance.
 */
export const PRESENTATION_HANDOFF_FIELDS = [
  "operationId",
  "artifactPurpose",
  "artifactEnvelope",
  "nodeIdentityPin",
  "discoveryPath",
  "originClass",
] as const;
export type PresentationHandoffField = (typeof PRESENTATION_HANDOFF_FIELDS)[number];

/**
 * The exact handoff from the generic core to an implementer product for customer instruction
 * presentation. Carries the signed expected artifact (the artifacts concern) the product must show/verify, the
 * implementer's own resolved identity pin state (the presentation-scope concern.1) so the product can render a
 * presentation-layer verified/unverified state, the discovery path the artifact's key can be
 * cross-checked against, and which origin class this presentation is being rendered on (so a
 * product cannot describe a platform-hosted render as if it were on an independently-pinned
 * origin). It NEVER carries a wallet private key, a signing capability, or any other custody
 * material (C-05, the key-custody rule) — the platform never touches private keys.
 */
export interface PresentationHandoff {
  readonly operationId: string;
  readonly artifactPurpose: ExpectedArtifactPurpose;
  readonly artifactEnvelope: ArtifactEnvelope;
  readonly nodeIdentityPin: NodeIdentityPin;
  readonly discoveryPath: string;
  readonly originClass: OriginClass;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Pure, structural shape validator: exact field membership AND sequence (closed set), plus a
 * shallow type check per field. Any additional field is rejected regardless of its name or
 * value — this is what makes the C-05 negative (wallet key material smuggled into a handoff)
 * fail by construction rather than by an incomplete keyword list.
 *
 * Closed field *values* for `originClass` are also required: only `ORIGIN_CLASSES` members
 * pass. An undeclared class must not reach `isSubstitutionProof` / `claimsForOriginClass`
 * (which throw on unknown classes) — the untrusted boundary refuses with `handoff_shape_invalid`.
 */
export const isValidPresentationHandoffShape = (value: unknown): value is PresentationHandoff => {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  if (
    keys.length !== PRESENTATION_HANDOFF_FIELDS.length ||
    keys.some((key, i) => key !== PRESENTATION_HANDOFF_FIELDS[i])
  ) {
    return false;
  }
  if (typeof value.operationId !== "string") return false;
  if (typeof value.artifactPurpose !== "string") return false;
  if (!isPlainObject(value.artifactEnvelope)) return false;
  if (!isPlainObject(value.nodeIdentityPin)) return false;
  if (typeof value.discoveryPath !== "string") return false;
  // Closed value set, not merely "is a string" — undeclared classes throw inside claimsForOriginClass.
  if (typeof value.originClass !== "string" || !ORIGIN_CLASS_SET.has(value.originClass)) return false;
  return true;
};

/**
 * One row of the substitution-threat decision table: for a given origin class, whether an
 * independent identity pin was verified, and whether the node artifact itself is valid, does
 * this presentation defeat the compromised-platform substitution threat? `substitutionProof`
 * here is DATA (what the table asserts); `isThreatTableRowConsistent` proves it agrees with the
 * frozen `isSubstitutionProof` decision function, so the table can never silently drift from
 * the function it documents.
 */
export interface SubstitutionThreatRow {
  readonly scenario: string;
  readonly originClass: OriginClass;
  readonly independentPinVerified: boolean;
  readonly nodeArtifactValid: boolean;
  readonly substitutionProof: boolean;
  readonly rationale: string;
}

export const SUBSTITUTION_THREAT_TABLE: readonly SubstitutionThreatRow[] = [
  {
    scenario: "a compromised platform substitutes a different, otherwise-valid instruction on a platform-hosted page",
    originClass: "platform-hosted",
    independentPinVerified: false,
    nodeArtifactValid: true,
    substitutionProof: false,
    rationale:
      "Platform-controlled code controls both what is shown and the check itself; a valid node artifact alone never proves the presented instruction is genuine (R-07).",
  },
  {
    scenario: "same substitution attempt on a platform-hosted page that ALSO performs its own pin check",
    originClass: "platform-hosted",
    independentPinVerified: true,
    nodeArtifactValid: true,
    substitutionProof: false,
    rationale:
      "platform-hosted is frozen non-substitution-proof unconditionally: the platform still controls the pin check itself, so a pin check IT performs proves nothing about independence.",
  },
  {
    scenario: "instruction presented on a node-controlled origin with an independently verified pin",
    originClass: "node-origin",
    independentPinVerified: true,
    nodeArtifactValid: true,
    substitutionProof: true,
    rationale:
      "An origin the platform cannot silently alter, plus a key check against a pin established outside the platform's control, defeats the substitution.",
  },
  {
    scenario: "instruction presented on an implementer-controlled origin with an independently verified pin",
    originClass: "implementer-controlled-origin",
    independentPinVerified: true,
    nodeArtifactValid: true,
    substitutionProof: true,
    rationale: "Same defense as node-origin: an origin the platform cannot alter, plus an independent pin check.",
  },
  {
    scenario: "node-controlled origin, but the pin was never independently verified",
    originClass: "node-origin",
    independentPinVerified: false,
    nodeArtifactValid: true,
    substitutionProof: false,
    rationale: "Origin control alone is insufficient; without a verified pin a substituted key is undetectable.",
  },
] as const;

/** True iff `row.substitutionProof` agrees with the frozen `isSubstitutionProof` decision
 *  function. Used to prove the table's data cannot silently diverge from the function it
 *  documents, and (negated) to catch a fabricated row that claims otherwise. */
export const isThreatTableRowConsistent = (row: SubstitutionThreatRow): boolean =>
  isSubstitutionProof(row.originClass, row.independentPinVerified) === row.substitutionProof;

export const SOURCE = "presentation handoff; implementer-controlled-origin model; instruction-origin-identity" as const;
