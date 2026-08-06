/**
 * The origin-classes CONTRACT_FREEZE: the frozen implementer-controlled-origin model — a compromised hosted
 * platform cannot be excluded from the threat model, so customer instructions are presented
 * and verified on an origin the platform cannot silently alter, checked against a node
 * identity key pinned through a channel independent of the hosted platform. This module
 * freezes the closed set of origin classes the generic core recognizes and, for each, whether
 * it may ever claim to defeat that substitution threat.
 *
 * `platform-hosted` is frozen at `false` UNCONDITIONALLY: a valid node artifact never makes a
 * platform-hosted presentation substitution-proof, because platform-controlled code controls
 * both what is shown and the check itself (R-07). This is a structural fact about the origin,
 * not a function of whether a pin was checked — see `presentation-handoff.contract.ts` for the
 * full decision table and the negative test proving this cannot be overridden.
 */

/** The closed set of instruction-origin classes the generic core recognizes. There
 *  is no "wallet-bound" class here — only the implementer-controlled-origin model is frozen; a
 *  wallet-side verification origin is out of scope until a separate reviewed freeze adds it. */
export const ORIGIN_CLASSES = [
  "node-origin",
  "implementer-controlled-origin",
  "platform-hosted",
] as const;

export type OriginClass = (typeof ORIGIN_CLASSES)[number];

/**
 * Frozen, per-origin-class claims (what a consumer of this contract may ever assert about an
 * instruction presented on that origin).
 *
 * - `canEverClaimSubstitutionProof`: `false` means NO combination of inputs — not even a valid
 *   node artifact and a correctly-checked pin — may ever cause this origin class to be
 *   reported as defeating the compromised-platform substitution threat. Only `platform-hosted`
 *   freezes this at `false`.
 * - `requiresIndependentPinToClaimSubstitutionProof`: for a class where
 *   `canEverClaimSubstitutionProof` is `true`, an independently-verified identity pin
 *   (`identity-pin.contract.ts`) is still a NECESSARY condition — origin control alone, without
 *   a pin check, is insufficient (see `presentation-handoff.contract.ts`'s decision table).
 * - `platformControlsOriginContent`: `true` iff the hosted platform can silently alter what is
 *   shown at this origin. This is the structural reason `platform-hosted` is frozen at `false`.
 */
export interface OriginClassClaims {
  readonly originClass: OriginClass;
  readonly canEverClaimSubstitutionProof: boolean;
  readonly requiresIndependentPinToClaimSubstitutionProof: boolean;
  readonly platformControlsOriginContent: boolean;
}

export const ORIGIN_CLASS_CLAIMS: readonly OriginClassClaims[] = [
  {
    originClass: "node-origin",
    canEverClaimSubstitutionProof: true,
    requiresIndependentPinToClaimSubstitutionProof: true,
    platformControlsOriginContent: false,
  },
  {
    originClass: "implementer-controlled-origin",
    canEverClaimSubstitutionProof: true,
    requiresIndependentPinToClaimSubstitutionProof: true,
    platformControlsOriginContent: false,
  },
  {
    originClass: "platform-hosted",
    canEverClaimSubstitutionProof: false,
    requiresIndependentPinToClaimSubstitutionProof: false,
    platformControlsOriginContent: true,
  },
] as const;

const CLAIMS_BY_CLASS = new Map(ORIGIN_CLASS_CLAIMS.map((c) => [c.originClass, c] as const));

export const claimsForOriginClass = (originClass: OriginClass): OriginClassClaims => {
  const claims = CLAIMS_BY_CLASS.get(originClass);
  if (!claims) {
    throw new Error(`no frozen claims for origin class: ${originClass}`);
  }
  return claims;
};

/**
 * Pure decision function: given an origin class and whether an independent identity pin was
 * successfully verified for this presentation, does the presentation defeat the
 * compromised-platform substitution threat? `platform-hosted` returns `false`
 * regardless of `pinIndependentlyVerified` — this is the frozen fact under test.
 */
export const isSubstitutionProof = (originClass: OriginClass, pinIndependentlyVerified: boolean): boolean => {
  const claims = claimsForOriginClass(originClass);
  if (!claims.canEverClaimSubstitutionProof) {
    return false;
  }
  return !claims.requiresIndependentPinToClaimSubstitutionProof || pinIndependentlyVerified;
};

export const SOURCE = "origin classes; implementer-controlled-origin model; instruction-origin-identity" as const;
