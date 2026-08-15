// landing-path proof MINT channel (package-internal).
//
// Mint lives here — NOT on landing-proof.ts and NOT on any barrel — so a deep-import of
// the capability type module cannot issue settle-grade proofs from bare strings.
//
// ONLY these production modules may import this file (enforced by discrimination test):
// - src/verifier/landing-path-oracle.ts (proveReceiveLanding / proveSendLanding)
// - src/verifier/ancestry-walker.ts (walkAncestryPath)
// Tests import via landing-oracle-mint.fixture.ts only.

const landingPathProofBrand = Symbol("landingPathProofBrand");
const landingOracleSealBrand = Symbol("landingOracleSealBrand");

const issuedLandingPathProofs = new WeakSet<object>();
const issuedLandingOracleSeals = new WeakSet<object>();

export type LandingPathProof =
  | {
      readonly [landingPathProofBrand]: true;
      readonly kind: "LANDED_EXACT";
      readonly walletPubkeyBase64Urlsafe: string;
      readonly expectedBodySha256: string;
      readonly freshHeadBodySha256: string;
      readonly freshHeadObservationId: string;
      readonly depth: 0;
    }
  | {
      readonly [landingPathProofBrand]: true;
      readonly kind: "LANDED_COMPLETE_PATH";
      readonly walletPubkeyBase64Urlsafe: string;
      readonly expectedBodySha256: string;
      readonly freshHeadBodySha256: string;
      readonly freshHeadObservationId: string;
      readonly depth: number;
    };

export const LANDING_PROOF_FAULTS = [
  "MISSING_BODY",
  "GAP",
  "CONFLICT",
  "DUPLICATE",
  "CYCLE",
  "MALFORMED_BODY",
  "ANOMALOUS_OR_CONTRADICTORY",
  "BUDGET_EXHAUSTED",
] as const;
export type LandingProofFault = (typeof LANDING_PROOF_FAULTS)[number];

export interface LandingProofFailure {
  readonly kind: "PROOF_INCOMPLETE";
  readonly fault: LandingProofFault;
}

export type LandingProofOutcome = LandingPathProof | LandingProofFailure;

/**
 * Evidence that the complete landing-path oracle (or equivalent durable body revalidation) closed.
 * Opaque + single-use. Not imported by Stage-2; only the mint channel consumes seals.
 */
export interface LandingOracleSeal {
  readonly [landingOracleSealBrand]: true;
  readonly kind: LandingPathProof["kind"];
  readonly walletPubkeyBase64Urlsafe: string;
  readonly expectedBodySha256: string;
  readonly freshHeadBodySha256: string;
  readonly freshHeadObservationId: string;
  readonly depth: number;
}

export interface LandingOracleSealInput {
  readonly walletPubkeyBase64Urlsafe: string;
  readonly expectedBodySha256: string;
  readonly freshHeadBodySha256: string;
  readonly freshHeadObservationId: string;
  readonly depth: number;
}

function assertNonEmptyBinding(label: string, value: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`landing oracle seal ${label} must be a non-empty string`);
  }
}

/**
 * Issue the landing-path oracle seal. Call ONLY after dual fresh-head confirm (live oracle) or
 * transactional body revalidation (late-landing rebuild). Friend-channel only.
 */
export function issueLandingOracleSeal(input: LandingOracleSealInput): LandingOracleSeal {
  const { depth } = input;
  if (!Number.isInteger(depth) || depth < 0) {
    throw new Error(`landing path proof depth must be a non-negative integer, got ${depth}`);
  }
  assertNonEmptyBinding("walletPubkeyBase64Urlsafe", input.walletPubkeyBase64Urlsafe);
  assertNonEmptyBinding("expectedBodySha256", input.expectedBodySha256);
  assertNonEmptyBinding("freshHeadBodySha256", input.freshHeadBodySha256);
  assertNonEmptyBinding("freshHeadObservationId", input.freshHeadObservationId);

  if (depth === 0 && input.expectedBodySha256 !== input.freshHeadBodySha256) {
    throw new Error(
      "LANDED_EXACT requires expectedBodySha256 === freshHeadBodySha256 (exact-head anchor)",
    );
  }
  if (depth >= 1 && input.expectedBodySha256 === input.freshHeadBodySha256) {
    throw new Error(
      "LANDED_COMPLETE_PATH requires expectedBodySha256 !== freshHeadBodySha256 (buried head)",
    );
  }

  const kind: LandingPathProof["kind"] = depth === 0 ? "LANDED_EXACT" : "LANDED_COMPLETE_PATH";
  const seal: LandingOracleSeal = Object.freeze({
    [landingOracleSealBrand]: true as const,
    kind,
    walletPubkeyBase64Urlsafe: input.walletPubkeyBase64Urlsafe,
    expectedBodySha256: input.expectedBodySha256,
    freshHeadBodySha256: input.freshHeadBodySha256,
    freshHeadObservationId: input.freshHeadObservationId,
    depth,
  });
  issuedLandingOracleSeals.add(seal);
  return seal;
}

/** The ONLY constructor for LandingPathProof. Consumes the seal (single-use). Friend-channel only. */
export function mintLandingPathProof(seal: LandingOracleSeal): LandingPathProof {
  if (!issuedLandingOracleSeals.has(seal)) {
    throw new Error("landing path proof mint requires an issued oracle seal");
  }
  issuedLandingOracleSeals.delete(seal);

  if (seal.kind === "LANDED_EXACT") {
    if (seal.depth !== 0) {
      throw new Error(`LANDED_EXACT requires depth 0, got ${seal.depth}`);
    }
    const proof: LandingPathProof = Object.freeze({
      [landingPathProofBrand]: true as const,
      kind: "LANDED_EXACT" as const,
      walletPubkeyBase64Urlsafe: seal.walletPubkeyBase64Urlsafe,
      expectedBodySha256: seal.expectedBodySha256,
      freshHeadBodySha256: seal.freshHeadBodySha256,
      freshHeadObservationId: seal.freshHeadObservationId,
      depth: 0 as const,
    });
    issuedLandingPathProofs.add(proof);
    return proof;
  }
  if (seal.depth < 1) {
    throw new Error(`LANDED_COMPLETE_PATH requires depth >= 1, got ${seal.depth}`);
  }
  const proof: LandingPathProof = Object.freeze({
    [landingPathProofBrand]: true as const,
    kind: "LANDED_COMPLETE_PATH" as const,
    walletPubkeyBase64Urlsafe: seal.walletPubkeyBase64Urlsafe,
    expectedBodySha256: seal.expectedBodySha256,
    freshHeadBodySha256: seal.freshHeadBodySha256,
    freshHeadObservationId: seal.freshHeadObservationId,
    depth: seal.depth,
  });
  issuedLandingPathProofs.add(proof);
  return proof;
}

/**
 * Seal then mint. Production callers: proveReceiveLanding / proveSendLanding /
 * walkAncestryPath / late-landing body rebuild only.
 */
export function mintLandingPathProofFromOracle(input: LandingOracleSealInput): LandingPathProof {
  return mintLandingPathProof(issueLandingOracleSeal(input));
}

export function isLandingOracleSeal(value: unknown): value is LandingOracleSeal {
  return typeof value === "object" && value !== null && issuedLandingOracleSeals.has(value);
}

export function isLandingPathProof(value: unknown): value is LandingPathProof {
  return typeof value === "object" && value !== null && issuedLandingPathProofs.has(value);
}

export interface LandingPathProofBinding {
  readonly walletPubkeyBase64Urlsafe: string;
  readonly expectedBodySha256: string;
  readonly freshHeadObservationId?: string;
  readonly freshHeadBodySha256?: string;
}

/**
 * Stage-2 transactional revalidation: issued capability + independent external limbs.
 * Never compare proof fields to themselves.
 */
export function revalidateLandingPathProofBindings(
  proof: unknown,
  binding: LandingPathProofBinding,
): proof is LandingPathProof {
  if (!isLandingPathProof(proof)) return false;
  if (proof.walletPubkeyBase64Urlsafe !== binding.walletPubkeyBase64Urlsafe) return false;
  if (proof.expectedBodySha256 !== binding.expectedBodySha256) return false;
  if (
    binding.freshHeadObservationId !== undefined &&
    proof.freshHeadObservationId !== binding.freshHeadObservationId
  ) {
    return false;
  }
  if (
    binding.freshHeadBodySha256 !== undefined &&
    proof.freshHeadBodySha256 !== binding.freshHeadBodySha256
  ) {
    return false;
  }
  return true;
}
