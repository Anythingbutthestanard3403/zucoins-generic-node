// TEST-ONLY fixture for minting landing-path oracle landing proofs in unit/e2e suites.
// Not a production settle API. Production mint is confined to landing-oracle-mint.ts and
// the three landing-path oracle producers. Enforced by landing-oracle-mint.discipline.test.ts.

export {
  issueLandingOracleSeal,
  mintLandingPathProof,
  mintLandingPathProofFromOracle,
  isLandingOracleSeal,
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  LANDING_PROOF_FAULTS,
  type LandingOracleSeal,
  type LandingOracleSealInput,
  type LandingPathProof,
  type LandingPathProofBinding,
  type LandingProofFault,
  type LandingProofFailure,
  type LandingProofOutcome,
} from "./landing-oracle-mint.js";
