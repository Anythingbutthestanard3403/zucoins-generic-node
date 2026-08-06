// opaque landing-path oracle landing-path proof capability (public/Stage-2 surface).
// 10,12;; changed-response observation ledger.
//
// A positive LandingPathProof is an ORACLE CAPABILITY, not structural data. Object literals
// and duck-typed impostors cannot satisfy the type (module-private brand symbol) and cannot
// pass the runtime identity guard (module-private WeakSet).
//
// Mint / seal issue is intentionally NOT exported from this module. The only settle-grade
// constructors live on landing-oracle-mint.ts and may be imported only by complete landing-path oracle
// producers (proveReceiveLanding / proveSendLanding / walkAncestryPath) and transactional
// durable-path revalidation (late-landing rebuild). Stage-2 consumers MUST call
// isLandingPathProof / revalidateLandingPathProofBindings before treating a value as
// landing authority. Tests mint only via landing-oracle-mint.fixture.ts.

export {
  LANDING_PROOF_FAULTS,
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  type LandingPathProof,
  type LandingPathProofBinding,
  type LandingProofFault,
  type LandingProofFailure,
  type LandingProofOutcome,
} from "./landing-oracle-mint.js";
