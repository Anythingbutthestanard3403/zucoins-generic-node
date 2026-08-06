// Concern barrel for the any-depth complete-path landing proof (the landing-proof concern). Public frozen surface for
// the concern-manifest registry assembly. This is NOT the package index (src/index.ts, the concern-manifest registry-owned) — it is the
// src/landing-proof/ concern's own export sequence, seeded by the landing-proof index/walk, extended by the landing-proof manifest builder, and
// closed by the landing-proof e2e (the fail-closed determination side).

export * from "./index-fields.contract.ts";
export * from "./linkage.contract.ts";
export * from "./fixtures.contract.ts";
export * from "./ancestry-index.ts";
export * from "./proof-manifest.contract.ts";
export * from "./proof-manifest.ts";
export * from "./proof-manifest.golden.contract.ts";
export * from "./fail-closed.contract.ts";
export * from "./landing-determination.ts";
export { LANDING_PROOF_CONTRACT, LANDING_PROOF_CONCERN_MANIFEST } from "./manifest.ts";
