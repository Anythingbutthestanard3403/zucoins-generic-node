// Concern barrel for the readiness / signer-leadership contract (the named concern). Public frozen
// surface for the concern-manifest registry assembly and the downstream the named concern (leader-gated engine startup)
// and the named concern (two-instance handoff proof) slices. This is NOT the package index
// (src/index.ts, the concern-manifest registry-owned) — it is the src/readiness/ concern's own export sequence.

export * from "./readiness-checks.contract.ts";
export * from "./boot-sequence.contract.ts";
export * from "./degraded-modes.contract.ts";
export * from "./fail-closed.contract.ts";
export * from "./predicates.ts";
export * from "./verifiers.ts";
export { READINESS_CONTRACT, READINESS_CONCERN_MANIFEST } from "./manifest.ts";
