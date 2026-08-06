// Concern barrel for the wallet-vault architecture ADR (the vault concern). Public frozen surface for
// the concern-manifest registry assembly and the downstream the vault schema freeze schema / the vault threat-model freeze threat-model lanes.
// This is NOT the package index (src/index.ts, the concern-manifest registry-owned) — it is the src/vault/ concern's
// own export sequence. Custody-sensitive: architecture only, no key access.

export * from "./storage.contract.ts";
export * from "./crypto.contract.ts";
export * from "./aad.contract.ts";
export * from "./lifecycle.contract.ts";
export * from "./compatibility.contract.ts";
export * from "./vault-verifier.ts";
// the vault schema freeze — schema, byte serializations, interfaces, failure behavior.
export * from "./vault-schema.contract.ts";
export * from "./aad-serialization.ts";
export * from "./hkdf-info.ts";
export * from "./interfaces.contract.ts";
export * from "./failure-behavior.ts";
export * from "./canonicalization.contract.ts";
export * from "./canonicalization.ts";
// the vault threat-model freeze — threat model + verification matrix.
export * from "./threat-model.contract.ts";
export * from "./threat-verifier.ts";
export { VAULT_CONTRACT, VAULT_CONCERN_MANIFEST } from "./manifest.ts";
