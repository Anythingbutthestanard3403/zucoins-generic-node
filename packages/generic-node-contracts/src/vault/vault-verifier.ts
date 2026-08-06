import { REQUIRED_VAULT_MODEL } from "./storage.contract.ts";
import { type SealedStoreEntry } from "./compatibility.contract.ts";

/**
 * Pure architecture-conformance verifiers for the vault ADR. They neither read storage nor
 * perform any cryptographic operation; they check that a proposed model / sealed store matches
 * the frozen the vault-storage rule architecture, and return the frozen violation ids a candidate commits.
 */

export interface VaultModelDescriptor {
  readonly grain: string;
  readonly hybridPermitted: boolean;
  readonly keyDerivation: string;
  readonly nonceSource: string;
  readonly aadSource: string;
  readonly rotation: string;
}

const MODEL_VIOLATION_BY_FIELD = {
  grain: "GRAIN_NOT_PER_WALLET",
  hybridPermitted: "HYBRID_FORBIDDEN",
  keyDerivation: "KEY_DERIVATION_NOT_PER_WALLET_HKDF",
  nonceSource: "NONCE_NOT_FRESH_PER_SEAL",
  aadSource: "AAD_NOT_RECONSTRUCTED",
  rotation: "ROTATION_NOT_CRASH_SAFE",
} as const;

type ModelField = keyof typeof MODEL_VIOLATION_BY_FIELD;

const MODEL_FIELDS = Object.keys(MODEL_VIOLATION_BY_FIELD) as readonly ModelField[];

export const verifyVaultModelDescriptor = (
  descriptor: VaultModelDescriptor,
): readonly string[] =>
  MODEL_FIELDS.filter((field) => descriptor[field] !== REQUIRED_VAULT_MODEL[field]).map(
    (field) => MODEL_VIOLATION_BY_FIELD[field],
  );

export const isConformantVaultModel = (descriptor: VaultModelDescriptor): boolean =>
  verifyVaultModelDescriptor(descriptor).length === 0;

/**
 * A sealed store is conformant only when its key is per-store HKDF-derived and its nonce is
 * fresh per seal. A shared-key or reused-nonce shortcut is the exact regression the dual-run
 * addendum's census must catch.
 */
export const verifySealedStore = (entry: SealedStoreEntry): readonly string[] => {
  const violations: string[] = [];
  if (!entry.derivation.endsWith("HKDF")) violations.push("SHARED_KEY_SHORTCUT");
  if (entry.nonce !== "FRESH_PER_SEAL") violations.push("NONCE_SHORTCUT");
  return violations;
};
