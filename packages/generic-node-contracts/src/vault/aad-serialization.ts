/**
 * SOURCE: the vault-storage decision guard 2 (the 6-field AAD field set) + the AAD/HKDF
 * encoding decision (2026-07-19): extend the signing-custody newline-joined
 * convention to the frozen field sequence. Consistent with the reporting tuple pattern
 * (purpose + LF + fields). All field domains are newline-free (UUIDs, integer text, base64url,
 * enum), so newline-joining is unambiguous.
 *
 * STATUS: FROZEN. The AAD/HKDF encoding decision (2026-07-19)
 * CONFIRMED this encoding exactly as frozen. This is the byte contract
 * (the byte-exact signing rule) — never reformat the frozen strings.
 */

import { AAD_DOMAIN, AAD_BINDING } from "./aad.contract.ts";

export const AAD_SERIALIZATION = {
  status: "FROZEN",
  decision: "AAD/HKDF encoding decision 2026-07-19 (confirmed)",
  method: "NEWLINE_JOINED_UTF8",
  domain: "zp-wallet-secret-v1",
  field_sequence: ["domain", "node_id", "wallet_id", "key_version", "public_key", "key_origin"],
} as const;

export interface WalletSecretAadInputs {
  readonly nodeId: string;
  readonly walletId: string;
  readonly keyVersion: string;
  readonly publicKey: string;
  readonly keyOrigin: string;
}

/** Construct the exact UTF-8 AAD text. Deterministic string assembly; not a cryptographic op. */
export const buildWalletSecretAad = (inputs: WalletSecretAadInputs): string =>
  [
    AAD_DOMAIN,
    inputs.nodeId,
    inputs.walletId,
    inputs.keyVersion,
    inputs.publicKey,
    inputs.keyOrigin,
  ].join("\n");

/** The full serialization sequence must be the AAD domain followed by the vault model freeze's frozen field set.*/
export const AAD_FULL_FIELD_SEQUENCE = ["domain", ...AAD_BINDING.input_fields] as const;

/** Frozen golden with synthetic, obviously-fake inputs. `aad_sha256` pins the exact bytes. */
export const AAD_GOLDEN = {
  inputs: {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: "22222222-2222-4222-8222-222222222222",
    keyVersion: "1",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    keyOrigin: "node_generated",
  },
  aad_text:
    "zp-wallet-secret-v1\n11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nnode_generated",
  aad_sha256: "a88fa5bc689d90bd4d6b76b4bf6678b181864bf979b7fb9627117aca109f0e84",
} as const;
