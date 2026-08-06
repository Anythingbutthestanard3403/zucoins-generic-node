// Byte-exact serializations for the wallet-secret vault envelope. These strings are the
// AEAD associated data and the HKDF info that separate per-wallet keys; they are a byte
// contract (the byte-exact signing rule) and must never be reformatted.
//
// the builders and golden digests live in
// `@zucoins/generic-node-contracts/vault` (APPROVED_BY_PROXY). This module is a thin
// number→string adapter so node-core callers can keep keyVersion as a number while the
// frozen builders consume the wallet-vault AAD and HKDF-info minimal base-10 string encoding. Do not reimplement
// the join layout here — a second copy can drift from the pins that keep existing rows
// decryptable.
//
// Six-field AAD, reconstructed at open, never stored; the store is the `vault` table.
// Tests that pin digests: packages/node-core/test/vault.test.ts.

import { createHash } from "node:crypto";

import {
  AAD_DOMAIN,
  AAD_GOLDEN as FROZEN_AAD_GOLDEN,
  HKDF_DEK_LABEL,
  HKDF_INFO_GOLDEN as FROZEN_HKDF_INFO_GOLDEN,
  buildWalletDekInfo as frozenBuildWalletDekInfo,
  buildWalletSecretAad as frozenBuildWalletSecretAad,
} from "@zucoins/generic-node-contracts/vault";

export const WALLET_SECRET_AAD_DOMAIN = AAD_DOMAIN;
export const WALLET_DEK_HKDF_LABEL = HKDF_DEK_LABEL;

export interface WalletSecretAadFields {
  readonly nodeId: string;
  readonly walletId: string;
  readonly keyVersion: number;
  readonly publicKey: string;
  readonly keyOrigin: string;
}

export interface WalletDekInfoFields {
  readonly nodeId: string;
  readonly walletId: string;
  readonly keyVersion: number;
}

// Six-field newline-joined AAD: domain, node_id, wallet_id, key_version, public_key,
// key_origin. Reconstructed at open from the wallet's authoritative columns; never persisted
// as a column, so a row cannot carry an AAD that disagrees with its authoritative fields.
export function buildWalletSecretAad(fields: WalletSecretAadFields): string {
  return frozenBuildWalletSecretAad({
    nodeId: fields.nodeId,
    walletId: fields.walletId,
    keyVersion: String(fields.keyVersion),
    publicKey: fields.publicKey,
    keyOrigin: fields.keyOrigin,
  });
}

// Four-field newline-joined HKDF info: domain, node_id, wallet_id, key_version. The domain
// label is the only separation stopping two sealed stores deriving the same AES key under a
// shared root.
export function buildWalletDekInfo(fields: WalletDekInfoFields): string {
  return frozenBuildWalletDekInfo({
    nodeId: fields.nodeId,
    walletId: fields.walletId,
    keyVersion: String(fields.keyVersion),
  });
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Padded URLSAFE base64 (SplitChain key encoding). Buffer's base64url alphabet is already
// URLSAFE and unpadded; re-pad to a multiple of four.
export function toBase64UrlPadded(bytes: Uint8Array): string {
  const body = Buffer.from(bytes).toString("base64url");
  return body + "=".repeat((4 - (body.length % 4)) % 4);
}

// Frozen goldens — re-exported under node-core's number-keyVersion shape so existing
// callers keep working. Digests are taken from the frozen package, never re-declared here, so
// a local layout change cannot silently rewrite the pin.
export const AAD_GOLDEN = {
  fields: {
    nodeId: FROZEN_AAD_GOLDEN.inputs.nodeId,
    walletId: FROZEN_AAD_GOLDEN.inputs.walletId,
    keyVersion: Number(FROZEN_AAD_GOLDEN.inputs.keyVersion),
    publicKey: FROZEN_AAD_GOLDEN.inputs.publicKey,
    keyOrigin: FROZEN_AAD_GOLDEN.inputs.keyOrigin,
  },
  aadSha256: FROZEN_AAD_GOLDEN.aad_sha256,
} as const;

export const HKDF_INFO_GOLDEN = {
  fields: {
    nodeId: FROZEN_HKDF_INFO_GOLDEN.inputs.nodeId,
    walletId: FROZEN_HKDF_INFO_GOLDEN.inputs.walletId,
    keyVersion: Number(FROZEN_HKDF_INFO_GOLDEN.inputs.keyVersion),
  },
  infoSha256: FROZEN_HKDF_INFO_GOLDEN.info_sha256,
} as const;
