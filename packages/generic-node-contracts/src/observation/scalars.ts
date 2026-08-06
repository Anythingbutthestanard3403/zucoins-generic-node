import {
  SHA256_HEX_PATTERN,
  PADDED_BASE64URL_PUBKEY_PATTERN,
  PADDED_BASE64URL_PUBKEY_LENGTH,
  PADDED_BASE64URL_SIGNATURE_PATTERN,
  PADDED_BASE64URL_SIGNATURE_LENGTH,
  ZKZ_BALANCE_TEXT_PATTERN,
} from "./scalars.contract.ts";

// Pure format matchers over the frozen scalar domain patterns. These check the boundary shape
// the DB CHECK enforces — not canonical Ed25519 validity, which is a later verification lane.
const sha256Hex = new RegExp(SHA256_HEX_PATTERN);
const paddedPubkey = new RegExp(PADDED_BASE64URL_PUBKEY_PATTERN);
const paddedSignature = new RegExp(PADDED_BASE64URL_SIGNATURE_PATTERN);
const zkzBalanceText = new RegExp(ZKZ_BALANCE_TEXT_PATTERN);

export const isSha256Hex = (value: string): boolean => sha256Hex.test(value);

export const isPaddedPubkey = (value: string): boolean =>
  value.length === PADDED_BASE64URL_PUBKEY_LENGTH && paddedPubkey.test(value);

export const isPaddedSignature = (value: string): boolean =>
  value.length === PADDED_BASE64URL_SIGNATURE_LENGTH && paddedSignature.test(value);

export const isEmptyOrPaddedSignature = (value: string): boolean =>
  value === "" || isPaddedSignature(value);

export const isZkzBalanceText = (value: string): boolean => zkzBalanceText.test(value);
