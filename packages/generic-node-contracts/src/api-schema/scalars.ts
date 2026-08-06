import { Buffer } from "node:buffer";

import { z } from "zod";

import { validateBalanceAmount, validateOperationAmount } from "../amounts/validators.ts";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const WALLET_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}=$/;
const ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}==$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;
const RFC3339_MS_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ANCHOR_PATTERN = /^[A-Za-z0-9_-]{1,96}$/;

function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  const paddingLength = (4 - (unpadded.length % 4)) % 4;
  return `${unpadded}${"=".repeat(paddingLength)}`;
}

function isCanonicalPaddedBase64Url(
  value: string,
  pattern: RegExp,
  decodedLength: number,
): boolean {
  if (!pattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === decodedLength && paddedBase64Url(decoded) === value;
}

export const UuidSchema = z.string().regex(UUID_PATTERN, "must be a lowercase canonical UUID");

export const WalletPublicKeySchema = z.string().refine(
  (value) => isCanonicalPaddedBase64Url(value, WALLET_PUBLIC_KEY_PATTERN, 32),
  "must be canonical padded base64url encoding of exactly 32 bytes",
);

export const Ed25519SignatureSchema = z.string().refine(
  (value) => isCanonicalPaddedBase64Url(value, ED25519_SIGNATURE_PATTERN, 64),
  "must be canonical padded base64url encoding of exactly 64 bytes",
);

export const Sha256HexSchema = z
  .string()
  .regex(SHA256_HEX_PATTERN, "must be exactly 64 lowercase hexadecimal characters");

export const PositiveZkzAmountSchema = z.string().superRefine((value, context) => {
  if (validateOperationAmount(value).ok) return;
  context.addIssue({
    code: z.ZodIssueCode.custom,
    message: "must be a canonical ZKZ amount greater than zero and less than 100000000",
  });
});

export const ZkzBalanceSchema = z.string().superRefine((value, context) => {
  if (validateBalanceAmount(value).ok) return;
  context.addIssue({
    code: z.ZodIssueCode.custom,
    message: "must be a canonical ZKZ balance greater than or equal to zero and less than 100000000",
  });
});

export const PreviousStateSignatureSchema = z.union([
  z.literal(""),
  Ed25519SignatureSchema,
]);

export const Rfc3339MsSchema = z
  .string()
  .regex(RFC3339_MS_PATTERN, "must be an RFC 3339 UTC timestamp with millisecond precision")
  .refine((value) => {
    const parsed = new Date(value);
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
  }, "must be a valid RFC 3339 UTC timestamp");

export const AnchorSchema = z
  .string()
  .regex(ANCHOR_PATTERN, "must match ^[A-Za-z0-9_-]{1,96}$");

export const ClientReferenceSchema = z.string().max(256);
export const DescriptionSchema = z.string().max(512);
