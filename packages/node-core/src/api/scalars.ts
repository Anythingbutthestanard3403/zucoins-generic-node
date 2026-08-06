// Canonical scalar Zod schemas derived from.
// Every trust boundary validates through these; no raw string passes unchecked.
// PositiveZkzAmount is strictly < 100000000 (supersedes the proposal's "at most").
//
// Named with a `Schema` suffix to distinguish runtime Zod validators from the
// compile-time branded types in../protocol/scalars.ts.
//
// Pattern string constants are the single source for both Zod and the OpenAPI
// field inventory (request-bodies.ts) so the freeze cannot drift from runtime.

import { z } from "zod";
import {
  CANONICAL_DECIMAL_PATTERN,
  validateOperationAmount,
} from "@zucoins/generic-node-contracts/amounts";
import { parseWalletPublicKey, parseEd25519Signature } from "../protocol/scalars.js";

/** Lowercase canonical UUID (no uppercase). Shared with OpenAPI. */
export const UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

export const UuidSchema = z.string().regex(new RegExp(UUID_PATTERN), "must be lowercase canonical UUID");

// Canonical SplitChain wire encoding is PADDED base64url: 43 body chars + one `=`
// (44 total) for a 32-byte key. The charset excludes `=`, so the pattern must end in a
// literal `=`. The byte-length and canonical-re-encode check is delegated to the frozen
// protocol parser (../protocol/scalars.ts) so this API boundary can never drift from it.
export const WALLET_PUBKEY_PATTERN = "^[A-Za-z0-9_-]{43}=$";

export const WalletPublicKeySchema = z
  .string()
  .regex(new RegExp(WALLET_PUBKEY_PATTERN), "must be padded base64url, 44 chars")
  .refine((value) => {
    try {
      parseWalletPublicKey(value);
      return true;
    } catch {
      return false;
    }
  }, "must decode to exactly 32 bytes with canonical re-encode");

// Padded base64url: 86 body chars + `==` (88 total) for a 64-byte signature. Same
// delegation to the frozen protocol parser as WalletPublicKeySchema above.
export const ED25519_SIG_PATTERN = "^[A-Za-z0-9_-]{86}==$";

export const Ed25519SignatureSchema = z
  .string()
  .regex(new RegExp(ED25519_SIG_PATTERN), "must be padded base64url, 88 chars")
  .refine((value) => {
    try {
      parseEd25519Signature(value);
      return true;
    } catch {
      return false;
    }
  }, "must decode to exactly 64 bytes with canonical re-encode");

// ZkzAmount grammar: byte-identical to canonical ZKZ amount contract / generic-node-contracts CANONICAL_DECIMAL_PATTERN.
// Structurally enforces exclusive upper bound < 1e8 and ≤32 decimal places.
export const ZKZ_AMOUNT_PATTERN = CANONICAL_DECIMAL_PATTERN;

/**
 * OpenAPI pattern for operation amounts (PositiveZkzAmount).
 * Grammar of canonical ZKZ amount contract plus `(?=.*[1-9])` so pure-zero forms ("0", "0.0", …) fail the
 * published contract. Runtime still applies validateOperationAmount for numeric
 * positivity / canonical re-emit; this pattern is the structural half clients see.
 */
export const POSITIVE_ZKZ_OPENAPI_PATTERN =
  "^(?=.*[1-9])(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$";

export const ZkzAmountSchema = z
  .string()
  .regex(new RegExp(ZKZ_AMOUNT_PATTERN), "must be a canonical non-negative decimal string");

// PositiveZkzAmount: mathematically > 0 AND strictly < 100000000 (canonical ZKZ amount contract).
// Delegates to the frozen canonical validator which uses isNumericallyPositive
// (real decimal compare) — correctly rejects all zero forms including "0.0", "0.00", etc.
export const PositiveZkzAmountSchema = ZkzAmountSchema.refine(
  (value) => validateOperationAmount(value).ok,
  "must be > 0 and strictly < 100000000",
);

export const SHA256_HEX_PATTERN = "^[0-9a-f]{64}$";

export const Sha256HexSchema = z
  .string()
  .regex(new RegExp(SHA256_HEX_PATTERN), "must be exactly 64 lowercase hex chars");

export const UnixTimeSecsV2Schema = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/, "must be a non-negative decimal integer string");

export const OpaqueReferenceSchema = z.string().max(512);

export const ANCHOR_PATTERN = "^[A-Za-z0-9_-]{1,96}$";

export const AnchorSchema = z.string().regex(new RegExp(ANCHOR_PATTERN), "must match ^[A-Za-z0-9_-]{1,96}$");

/** Idempotency-Key bounds — / IdempotencyKeySchema. */
export const IDEMPOTENCY_KEY_MIN_LENGTH = 16;
export const IDEMPOTENCY_KEY_MAX_LENGTH = 255;
export const IDEMPOTENCY_KEY_PATTERN = "^[ -~]+$";

export const IdempotencyKeySchema = z
  .string()
  .min(IDEMPOTENCY_KEY_MIN_LENGTH, "must be 16-255 visible ASCII chars")
  .max(IDEMPOTENCY_KEY_MAX_LENGTH, "must be 16-255 visible ASCII chars")
  .regex(new RegExp(IDEMPOTENCY_KEY_PATTERN), "must be visible ASCII only");

export const Rfc3339MsSchema = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    "must be RFC 3339 UTC with millisecond precision",
  );

export const DECIMAL_SEQ_PATTERN = "^(0|[1-9][0-9]*)$";

export const DecimalSeqStringSchema = z
  .string()
  .regex(new RegExp(DECIMAL_SEQ_PATTERN), "must be a non-negative decimal string");
