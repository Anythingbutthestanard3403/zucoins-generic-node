import { z } from "zod";

import {
  PROOF_BODY_SOURCE_KIND,
  PROOF_BODY_WALLET_ROLES,
  type ValidatedProofBody,
} from "./types.js";

// frozen Zod schema for the validated proof body (the shape that
// remains AFTER capture-before-parse, identity binding, strict UTF-8 decode, and
// duplicate-key detection have all passed).
//
// This mirrors the lineage_path_bodies column set field-for-field (minus the node-assigned
// path_proof_id primary-key component). Non-authority (landing-path oracle): these are
// supplied fields, never authoritative projections; the node independently
// re-derives S/P/B, the inner preimage, the digests, and the step signatures during
// verification. .strict means any unknown key fails closed — a supplied body cannot
// smuggle an extra field that overrides a node-canonical value.
//
// The byte-exact signing rule: byte-exact JSON.stringify — the schema validates structure only; it never
// reformats or re-serializes the captured bytes.

// The sha256_hex domain — lowercase hex, 64 chars.
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

// The padded_base64url_signature domain — a 64-byte Ed25519 signature is
// 86 base64url chars plus `==` padding (s_signature, step_1_signature, step_2_signature).
const PADDED_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}==$/;

// p_signature is the queried-wallet predecessor signature — empty for
// genesis, otherwise a padded base64url signature.
const P_SIGNATURE_PATTERN = /^$|^[A-Za-z0-9_-]{86}==$/;

// ZKZ amounts are canonical positive decimal strings; JSON numbers
// are rejected for all amount fields. This is the structural canonical ZKZ amount contract grammar shared with
// protocol/amounts.ts (CANONICAL_AMOUNT_PATTERN): 0 <= v < 1e8, <= 32 fractional digits.
const ZKZ_AMOUNT_PATTERN = /^(0|[1-9][0-9]{0,7})(?:\.[0-9]{1,32})?$/;

// The frozen field sequence. A freeze test pins the schema's key sequence to this exact
// list, so any field addition, removal, rename, or resequence fails the suite.
export const PROOF_BODY_FIELDS = [
  "path_index",
  "source_kind",
  "completed_transaction_text",
  "completed_transaction_sha256",
  "completed_transaction_octets",
  "wallet_role",
  "s_signature",
  "p_signature",
  "b_amount",
  "inner_preimage_text",
  "inner_sha256",
  "step_1_signature",
  "step_2_signature",
  "verification_manifest_text",
  "verification_manifest_sha256",
] as const;

export type ProofBodyField = (typeof PROOF_BODY_FIELDS)[number];

// The frozen schema. Field sequence matches PROOF_BODY_FIELDS exactly. .strict rejects
// unknown keys (unknown request properties are rejected).
export const proofBodySchema = z
  .object({
    path_index: z.number().int().nonnegative(),
    source_kind: z.literal(PROOF_BODY_SOURCE_KIND),
    completed_transaction_text: z.string().min(1),
    completed_transaction_sha256: z.string().regex(SHA256_HEX_PATTERN),
    completed_transaction_octets: z.number().int().positive(),
    wallet_role: z.enum(PROOF_BODY_WALLET_ROLES),
    s_signature: z.string().regex(PADDED_SIGNATURE_PATTERN),
    p_signature: z.string().regex(P_SIGNATURE_PATTERN),
    b_amount: z.string().regex(ZKZ_AMOUNT_PATTERN),
    inner_preimage_text: z.string().min(1),
    inner_sha256: z.string().regex(SHA256_HEX_PATTERN),
    step_1_signature: z.string().regex(PADDED_SIGNATURE_PATTERN),
    step_2_signature: z.string().regex(PADDED_SIGNATURE_PATTERN),
    verification_manifest_text: z.string().min(1),
    verification_manifest_sha256: z.string().regex(SHA256_HEX_PATTERN),
  })
  .strict();

// The inferred type is structurally identical to ValidatedProofBody; this compile-time
// check keeps the frozen interface (types.ts) and the Zod schema honest with each other.
// If the two ever diverge, SchemaMatchesInterface resolves to `never` and the `true`
// initializer below stops type-checking. The underscore-prefixed binding is ignored by the
// repo's no-unused-vars config.
type SchemaMatchesInterface = z.infer<typeof proofBodySchema> extends ValidatedProofBody
  ? ValidatedProofBody extends z.infer<typeof proofBodySchema>
    ? true
    : never
  : never;

const _schemaMatchesInterface: SchemaMatchesInterface = true;
