/**
 * Per-operation verification-mode vocabulary (contracts: INDEPENDENT | NODE_VERIFIED).
 * Create-body omit → INDEPENDENT. Discovery / implementer-identity documents always
 * emit the field (ZTR-1319); those parsers fail closed on omit rather than inventing
 * this default. Unknown tokens fail closed.
 */

import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
  type VerificationMode,
} from "@zucoins/generic-node-contracts/operations";

export {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
  type VerificationMode,
} from "@zucoins/generic-node-contracts/operations";

const MODE_SET: ReadonlySet<string> = new Set(VERIFICATION_MODES);

export class VerificationModeDriftError extends Error {
  readonly code = "VERIFICATION_MODE_DRIFT" as const;
  readonly value: unknown;

  constructor(value: unknown) {
    super(
      `verification_mode ${JSON.stringify(value)} is outside the closed vocabulary ${VERIFICATION_MODES.join(" | ")}`,
    );
    this.name = "VerificationModeDriftError";
    this.value = value;
  }
}

export function isVerificationMode(value: unknown): value is VerificationMode {
  return typeof value === "string" && MODE_SET.has(value);
}

/**
 * Parse a wire `verification_mode`. `undefined` / `null` / omitted → INDEPENDENT.
 * Any other non-vocabulary token throws `VerificationModeDriftError`.
 */
export function parseVerificationMode(value: unknown): VerificationMode {
  if (value === undefined || value === null) return DEFAULT_VERIFICATION_MODE;
  if (isVerificationMode(value)) return value;
  throw new VerificationModeDriftError(value);
}
