import { CANONICAL_FIELD_PINS, LABEL_FIELD_COUPLING } from "./canonicalization.contract.ts";

// Pure canonical-form validators over the frozen field pins. No key access.
const uuid = new RegExp(CANONICAL_FIELD_PINS.node_id.pin);
const keyVersion = new RegExp(CANONICAL_FIELD_PINS.key_version.pin);
const pubkey = new RegExp(CANONICAL_FIELD_PINS.public_key.pin);
const keyOrigin = new RegExp(CANONICAL_FIELD_PINS.key_origin.pin);

export const isCanonicalUuid = (value: string): boolean => uuid.test(value);
export const isMinimalKeyVersion = (value: string): boolean => keyVersion.test(value);
export const isCanonicalPublicKey = (value: string): boolean =>
  pubkey.test(value) && !value.includes("+") && !value.includes("/");
export const isCanonicalKeyOrigin = (value: string): boolean => keyOrigin.test(value);

/** LF-free is the injectivity precondition for the newline-joined encodings. */
export const isLineFeedFree = (value: string): boolean => !value.includes("\n");

/**
 * The label<->field-set coupling check: `true` means the proposed field count does NOT match the
 * label's frozen count, so a NEW `-vN` label is required (a 7th field can never be appended under
 * `-v1`). An unknown label also requires a new declared coupling.
 */
export const requiresNewLabel = (label: string, proposedFieldCount: number): boolean => {
  const entry = LABEL_FIELD_COUPLING.find((coupling) => coupling.label === label);
  if (entry === undefined) return true;
  return proposedFieldCount !== entry.field_count;
};
