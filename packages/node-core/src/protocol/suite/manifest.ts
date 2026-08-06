// Machine census + the external-serialization prohibition datum for the suite serializer.
//
// The census enumerates every registered purpose, its signing key class, and its exact field
// sequence — a single structure a freeze test pins so a silent field reorder or a dropped/added
// purpose is caught. `EXTERNAL_SUITE_SERIALIZATION_PROHIBITED` is the datum the census asserts and the source
// scan enforces: `serializeSuiteTuple` is the only sanctioned path to a suite preimage, and calling
// JSON.stringify on a suite tuple anywhere else is a contract violation (spec).

import { SUITE_PURPOSES, suitePurposeSpec } from "./registry.js";

// The one sanctioned entrypoint name, carried as data so the census/source-scan can assert it.
export const SUITE_SERIALIZER_ENTRYPOINT = "serializeSuiteTuple" as const;

// The prohibition datum. External (ad-hoc) suite-tuple serialization is forbidden; the serializer is
// the sole path. Enforced two ways: the export shape yields only a finished preimage (no intermediate
// object to re-stringify), and the census source scan asserts no other node-core source file calls
// JSON.stringify on a registered suite purpose.
export const EXTERNAL_SUITE_SERIALIZATION_PROHIBITED = true as const;

export interface SuitePurposeCensus {
  readonly purpose: string;
  readonly keyClass: string;
  readonly fieldOrder: readonly string[];
}

export interface SuiteSerializerManifest {
  readonly canonicalEntrypoint: string;
  readonly externalSerializationProhibited: boolean;
  readonly domainSeparator: string;
  readonly purposeCount: number;
  readonly purposes: readonly SuitePurposeCensus[];
}

// Build the deterministic census. Purpose sequence follows the registry's frozen sequence; the field
// sequence is exactly what the serializer emits (the golden reproduction test proves it is byte-right).
export function buildSuiteSerializerManifest(): SuiteSerializerManifest {
  const purposes: SuitePurposeCensus[] = SUITE_PURPOSES.map((purpose) => {
    const specification = suitePurposeSpec(purpose);
    if (specification === undefined) {
      throw new Error(`registry census drift: ${purpose} is listed but has no spec`);
    }
    return {
      purpose: specification.purpose,
      keyClass: specification.keyClass,
      fieldOrder: specification.fields.map((fieldSpec) => fieldSpec.name),
    };
  });

  return {
    canonicalEntrypoint: SUITE_SERIALIZER_ENTRYPOINT,
    externalSerializationProhibited: EXTERNAL_SUITE_SERIALIZATION_PROHIBITED,
    // The domain separator is a single LF between the purpose prefix and the payload JSON (A.1.1).
    domainSeparator: "\n",
    purposeCount: purposes.length,
    purposes,
  };
}
