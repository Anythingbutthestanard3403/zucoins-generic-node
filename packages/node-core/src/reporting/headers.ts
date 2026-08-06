// exact-once extraction of the five mandatory signed reporting headers
// plus the mutation-route Idempotency-Key from the RAW header array. `req.headers`
// (node:http) comma-joins duplicates and is unusable for this check; only `rawHeaders`
// preserves occurrence counts and original case. Matching is case-insensitive on the name
// (HTTP/1 header names are case-insensitive); values are kept byte-verbatim — any form
// validation is the caller's bounded-shape stage.

export const REPORTING_HEADER_NAMES = {
  keyId: "x-zp-reporting-key-id",
  issuedAt: "x-zp-reporting-timestamp",
  expiresAt: "x-zp-reporting-expires-at",
  nonce: "x-zp-reporting-nonce",
  signature: "x-zp-reporting-signature",
  idempotencyKey: "idempotency-key",
} as const;

export type ExactHeaderRead =
  | { readonly kind: "ABSENT" }
  | { readonly kind: "DUPLICATE" }
  | { readonly kind: "ONE"; readonly value: string };

export function readExactHeader(rawHeaders: readonly string[], name: string): ExactHeaderRead {
  let found: string | null = null;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() !== name) continue;
    if (found !== null) return { kind: "DUPLICATE" };
    found = rawHeaders[index + 1]!;
  }
  return found === null ? { kind: "ABSENT" } : { kind: "ONE", value: found };
}

export interface ReportingSignedHeaders {
  readonly keyId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly signature: string;
}

export type ReportingSignedHeaderRead =
  | { readonly kind: "OK"; readonly headers: ReportingSignedHeaders }
  | { readonly kind: "MISSING_OR_DUPLICATE" };

// All five signed headers must be present exactly once each; any absence or repetition is the
// same bounded-shape failure (no hint about which header was wrong beyond the shared code).
export function readReportingSignedHeaders(
  rawHeaders: readonly string[],
): ReportingSignedHeaderRead {
  const keyId = readExactHeader(rawHeaders, REPORTING_HEADER_NAMES.keyId);
  const issuedAt = readExactHeader(rawHeaders, REPORTING_HEADER_NAMES.issuedAt);
  const expiresAt = readExactHeader(rawHeaders, REPORTING_HEADER_NAMES.expiresAt);
  const nonce = readExactHeader(rawHeaders, REPORTING_HEADER_NAMES.nonce);
  const signature = readExactHeader(rawHeaders, REPORTING_HEADER_NAMES.signature);
  if (
    keyId.kind !== "ONE" ||
    issuedAt.kind !== "ONE" ||
    expiresAt.kind !== "ONE" ||
    nonce.kind !== "ONE" ||
    signature.kind !== "ONE"
  ) {
    return { kind: "MISSING_OR_DUPLICATE" };
  }
  return {
    kind: "OK",
    headers: {
      keyId: keyId.value,
      issuedAt: issuedAt.value,
      expiresAt: expiresAt.value,
      nonce: nonce.value,
      signature: signature.value,
    },
  };
}
