/**
 * The API wire conventions and the error envelope + status table; the frozen error
 * vocabulary (403 resolution).
 *
 * the fixture-provenance purposes census — the API manifest category. The route inventory stays OWNED by
 * `src/operations/routes.contract.ts`, the auth classes by `src/route-policy/`, and the
 * non-oracular 401/404 auth-error resolution by `src/auth-errors/`; this module freezes the
 * remaining wire/error-envelope vocabulary: the full nine-row HTTP status table, the error-envelope shape,
 * and the wire conventions. DATA ONLY so `gen/api.json` stays a clean review-diff snapshot.
 *
 * Emitted contract modules are import-free leaves (the emitter runs plain Node
 * type-stripping). Values shared with `src/auth-errors/envelope.ts` are restated here with
 * their owner named, and the census test asserts both freezes agree byte-for-byte — the
 * two-source drift-gate discipline (dedup target: the concern-manifest registry rollup).
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const API_CONTRACT_VERSION = 1 as const;

/** The error envelope's single outer key (API 1.1). */
export const API_ERROR_ENVELOPE_OUTER_KEY = "error" as const;

/** The inner error field sequence (API 1.1 example, verbatim). OWNED by
 *  `src/auth-errors/envelope.ts` (`ERROR_ENVELOPE_FIELD_ORDER`); restated here so the API
 *  category is complete, with the census test asserting the two freezes agree. */
export const API_ERROR_ENVELOPE_FIELD_SEQUENCE = [
  "code",
  "message",
  "request_id",
  "details",
] as const;

/**
 * The error-envelope contract HTTP status table, transcribed verbatim. The 403 row's canonical resolution is
 * the frozen error vocabulary: scope denial collapses onto the generic 401 `invalid_api_key` — no `403` auth-error
 * code exists in the v2 contract (the resolution is OWNED by `src/auth-errors/codes.ts`; the
 * status row is frozen here as API vocabulary).
 */
export const API_STATUS_TABLE = [
  { status: 400, meaning: "Malformed JSON, invalid scalar, unknown field, or impossible shape." },
  { status: 401, meaning: "Missing/invalid/expired authentication or TOTP." },
  {
    status: 403,
    meaning: "Authenticated principal lacks scope.",
    resolution: "scope denial collapses to the generic 401 invalid_api_key; no 403 auth-error code exists",
  },
  { status: 404, meaning: "Object is absent or outside the authenticated tenant." },
  {
    status: 409,
    meaning: "Idempotency, state-version, active-lease, T0, or other concurrent-state conflict.",
  },
  {
    status: 410,
    meaning: "Verification-material access window has expired. The underlying ledger is not deleted.",
  },
  { status: 422, meaning: "Well-formed request fails a custody/protocol predicate." },
  { status: 429, meaning: "Principal rate limit exceeded." },
  {
    status: 503,
    meaning:
      "Bounded queue is full, signer leadership unavailable, or required gateway evidence cannot currently be obtained.",
  },
] as const;

/** the error-envelope contract envelope semantics: clients branch on `code` only; `details` never carries secrets or
 *  cross-tenant existence information. */
export const API_ERROR_ENVELOPE_RULES = {
  messageIsDiagnosticNotStable: true,
  clientsBranchOnCodeOnly: true,
  detailsNeverContains: [
    "secrets",
    "raw signed bodies",
    "gateway responses",
    "existence information outside the caller's tenant",
  ],
} as const;

/** wire conventions, transcribed. */
export const API_WIRE_CONVENTIONS = {
  mediaType: "application/json; charset=utf-8",
  sseMediaTypeExcepted: true,
  propertyNames: "lower snake_case",
  uuidForm: "lowercase canonical textual form",
  amounts: "canonical positive decimal strings; JSON numbers rejected for all amount fields",
  timestamps:
    "RFC 3339 UTC strings with millisecond precision; protocol unix_time_secs values remain strings",
  unknownRequestProperties: "rejected with 400 unknown_field",
  absentOptionalProperty: "omitted",
  nullableProperty: "always present, JSON null when unavailable",
  operationStateField: "state",
  eventTypeField: "type",
  operationTypeField: "operation_type",
  idempotencyKey: {
    header: "Idempotency-Key",
    requiredOn: "every POST mutation unless the route is explicitly a read-like SSE connection",
    acceptedLength: "16-255 visible ASCII characters",
    replayHeader: "Idempotency-Replayed: true",
  },
} as const;

export const SOURCE = "API wire conventions and error envelope; non-oracular-auth-errors" as const;
