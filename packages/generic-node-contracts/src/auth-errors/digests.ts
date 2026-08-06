// the auth-errors/route-policy concern.1 — Digest pins for the byte-exact golden wire bodies (freeze tier 3).
//
// Each value is the lowercase-hex SHA-256 over the exact UTF-8 bytes of the canonical body
// (with the placeholder `request_id`), which is also the exact content of the committed raw
// artifact under `gen/`. The freeze test recomputes the digest from the builder output and
// from the raw file and asserts all three agree; any drift in the frozen body bytes fails
// the test. Regenerating a body is a deliberate paired change: update the builder inputs,
// the raw `gen/*.body.json` artifact, and the pin below in the same commit.

// SHA-256 of CANONICAL_AUTH_FAILURE_BODY / gen/auth-error-401.body.json (130 bytes).
export const SHA256_AUTH_FAILURE_BODY =
  "44fa5568b442479b191887b617c06c3d37ccb8c97f8c1c5d063362c540961e7e" as const;

// SHA-256 of CANONICAL_NOT_FOUND_BODY / gen/auth-error-404.body.json (118 bytes).
export const SHA256_NOT_FOUND_BODY =
  "949585168d1c03d64520afd562f8c1f8a11e7ddf7ee7133fad8d6bab1064d147" as const;
