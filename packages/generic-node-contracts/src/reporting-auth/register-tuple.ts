// the reporting-auth register tuple — The frozen `zp-reporting-register-v1` enrolment tuple: the reporting-key
// registration / proof-of-possession preimage. This discharges the pull-cursor authority rule build-blocker (Appendix A
// had no reporting-key enrolment preimage) and is now the frozen canonical contract.
// Appendix A.5.1 / A.8. The implementer self-signs this tuple with the reporting private key,
// proving possession of `new_reporting_public_key` and binding it to
// `(node_id, implementer_id, new_reporting_key_id)`.
//
// Governing contract: the reporting-key enrolment decision; the canonical suite serializer,
// field set, golden fixture, and negatives. Byte-exactness is the byte-exact signing rule: the preimage is built
// ONCE with an explicit key sequence and never reformatted. Custody is the key-custody rule: the node
// stores only the enrolled public key.

export const REPORTING_REGISTER_PURPOSE = "zp-reporting-register-v1" as const;
export const REPORTING_REGISTER_CANONICAL_VERSION = 1 as const;

// Ceremony window (`REPORTING_KEY_ENROL_WINDOW = 300 s`). `expires_at` is
// at most this many seconds after the SIGNED `issued_at` — the 5-minute enrolment class, NOT the
// 60-second automated-read window of `zp-report-request-v1`.
export const REPORTING_KEY_ENROL_WINDOW_SECS = 300 as const;

// The frozen insertion sequence of the register payload. Byte sequence IS the
// contract: `purpose` is both the domain-separation prefix and payload field 1; `canonical_version`
// is field 2. `supersedes_key_id` is `null` at bootstrap and the current active key id on rotation.
export const REGISTER_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "new_reporting_key_id",
  "new_reporting_public_key",
  "supersedes_key_id",
  "nonce",
  "issued_at",
  "expires_at",
] as const;

export interface ReportingRegisterPayload {
  readonly purpose: typeof REPORTING_REGISTER_PURPOSE;
  readonly canonical_version: typeof REPORTING_REGISTER_CANONICAL_VERSION;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly new_reporting_key_id: string;
  // Padded base64url Ed25519 public key being enrolled. Attacker-supplied here (unlike every other
  // suite tuple), so the PoP-verification path rejects a non-canonical / wrong-length /
  // small-subgroup / identity key BEFORE checking the PoP signature (crypto in the runtime
  // PoP layer).
  readonly new_reporting_public_key: string;
  // UUID of the key this rotates from during REPORTING_KEY_OVERLAP_WINDOW, or `null` at bootstrap.
  // Always present as JSON `null` when absent, never omitted (A.1.1 rule 7).
  readonly supersedes_key_id: string | null;
  // Node-issued single-use durable value per `(implementer_id, node_id)` — the replay / cross-bind
  // guard. Bundled with `node_id`, `implementer_id`, and the domain prefix in the bytes.
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

// Build the byte-exact preimage per A.1.1: `purpose + "\n" + JSON.stringify(payload)`, payload
// constructed in the frozen sequence and serialized exactly once (the byte-exact signing rule). No BOM, trailing
// newline, whitespace, key sorting, or normalization.
export function buildRegisterPreimage(p: ReportingRegisterPayload): string {
  const payload = {
    purpose: p.purpose,
    canonical_version: p.canonical_version,
    node_id: p.node_id,
    implementer_id: p.implementer_id,
    new_reporting_key_id: p.new_reporting_key_id,
    new_reporting_public_key: p.new_reporting_public_key,
    supersedes_key_id: p.supersedes_key_id,
    nonce: p.nonce,
    issued_at: p.issued_at,
    expires_at: p.expires_at,
  };
  return `${REPORTING_REGISTER_PURPOSE}\n${JSON.stringify(payload)}`;
}

// The A.8 deterministic golden payload — a BOOTSTRAP enrolment (`supersedes_key_id:null`).
// `new_reporting_key_id` extends the A.8 fixture letter series (aaaa=device_key_id, bbbb=event_id →
// cccc=reporting_key_id); `new_reporting_public_key` is the A.8 seed-0x04 reporting key; `nonce` is
// the A.8 fixture nonce; times use the A.8 5-minute enrolment window. Test-only, never live-chain.
export const REGISTER_GOLDEN_PAYLOAD: ReportingRegisterPayload = {
  purpose: REPORTING_REGISTER_PURPOSE,
  canonical_version: REPORTING_REGISTER_CANONICAL_VERSION,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  new_reporting_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  new_reporting_public_key: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
  supersedes_key_id: null,
  nonce: "99999999-9999-4999-8999-999999999999",
  issued_at: "2026-07-18T00:00:00.000Z",
  expires_at: "2026-07-18T00:05:00.000Z",
};

export const REGISTER_GOLDEN_PREIMAGE = buildRegisterPreimage(REGISTER_GOLDEN_PAYLOAD);
