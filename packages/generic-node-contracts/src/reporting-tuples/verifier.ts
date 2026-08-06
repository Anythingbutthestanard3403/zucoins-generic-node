// the reporting node-event purpose — Pure structural verifiers for the request and event tuples (A.9 classes that need no
// signature crypto, plus the 60s window, HTTP method/path form, event-type closure, seq form, and
// hash-chain linkage). Signature/event-hash crypto is exercised in the freeze test via node:crypto.
//
// Governing: the canonical-fields tuple tables, the closed event set, the api contract, and the pull-cursor authority rule.

import {
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_FIELD_ORDER,
  REPORT_REQUEST_MAX_WINDOW_SECONDS,
  REPORT_REQUEST_PURPOSE,
  buildReportRequestPreimage,
  type ReportRequestPayload,
} from "./request-tuple.js";
import {
  NEUTRAL_EVENT_TYPES,
  NODE_EVENT_CANONICAL_VERSION,
  NODE_EVENT_FIELD_ORDER,
  NODE_EVENT_PURPOSE,
  buildNodeEventPreimage,
  type NodeEventPayload,
} from "./event-tuple.js";
import {
  parseCanonicalRfc3339Ms,
  validateReportingRequestTarget,
} from "./request-target.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const RFC3339_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SEQ = /^[1-9][0-9]*$/;

export interface VerifyResult {
  readonly ok: boolean;
  readonly reason: string | null;
}
const ok: VerifyResult = { ok: true, reason: null };
const fail = (reason: string): VerifyResult => ({ ok: false, reason });

function splitPreimage(preimage: string, purpose: string): Record<string, unknown> | null {
  const lf = preimage.indexOf("\n");
  if (lf < 0 || preimage.slice(0, lf) !== purpose) return null;
  try {
    return JSON.parse(preimage.slice(lf + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

// Verify a `zp-report-request-v1` preimage: structure, UUIDs, method/path/body form, and the
// 60-second window measured against the SIGNED issued_at (never receipt time).
export function verifyReportRequestPreimage(preimage: string): VerifyResult {
  const p = splitPreimage(preimage, REPORT_REQUEST_PURPOSE);
  if (!p) return fail("prefix/purpose separator invalid");
  if (p.purpose !== REPORT_REQUEST_PURPOSE) return fail("payload purpose mismatch");
  if (p.canonical_version !== REPORT_REQUEST_CANONICAL_VERSION || typeof p.canonical_version !== "number") {
    return fail("canonical_version must be the number 1");
  }
  for (const field of REPORT_REQUEST_FIELD_ORDER) {
    if (p[field] === undefined) return fail(`missing field ${field}`);
  }
  for (const field of ["node_id", "implementer_id", "nonce"] as const) {
    if (typeof p[field] !== "string" || !UUID.test(p[field] as string)) return fail(`${field} not a UUID`);
  }
  if (typeof p.method !== "string" || typeof p.path !== "string") return fail("method/path must be strings");
  const target = validateReportingRequestTarget(p.method, p.path);
  if (!target.ok) return fail(target.reason ?? "request target invalid");
  if (typeof p.body_sha256 !== "string" || !HEX64.test(p.body_sha256)) return fail("body_sha256 not hex");
  for (const field of ["issued_at", "expires_at"] as const) {
    if (typeof p[field] !== "string" || parseCanonicalRfc3339Ms(p[field] as string) === null) {
      return fail(`${field} bad`);
    }
  }
  const delta = parseCanonicalRfc3339Ms(p.expires_at as string)! - parseCanonicalRfc3339Ms(p.issued_at as string)!;
  if (!(delta > 0)) return fail("expires_at must be later than issued_at");
  if (delta > REPORT_REQUEST_MAX_WINDOW_SECONDS * 1000) return fail("window exceeds 60 seconds");
  if (buildReportRequestPreimage(p as unknown as ReportRequestPayload) !== preimage) {
    return fail("non-canonical byte layout");
  }
  return ok;
}

// Verify a `zp-node-event-v1` preimage: structure, UUIDs, seq form, closed event type, nullable
// fields present-as-null, and digest/hash formats.
export function verifyNodeEventPreimage(preimage: string): VerifyResult {
  const p = splitPreimage(preimage, NODE_EVENT_PURPOSE);
  if (!p) return fail("prefix/purpose separator invalid");
  if (p.purpose !== NODE_EVENT_PURPOSE) return fail("payload purpose mismatch");
  if (p.canonical_version !== NODE_EVENT_CANONICAL_VERSION || typeof p.canonical_version !== "number") {
    return fail("canonical_version must be the number 1");
  }
  for (const field of NODE_EVENT_FIELD_ORDER) {
    if (p[field] === undefined) return fail(`missing field ${field}`);
  }
  for (const field of ["node_id", "event_id"] as const) {
    if (typeof p[field] !== "string" || !UUID.test(p[field] as string)) return fail(`${field} not a UUID`);
  }
  if (typeof p.seq !== "string" || !SEQ.test(p.seq)) return fail("seq not a positive decimal string");
  for (const field of ["operation_id", "wallet_id"] as const) {
    if (p[field] !== null && (typeof p[field] !== "string" || !UUID.test(p[field] as string))) {
      return fail(`${field} must be a UUID or null`);
    }
  }
  if (!(NEUTRAL_EVENT_TYPES as readonly string[]).includes(p.event_type as string)) {
    return fail("event_type not in the closed set");
  }
  if (typeof p.data_sha256 !== "string" || !HEX64.test(p.data_sha256)) return fail("data_sha256 not hex");
  if (p.previous_event_hash !== null && (typeof p.previous_event_hash !== "string" || !HEX64.test(p.previous_event_hash))) {
    return fail("previous_event_hash must be hex or null");
  }
  if (typeof p.created_at !== "string" || !RFC3339_MS.test(p.created_at)) return fail("created_at bad");
  if (buildNodeEventPreimage(p as unknown as NodeEventPayload) !== preimage) {
    return fail("non-canonical byte layout");
  }
  return ok;
}

// Hash-chain linkage: an event's previous_event_hash must equal the prior event's event_hash
// (null for the first event). This is the structural link; the freeze test recomputes event_hash.
export function eventChainLinks(priorEventHash: string | null, event: NodeEventPayload): boolean {
  return event.previous_event_hash === priorEventHash;
}
