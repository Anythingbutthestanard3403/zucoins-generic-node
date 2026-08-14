// Fail-closed canonical request-target and timestamp policy for signed reporting reads
// and mutations. The target is the exact ASCII origin-form bytes captured by the outer trusted
// HTTP adapter; callers must never reconstruct it from a decoded URL or trust proxy rewrite
// headers. Governing: the canonical-fields report-request table, the api contract, and the pull-cursor authority rule.

export const REPORT_REQUEST_CLOCK_SKEW_MS = 0 as const;

const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NON_NEGATIVE_DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const UNRESERVED = /^[A-Za-z0-9._~-]+$/;

export interface CanonicalTargetResult {
  readonly ok: boolean;
  readonly reason: string | null;
}

const ok: CanonicalTargetResult = { ok: true, reason: null };
const fail = (reason: string): CanonicalTargetResult => ({ ok: false, reason });

export function parseCanonicalRfc3339Ms(value: string): number | null {
  if (!CANONICAL_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return null;
  return new Date(parsed).toISOString() === value ? parsed : null;
}

function canonicalIntegerInRange(value: string, min: number, max: number): boolean {
  if (!NON_NEGATIVE_DECIMAL.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max;
}

function validateQuery(
  rawQuery: string | null,
  allowed: Readonly<Record<string, (value: string) => boolean>>,
): CanonicalTargetResult {
  if (rawQuery === null) return ok;
  if (rawQuery.length === 0) return fail("empty query");

  let prior = "";
  const seen = new Set<string>();
  for (const pair of rawQuery.split("&")) {
    if (pair.length === 0) return fail("empty query pair");
    const equals = pair.indexOf("=");
    if (equals <= 0 || equals !== pair.lastIndexOf("=")) return fail("query pair must contain one equals");
    const name = pair.slice(0, equals);
    const value = pair.slice(equals + 1);
    if (!UNRESERVED.test(name) || !UNRESERVED.test(value)) return fail("query name/value not canonical ASCII");
    if (seen.has(name)) return fail("duplicate query key");
    if (prior !== "" && name <= prior) return fail("query keys not in ascending raw-ASCII sequence");
    const predicate = allowed[name];
    if (!predicate) return fail("query key not allowed for route");
    if (!predicate(value)) return fail("query value invalid for route");
    seen.add(name);
    prior = name;
  }
  return ok;
}

function noQuery(rawQuery: string | null): CanonicalTargetResult {
  return rawQuery === null ? ok : fail("query not allowed for route");
}

// Reject-only canonicalizer: it validates exact bytes and never decodes, normalizes, sorts,
// re-encodes, case-folds, or resolves them.
export function validateReportingRequestTarget(method: string, target: string): CanonicalTargetResult {
  if (method !== "GET" && method !== "POST") return fail("method must be exact GET or POST");
  if (!/^[\x21-\x7e]+$/.test(target)) return fail("target must be visible ASCII");
  if (!target.startsWith("/") || target.startsWith("//")) return fail("target must be origin-form");
  if (/[\\#%+]/.test(target)) return fail("target contains a forbidden byte");

  const question = target.indexOf("?");
  if (question !== target.lastIndexOf("?")) return fail("target contains multiple query delimiters");
  const path = question < 0 ? target : target.slice(0, question);
  const rawQuery = question < 0 ? null : target.slice(question + 1);
  if (path.length > 1 && path.endsWith("/")) return fail("path has trailing slash");
  const segments = path.slice(1).split("/");
  if (segments.some((segment) => segment.length === 0)) return fail("path has an empty segment");
  if (segments.some((segment) => segment === "." || segment === "..")) return fail("path has a dot segment");
  if (segments.some((segment) => !UNRESERVED.test(segment))) return fail("path segment not canonical ASCII");

  if (method === "GET" && path === "/v1/destinations") {
    return validateQuery(rawQuery, {
      after: (v) => LOWER_UUID.test(v),
      limit: (v) => canonicalIntegerInRange(v, 1, 100),
      state: (v) =>
        v === "PENDING" || v === "BLESSED" || v === "RETIRED" || v === "WORKER",
    });
  }
  if (method === "GET" && path === "/v1/events") {
    return validateQuery(rawQuery, {
      after_implementer_seq: (v) => NON_NEGATIVE_DECIMAL.test(v),
      limit: (v) => canonicalIntegerInRange(v, 1, 500),
      wait_seconds: (v) => canonicalIntegerInRange(v, 0, 30),
    });
  }
  if (method === "GET" && path === "/v1/events/stream") {
    return validateQuery(rawQuery, { after_implementer_seq: (v) => NON_NEGATIVE_DECIMAL.test(v) });
  }
  if (method === "GET" && path === "/v1/state/snapshot") return noQuery(rawQuery);

  const operation = path.match(/^\/v1\/operations\/([^/]+)\/(armed|verification-complete|verification-material)$/);
  if (operation) {
    const [, operationId, action] = operation;
    if (!LOWER_UUID.test(operationId!)) return fail("operation_id not a canonical lowercase UUID");
    const expectedMethod = action === "verification-material" ? "GET" : "POST";
    if (method !== expectedMethod) return fail("method not allowed for reporting route");
    return noQuery(rawQuery);
  }

  return fail("unknown signed reporting route");
}
