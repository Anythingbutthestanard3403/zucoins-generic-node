import {
  FIXTURE_BYTE_CLASSES,
  FIXTURE_ORIGIN_KINDS,
  type FixtureByteClass,
  type FixtureOriginKind,
  type FixtureProvenanceRecord,
} from "./types.ts";

/**
 * Structural validation for fixture provenance records — the negative-path gate. A record
 * with a missing, blank, or malformed required field fails here with one violation string per
 * defect found; a valid record returns an empty list. Accepts `unknown` so malformed input
 * (a hand-edited record, a future JSON form) is validated rather than assumed well-typed.
 *
 * "No silently-blank field": where a field is not applicable to a record's origin kind the
 * record must carry an explicit sentinel explaining why — an empty string is always a
 * violation, never a default.
 */

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const INDEX_PATH = /(?:^|\/)(?:[^/]+\.(?:meta|vectors)\.json|manifest\.json)$/;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const nonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

const nonEmptyStringArray = (value: unknown): boolean =>
  Array.isArray(value) && value.length > 0 && value.every(nonEmptyString);

const isValidCalendarDate = (value: string): boolean => {
  const match = ISO_DATE.exec(value);
  if (!match) {
    return false;
  }
  const [, year, month, day] = match;
  const parsed = new Date(`${year}-${month}-${day}T00:00:00Z`);
  return (
    !Number.isNaN(parsed.getTime()) &&
    parsed.toISOString().startsWith(`${year}-${month}-${day}`)
  );
};

const validateFiles = (files: unknown, violations: string[]): void => {
  if (!Array.isArray(files) || files.length === 0) {
    violations.push("files must be a non-empty array");
    return;
  }
  const seen = new Set<string>();
  for (const [index, entry] of files.entries()) {
    if (!isRecord(entry)) {
      violations.push(`files[${index}] must be an object`);
      continue;
    }
    if (!nonEmptyString(entry.path)) {
      violations.push(`files[${index}].path must be a non-empty string`);
    } else if (entry.path.startsWith("/") || entry.path.includes("..") || entry.path.includes("\\")) {
      violations.push(`files[${index}].path must be a package-relative POSIX path: ${entry.path}`);
    } else if (seen.has(entry.path)) {
      violations.push(`files[${index}].path is duplicated: ${entry.path}`);
    } else {
      seen.add(entry.path);
    }
    if (typeof entry.sha256 !== "string" || !SHA256_HEX.test(entry.sha256)) {
      violations.push(`files[${index}].sha256 must be a lowercase 64-hex digest`);
    }
  }
};

const validateProvenance = (provenance: unknown, violations: string[]): void => {
  if (!isRecord(provenance)) {
    violations.push("provenance must be an object");
    return;
  }
  if (
    typeof provenance.originKind !== "string" ||
    !(FIXTURE_ORIGIN_KINDS as readonly string[]).includes(provenance.originKind)
  ) {
    violations.push(`provenance.originKind must be one of ${FIXTURE_ORIGIN_KINDS.join(", ")}`);
  }
  for (const field of ["captureMethod", "captureDate", "walletVersion", "source", "keyMaterial"] as const) {
    if (!nonEmptyString(provenance[field])) {
      violations.push(`provenance.${field} must be a non-empty string (use an explicit n/a sentinel, never blank)`);
    }
  }
  if (typeof provenance.captureDate === "string" && !isValidCalendarDate(provenance.captureDate)) {
    violations.push(`provenance.captureDate must be a real ISO calendar date: ${provenance.captureDate}`);
  }
  if (!nonEmptyStringArray(provenance.specCitations)) {
    violations.push("provenance.specCitations must be a non-empty array of non-empty strings");
  }
  if (!nonEmptyStringArray(provenance.decisionRefs)) {
    violations.push("provenance.decisionRefs must be a non-empty array of non-empty strings");
  }
  if (provenance.details !== undefined) {
    const details = provenance.details;
    if (!isRecord(details) || !Object.values(details).every(nonEmptyString)) {
      violations.push("provenance.details must map strings to non-empty strings");
    }
  }
};

/**
 * Every structural violation in `candidate`, or an empty list when it is a valid record.
 * This is the check a missing/malformed provenance record must fail.
 */
export const validateFixtureRecord = (candidate: unknown): readonly string[] => {
  const violations: string[] = [];
  if (!isRecord(candidate)) {
    return ["record must be an object"];
  }
  if (!nonEmptyString(candidate.fixtureId)) {
    violations.push("fixtureId must be a non-empty string");
  }
  if (
    typeof candidate.byteClass !== "string" ||
    !(FIXTURE_BYTE_CLASSES as readonly string[]).includes(candidate.byteClass)
  ) {
    violations.push(`byteClass must be one of ${FIXTURE_BYTE_CLASSES.join(", ")}`);
  }
  if (!nonEmptyString(candidate.indexPath)) {
    violations.push("indexPath must be a non-empty string");
  } else if (!INDEX_PATH.test(candidate.indexPath)) {
    violations.push(`indexPath must name a *.meta.json, manifest.json, or *.vectors.json file: ${candidate.indexPath}`);
  }
  validateFiles(candidate.files, violations);
  if (
    Array.isArray(candidate.files) &&
    typeof candidate.indexPath === "string" &&
    !candidate.files.some((entry) => isRecord(entry) && entry.path === candidate.indexPath)
  ) {
    violations.push("indexPath must be a member of the record's own files digest set");
  }
  validateProvenance(candidate.provenance, violations);
  return violations;
};

/** The independently-pinned expectation a registered record must match (independent verification). */
export interface FixtureExpectation {
  readonly byteClass: FixtureByteClass;
  readonly originKind: FixtureOriginKind;
  readonly captureDate: string;
}

/**
 * Mismatches between a record and an independently-pinned expectation — the mechanism the
 * expectation tests use, so mutating a record's byte-class flag or capture date reddens the
 * suite. Returns one string per drifted field, empty when the record matches.
 */
export const diffFixtureExpectation = (
  record: FixtureProvenanceRecord,
  expectation: FixtureExpectation,
): readonly string[] => {
  const drift: string[] = [];
  if (record.byteClass !== expectation.byteClass) {
    drift.push(`byteClass: expected ${expectation.byteClass}, got ${record.byteClass}`);
  }
  if (record.provenance.originKind !== expectation.originKind) {
    drift.push(`originKind: expected ${expectation.originKind}, got ${record.provenance.originKind}`);
  }
  if (record.provenance.captureDate !== expectation.captureDate) {
    drift.push(`captureDate: expected ${expectation.captureDate}, got ${record.provenance.captureDate}`);
  }
  return drift;
};
