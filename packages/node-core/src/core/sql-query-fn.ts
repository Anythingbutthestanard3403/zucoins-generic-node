// The driver-free SQL seam shared by every SQL-backed port in core/ and send/ (: the
// package links no database driver, so statements are handed to an injected function).
//
// This type used to live in submit-decision-claim-store.ts. It is not a submit concern — it is
// the generic statement seam — and the structural guards scan SEND_EXTERNAL
// source for the literal text "submit-decision-claim-store", so importing a generic type from
// that module made a type-only import indistinguishable from a submit reach. Declaring it here
// keeps those guards byte-strict without an allow-list.

// Executes one parameterized statement ($1-indexed, as PostgreSQL wire parameters) and
// resolves to its result rows. Values are bound, never interpolated into the statement text.
export type SqlQueryFn = (
  text: string,
  values: readonly unknown[],
) => Promise<readonly Record<string, unknown>[]>;
