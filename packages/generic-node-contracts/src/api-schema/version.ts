/**
 * the crypto-goldens concern.2 — Drift-detection version metadata.
 *
 * A monotonically increasing version field that drift-detection tests assert against.
 * Bump this value whenever the frozen API schema vocabulary changes (adding/removing
 * a route, enum value, event, error code, or auth scope).
 */
export const API_SCHEMA_VERSION = 2 as const;
