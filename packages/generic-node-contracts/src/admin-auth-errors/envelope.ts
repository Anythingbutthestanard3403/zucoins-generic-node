// Admin error envelope: same outer shape as the public ApiErrorEnvelope
// (code, message, request_id, details) with .strict() objects. Code enum is
// ADMIN_ERROR_CODES rather than API_ERROR_CODES. Sibling schema for the
// checklist_links/operation_id lab-receive extension.

import { z } from "zod";
import { ADMIN_ERROR_CODES, type AdminErrorCode, isAdminErrorCode } from "./codes.js";

export const ADMIN_ERROR_ENVELOPE_FIELD_ORDER = [
  "code",
  "message",
  "request_id",
  "details",
] as const;

export const AdminErrorCodeSchema = z.enum(
  ADMIN_ERROR_CODES.map((e) => e.code) as unknown as [string, ...string[]],
) as z.ZodType<AdminErrorCode>;

/** Canonical admin error body — details always present (default {}). */
export const AdminErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: AdminErrorCodeSchema,
        message: z.string(),
        request_id: z.string().uuid(),
        details: z.record(z.never()).default({}),
      })
      .strict(),
  })
  .strict();

export type AdminErrorEnvelope = z.infer<typeof AdminErrorEnvelopeSchema>;

/**
 * Lab-receive extended error: checklist_links + operation_id sit as siblings
 * of `error`, not inside details (details stays empty Record). Named sibling
 * of AdminErrorEnvelopeSchema — not a loosened parent.
 */
export const AdminLabReceiveErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: AdminErrorCodeSchema,
        message: z.string(),
        request_id: z.string().uuid(),
        details: z.record(z.never()).default({}),
      })
      .strict(),
    checklist_links: z.array(z.unknown()).optional(),
    operation_id: z.string().optional(),
  })
  .strict();

export type AdminLabReceiveErrorEnvelope = z.infer<typeof AdminLabReceiveErrorEnvelopeSchema>;

/** Build the byte-exact admin error body (explicit key insertion sequence). */
export function buildAdminErrorBody(
  code: AdminErrorCode,
  message: string,
  requestId: string,
): string {
  return JSON.stringify({
    error: {
      code,
      message,
      request_id: requestId,
      details: {},
    },
  });
}

export function buildAdminLabReceiveErrorBody(
  code: AdminErrorCode,
  message: string,
  requestId: string,
  extras: {
    readonly checklist_links?: unknown;
    readonly operation_id?: string;
  } = {},
): string {
  const body: Record<string, unknown> = {
    error: {
      code,
      message,
      request_id: requestId,
      details: {},
    },
  };
  if (extras.checklist_links !== undefined) body.checklist_links = extras.checklist_links;
  if (extras.operation_id !== undefined) body.operation_id = extras.operation_id;
  return JSON.stringify(body);
}

/**
 * Coerce a free-form code string to AdminErrorCode. Unknown codes collapse to
 * `internal_error` so a hander bug cannot emit an unfrozen wire code.
 */
export function coerceAdminErrorCode(code: string): AdminErrorCode {
  if (isAdminErrorCode(code)) return code;
  return "internal_error";
}
