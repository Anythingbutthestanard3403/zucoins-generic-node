/**
 * Auth error-envelope helper.
 *
 * Uses the frozen ERROR_CODES vocabulary committed in the fuzz oracles — the
 * v1-compatible envelope shape. TEST + library SUT.
 */
import { randomUUID } from "node:crypto";

import type { ErrorCode } from "../http-auth-fuzz-oracles.ts";

const DOC_BASE = "https://errors.invalid/generic-node";

export interface ErrorEnvelopeBody {
  error: {
    code: ErrorCode;
    message: string;
    param?: string;
    request_id: string;
    doc_url: string;
  };
}

export function errorBody(
  code: ErrorCode,
  message: string,
  param?: string,
): ErrorEnvelopeBody {
  return {
    error: {
      code,
      message,
      ...(param ? { param } : {}),
      request_id: randomUUID(),
      doc_url: `${DOC_BASE}#${code}`,
    },
  };
}
