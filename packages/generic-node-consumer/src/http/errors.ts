/**
 * The frozen non-2xx error envelope. Every wrapped HTTP call in this
 * package decodes a non-2xx response through this module — callers branch on `code`, never on
 * `message` (diagnostic, not stable).
 */

export interface NodeApiErrorBody {
  readonly code: string;
  readonly message: string;
  readonly request_id: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export class NodeApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
  readonly details: Readonly<Record<string, unknown>>;

  constructor(status: number, body: NodeApiErrorBody) {
    super(body.message);
    this.name = "NodeApiError";
    this.status = status;
    this.code = body.code;
    this.requestId = body.request_id;
    this.details = body.details;
  }
}

function isErrorBody(value: unknown): value is { readonly error: unknown } {
  return typeof value === "object" && value !== null && "error" in value;
}

function isNodeApiErrorBody(value: unknown): value is NodeApiErrorBody {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.code === "string" &&
    typeof v.message === "string" &&
    typeof v.request_id === "string" &&
    typeof v.details === "object" &&
    v.details !== null
  );
}

/**
 * Parse a non-2xx response body into a NodeApiError. A malformed envelope (never expected from
 * a spec-conformant node, but never trusted blindly either) still fails closed with a
 * synthetic `malformed_error_envelope` code rather than throwing an unrelated JSON error.
 */
export async function readNodeApiError(response: Response): Promise<NodeApiError> {
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    return new NodeApiError(response.status, {
      code: "malformed_error_envelope",
      message: "response body was not valid JSON",
      request_id: "",
      details: {},
    });
  }
  if (!isErrorBody(parsed) || !isNodeApiErrorBody(parsed.error)) {
    return new NodeApiError(response.status, {
      code: "malformed_error_envelope",
      message: "response body did not match the frozen error envelope",
      request_id: "",
      details: {},
    });
  }
  return new NodeApiError(response.status, parsed.error);
}

/** Throw a NodeApiError for any non-2xx response; otherwise a no-op. */
export async function assertOk(response: Response): Promise<void> {
  if (response.ok) return;
  throw await readNodeApiError(response);
}
