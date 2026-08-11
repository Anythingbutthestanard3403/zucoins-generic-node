import type { ApiFailureDetail } from "../lib/api.js";

/**
 * Operator-actionable detail for a read that came back `live: false` from a genuine
 * caught failure — so operators see the server code/message/request id.
 */
export function ApiErrorNote({ error }: { error: ApiFailureDetail | undefined }) {
  if (!error) return null;
  return (
    <p className="muted" style={{ fontSize: 12.5 }}>
      <code className="mono">{error.code}</code> ({error.status}) — {error.message}
      {error.requestId ? (
        <>
          {" "}
          · request <code className="mono">{error.requestId}</code>
        </>
      ) : null}
    </p>
  );
}
