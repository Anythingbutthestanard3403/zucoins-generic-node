/**
 * ZTR-1170 — formal supersession of doc-05 §4.1 synchronous 201 on POST /v1/receives.
 *
 * Machine-readable fact: the live create path always admits CREATED + 202
 * (`buildReceiveAcceptedBody` / `completeOperation(..., 202, ...)`). Wallet
 * assignment, T0 observation, code formation, and READY commit run on the
 * money-worker loop after the HTTP response. A true in-request 201 would
 * require that full formation chain inside the request budget; the node does
 * not do that.
 *
 * OpenAPI still documents 201 for historical clients and for the eventual
 * READY representation shape; the create handler never emits it on first
 * completion (idempotent replay may surface a later-stored 201 after READY).
 */
export const RECEIVE_CREATE_SYNC_201_SUPERSESSION = {
  ticket: "ZTR-1170",
  clause: "doc-05 §4.1 POST /v1/receives — synchronous 201 when pool wallet assigned and T0/artifact formation completes in-request",
  status: "superseded" as const,
  served_create_status: 202 as const,
  served_create_code_status: "NOT_CREATED" as const,
  reason:
    "Receive formation (pool assign → T0 observe → formReceiveCodeAndArtifact → commitReceiveReady) is asynchronous via money workers; create returns 202 with null receiver_pubkey/expires_at/expected_artifact/t0 until READY rewrites response_body.",
  authority: [
    "packages/node-core/src/operation-route-store.ts createReceive",
    "apps/generic-node/src/money-workers/start-money-workers.ts",
    "packages/node-core/src/receive/code-ready-commit.ts buildReceiveReady201Body",
  ] as const,
} as const;
