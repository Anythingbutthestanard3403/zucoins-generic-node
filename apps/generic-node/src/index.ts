import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import {
  createNodeCore,
  createNodeEventVerifier,
  createReportingRequestHandler,
  createReportingRequestVerifier,
  DEFAULT_MAX_BODY_BYTES,
  InMemoryReportingRateLimiter,
  NODE_CORE_VERSION,
  type NodeCoreConfiguration,
  type NodeCoreRuntime,
  type NodeEventVerificationStore,
  type NodeEventVerifier,
  type ReportingHandlerRegistry,
  type ReportingRateLimiter,
  type ReportingRequestHandler,
  type ReportingRequestStore,
  type ReportingRequestVerifier,
} from "@zucoins/node-core";

import { createNodeHttpListener, createReportingHttpListener } from "./http-adapter.js";

// The default bounded-rate policy: 600 requests per 60 s fixed window per presented reporting
// key id. The contract fixes the check's pre-burn position, not a numeric policy — this is a
// configurable runtime choice, not a frozen bound.
export const GENERIC_NODE_DEFAULT_RATE_LIMIT = Object.freeze({
  windowMs: 60_000,
  maxRequests: 600,
});

export interface GenericNodeReportingConfiguration {
  readonly nodeId: string;
  readonly store: ReportingRequestStore & NodeEventVerificationStore;
  readonly handlers?: ReportingHandlerRegistry;
  readonly rateLimiter?: ReportingRateLimiter;
  readonly nowMs?: () => number;
  readonly maxBodyBytes?: number;
  readonly newRequestId?: () => string;
}

export interface GenericNodeReportingSurface {
  readonly verifier: ReportingRequestVerifier;
  readonly handler: ReportingRequestHandler;
  readonly events: NodeEventVerifier;
  readonly listener: (request: IncomingMessage, response: ServerResponse) => Promise<void>;
}

export interface GenericNodeApplication {
  readonly core: NodeCoreRuntime;
  readonly reporting?: GenericNodeReportingSurface;
}

export function createGenericNodeApplication(
  configuration: NodeCoreConfiguration,
  reporting?: GenericNodeReportingConfiguration,
): GenericNodeApplication {
  const core = createNodeCore(configuration);
  if (reporting === undefined) {
    return Object.freeze({ core });
  }
  const nowMs = reporting.nowMs ?? (() => Date.now());
  const maxBodyBytes = reporting.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const newRequestId = reporting.newRequestId ?? (() => randomUUID());
  const verifier = createReportingRequestVerifier({
    nodeId: reporting.nodeId,
    store: reporting.store,
    rateLimiter:
      reporting.rateLimiter ??
      new InMemoryReportingRateLimiter(
        GENERIC_NODE_DEFAULT_RATE_LIMIT.windowMs,
        GENERIC_NODE_DEFAULT_RATE_LIMIT.maxRequests,
      ),
    nowMs,
    maxBodyBytes,
  });
  const handler = createReportingRequestHandler({
    verifier,
    store: reporting.store,
    handlers: reporting.handlers ?? {},
    newRequestId,
    nowMs,
  });
  const events = createNodeEventVerifier({ store: reporting.store });
  const listener = createNodeHttpListener(
    createReportingHttpListener({ handle: handler.handle, nowMs, maxBodyBytes, newRequestId }),
  );
  return Object.freeze({
    core,
    reporting: Object.freeze({ verifier, handler, events, listener }),
  });
}

export const GENERIC_NODE_VERSION = NODE_CORE_VERSION;

export * from "./config/index.js";
export * from "./boot/index.js";
export * from "./health/index.js";
export * from "./operations/index.js";

export * from "./dr/index.js";
