import type { DatabaseAdapter } from "../data/index.js";
import type {
  GatewayReadCredentials,
  GatewayReadTransport,
  GatewaySubmitCredentials,
  GatewaySubmitTransport,
} from "../gateway/index.js";
import type { GatewayRequest, GatewayResponse } from "../protocol/index.js";

export type OfflineGatewayResult = GatewayResponse | Error;

export interface OfflineGatewayCall {
  readonly endpoints: readonly string[];
  readonly request: GatewayRequest;
}

export interface OfflineReadTransport extends GatewayReadTransport {
  readonly calls: readonly OfflineGatewayCall[];
}

export interface OfflineSubmitTransport extends GatewaySubmitTransport {
  readonly calls: readonly OfflineGatewayCall[];
}

export interface OfflineDatabaseAdapter extends DatabaseAdapter {
  readonly readyChecks: number;
}

function cloneRequest(request: GatewayRequest): GatewayRequest {
  return {
    rpc: request.rpc,
    bodyBytes: Uint8Array.from(request.bodyBytes),
  };
}

function cloneResponse(response: GatewayResponse): GatewayResponse {
  return {
    statusCode: response.statusCode,
    bodyBytes: Uint8Array.from(response.bodyBytes),
  };
}

function nextResult(
  scripted: readonly OfflineGatewayResult[],
  position: number,
): GatewayResponse {
  const result = scripted[position];
  if (result === undefined) {
    throw new Error("offline gateway script is exhausted");
  }
  if (result instanceof Error) {
    throw result;
  }
  return cloneResponse(result);
}

export function createOfflineReadTransport(
  credentials: GatewayReadCredentials,
  scripted: readonly OfflineGatewayResult[],
): OfflineReadTransport {
  const callLog: OfflineGatewayCall[] = [];

  return {
    credentials,
    get calls(): readonly OfflineGatewayCall[] {
      return callLog.map((call) => ({
        endpoints: [...call.endpoints],
        request: cloneRequest(call.request),
      }));
    },
    async read(
      endpoints: readonly string[],
      request: GatewayRequest,
    ): Promise<GatewayResponse> {
      callLog.push({ endpoints: [...endpoints], request: cloneRequest(request) });
      return nextResult(scripted, callLog.length - 1);
    },
  };
}

export function createOfflineSubmitTransport(
  credentials: GatewaySubmitCredentials,
  scripted: readonly OfflineGatewayResult[],
): OfflineSubmitTransport {
  const callLog: OfflineGatewayCall[] = [];

  return {
    credentials,
    get calls(): readonly OfflineGatewayCall[] {
      return callLog.map((call) => ({
        endpoints: [...call.endpoints],
        request: cloneRequest(call.request),
      }));
    },
    async submit(
      endpoints: readonly string[],
      request: GatewayRequest,
    ): Promise<GatewayResponse> {
      callLog.push({ endpoints: [...endpoints], request: cloneRequest(request) });
      return nextResult(scripted, callLog.length - 1);
    },
  };
}

export function createOfflineDatabaseAdapter(
  readyError?: Error,
): OfflineDatabaseAdapter {
  let checks = 0;
  return {
    get readyChecks(): number {
      return checks;
    },
    async checkReady(): Promise<void> {
      checks += 1;
      if (readyError !== undefined) {
        throw readyError;
      }
    },
  };
}
