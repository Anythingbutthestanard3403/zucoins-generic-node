// GET /v1/implementer/identity — bearer-scoped funding wallet pin (ZTR-1288)
// plus the node's default verification_mode (ZTR-1319, always emitted).
//
// Returns the effective funding_wallet_id + funding_wallet_public_key for the
// authenticated implementer (explicit pin, else node default, else nulls).
// Never substitutes a worker/send key. Unset → explicit null + funding_configured:false.

import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import {
  assertOperationAuthComposition,
  type OperationAuthBinding,
} from "./operation-auth.js";
import {
  runValidationPipeline,
  type PipelineConfig,
  type PipelineRequest,
} from "./pipeline.js";
import { findRouteSchema } from "./route-schemas.js";
import type { OperationRouteStore } from "./routes/operation-routes.js";
import { DEFAULT_VERIFICATION_MODE } from "@zucoins/generic-node-contracts/operations";
import {
  resolveEffectiveFundingWallet,
  toFundingWalletWireFields,
  type FundingWalletPin,
} from "../implementer/resolve-effective-funding-wallet.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const PATH = "/v1/implementer/identity" as const;

export interface ImplementerIdentityLoaders {
  /**
   * Load the implementer's explicit funding pin (funding_wallet_id + joined
   * public_key). Null/undefined when the implementer row is missing.
   */
  readonly loadImplementerPin: (
    implementerId: string,
  ) => Promise<FundingWalletPin | null>;
  /** Node-wide default funding pin (may be unset). */
  readonly loadNodeDefaultPin: () => Promise<FundingWalletPin>;
}

export interface ImplementerIdentityRouterDeps {
  readonly store: OperationRouteStore;
  readonly auth: OperationAuthBinding;
  readonly newRequestId: PipelineConfig["newRequestId"];
  readonly loaders: ImplementerIdentityLoaders;
}

export type ImplementerIdentityRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

function err(error: ApiErrorResponse) {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function ok(status: number, body: unknown) {
  return {
    status,
    body: JSON.stringify(body),
    headers: { "content-type": JSON_CONTENT_TYPE },
  };
}

export function createImplementerIdentityRouter(
  deps: ImplementerIdentityRouterDeps,
): ImplementerIdentityRouter {
  const store = deps.store;
  const auth = deps.auth;
  const newRequestId = deps.newRequestId;
  const loaders = deps.loaders;
  assertOperationAuthComposition(store, auth);

  const config: PipelineConfig = {
    newRequestId,
    authenticate: auth.authenticate,
    authorizeScope: auth.authorizeScope,
    ...(auth.kind === "implementer_bearer" ? { resolveCredential: auth.resolveCredential } : {}),
  };

  return async (method, rawPath, rawBody, headers) => {
    const queryIndex = rawPath.indexOf("?");
    const pathname = queryIndex >= 0 ? rawPath.slice(0, queryIndex) : rawPath;
    const verb = method.trim().toUpperCase();

    if (pathname !== PATH) {
      return err(apiErrorResponse("not_found", newRequestId()));
    }
    if (verb !== "GET") {
      return err(apiErrorResponse("not_found", newRequestId()));
    }

    const routeSchema = findRouteSchema("GET", PATH);
    if (routeSchema === undefined) {
      return err(apiErrorResponse("not_found", newRequestId()));
    }

    const request: PipelineRequest = {
      method: "GET",
      path: pathname,
      rawBody,
      headers,
      query: {},
    };
    const outcome = await runValidationPipeline(config, request, routeSchema);
    if (!outcome.ok) return err(outcome.error);

    const implementerId = outcome.context.principal?.implementerId;
    if (implementerId === undefined || implementerId.length === 0) {
      // Auth passed without a principal — fail closed rather than invent identity.
      return err(apiErrorResponse("invalid_api_key", outcome.context.requestId));
    }

    try {
      const [implPin, nodeDefault] = await Promise.all([
        loaders.loadImplementerPin(implementerId),
        loaders.loadNodeDefaultPin(),
      ]);
      if (implPin === null) {
        return err(apiErrorResponse("not_found", outcome.context.requestId));
      }
      const effective = resolveEffectiveFundingWallet({
        implementerPin: implPin,
        nodeDefault,
      });
      const wire = toFundingWalletWireFields(effective);
      return ok(200, {
        implementer_id: implementerId,
        funding_wallet_id: wire.funding_wallet_id,
        funding_wallet_public_key: wire.funding_wallet_public_key,
        funding_configured: effective.configured,
        funding_source: effective.source,
        // ZTR-1319: node's default create-time mode. Always emitted (never omitted).
        verification_mode: DEFAULT_VERIFICATION_MODE,
      });
    } catch {
      return err(apiErrorResponse("service_unavailable", outcome.context.requestId));
    }
  };
}
