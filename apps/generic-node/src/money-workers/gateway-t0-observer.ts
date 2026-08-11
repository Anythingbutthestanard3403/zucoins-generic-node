// Real RECEIVE_T0 OBSERVE.
// Read path only: get_transaction__v1 via node-core gateway read (package multi-endpoint
// failover on the read primitive). Never submit (the never-blind-retry rule).
// Replaces genesis-t0 stub on the money path when gateway URLs are set.
//
// Durable stream write uses the frozen capture planner + SQL stream writer:
// advisory lock, relationship classify, previous_recorded, wallet_observation_cursors upsert.
// No DIY FIRST / null-previous INSERT.
//
// ARM 409: when consumer arm projection ≠ this durable T0 {observation_id,S0,P0,B0},
// POST /v1/operations/:id/armed returns 409 t0_mismatch and never releases the code
// (arm-route). That compare path is already landed; this module supplies the
// honest gateway-derived T0 rows the compare consumes.

import type { Pool } from "pg";

import {
  GENESIS_PROJECTION,
  buildGenesisWalletHeadFingerprint,
  buildGetTransactionActionData,

  fingerprintEndpoint,
  parseGatewayEnvelope,
  projectGenesisState,
  readGatewayAction,
  verifySettledTransaction,
  type GatewayExchangeTransport,
  type MetricsHooks,
  type ObservationRowProjection,
  RECEIVE_T0_OBSERVATION_ROLE,
  type ReceiveT0Observation,
  type ReceiveT0Observer,
  type WalletStateProjection,
} from "@zucoins/node-core";

import { ensureNodeObserver, persistSqlObservation } from "./sql-observation-persistence.js";

const DEFAULT_LIMITS = {
  readTimeoutMs: 10_000,
  maxRequestBytes: 1_048_576,
  maxResponseBytes: 4_194_304,
} as const;

export interface GatewayT0ObserverDeps {
  readonly pool: Pool;
  readonly nodeId: string;
  /** Production SPLITCHAIN_GATEWAY_URLS — non-empty required (no silent genesis stub). */
  readonly gatewayUrls: readonly string[];
  /**
   * Offline fixtures inject a scripted exchange (synthetic gateway). Production leaves
   * this undefined so the default undici transport is used.
   */
  readonly exchange?: GatewayExchangeTransport;
  /** GATEWAY_READ_RETRY_MAX_ATTEMPTS — absent resolves to the read primitive's default. */
  readonly maxAttempts?: number;
  /** GATEWAY_READ_BACKOFF_MAX_MS — absent resolves to the read primitive's default. */
  readonly backoffMaxMs?: number;
  /** T0 read failure / observation anomaly / gateway duration, at the real seam. */
  readonly metricsHooks?: MetricsHooks;
  /** Transaction-local money-path statement_timeout (ZTR-1156). */
  readonly moneyPathStatementTimeoutMs?: number;
  /**
   * ZTR-1162: production injects createObservedGatewayRead so readiness is stamped
   * on every outcome. Absent → bare readGatewayAction (unit tests).
   */
  readonly readGatewayAction?: typeof readGatewayAction;
  /** ZTR-1172 §7.7 boot seed priors for first post-restart consecutive-dedup. */
  readonly bootPriorRawByStreamKey?: ReadonlyMap<string, Uint8Array | null>;
}

function genesisProjection(): WalletStateProjection {
  return {
    role: "genesis",
    S: GENESIS_PROJECTION.S,
    P: GENESIS_PROJECTION.P,
    B: GENESIS_PROJECTION.B,
    I: null,
  };
}

const EMPTY_ROW_PROJECTION = {
  walletRole: null,
  bAmount: null,
  innerPreimageText: null,
  step1Signature: null,
  step2Signature: null,
  completedTransactionText: null,
  completedTransactionSha256: null,
} as const;

/**
 * The one NODE-domain observer row every gateway read on this node is attributed to.
 * Shared with sql-fresh-head-reader.ts so T0 and the landing confirm-read append to the
 * same observation stream rather than two observers for the same node.
 */
export { ensureNodeObserver };

/**
 * Build a durable ReceiveT0Observer that OBSERVEs via get_transaction__v1 (read-only)
 * and persists observation_id + S/P/B through the frozen stream writer for artifact
 * binding and ARM compare.
 */
export function createGatewayT0Observer(deps: GatewayT0ObserverDeps): ReceiveT0Observer {
  if (deps.gatewayUrls.length === 0) {
    throw new Error(
      "createGatewayT0Observer requires at least one gateway URL (no silent genesis stub)",
    );
  }
  const bootPriors = deps.bootPriorRawByStreamKey;

  return {
    async observe(
      walletPublicKey: string,
      _role: typeof RECEIVE_T0_OBSERVATION_ROLE,
    ): Promise<ReceiveT0Observation> {
      let rawBytes: Uint8Array;
      let httpStatus: number | null;
      let endpointFingerprint: string;
      const read = deps.readGatewayAction ?? readGatewayAction;
      const readOnce = (): Promise<Awaited<ReturnType<typeof readGatewayAction>>> =>
        read(
          "get_transaction__v1",
          // Canonical codec — shared with the other three wallet-head readers so the
          // field name cannot drift again.
          buildGetTransactionActionData(walletPublicKey),
          {
            endpoints: deps.gatewayUrls,
            limits: DEFAULT_LIMITS,
            recorder: {
              recordObservation: async (observation) => {
                if (!observation.transportAmbiguous) return;
                await persistSqlObservation({
                  pool: deps.pool,
            metricsHooks: deps.metricsHooks,
                  nodeId: deps.nodeId,
                  ...(bootPriors !== undefined ? { bootPriorRawByStreamKey: bootPriors } : {}),
                  walletPublicKey,
                  moneyPathStatementTimeoutMs: deps.moneyPathStatementTimeoutMs,
                  endpointFingerprint: observation.endpointFingerprint,
                  httpStatus: null,
                  capture: {
                    parseResult: "TRANSPORT_ERROR",
                    rawResponseBytes: new Uint8Array(),
                    isGenesis: false,
                    sSignature: "",
                    pSignature: "",
                    semanticFingerprint: "",
                  },
                  projection: EMPTY_ROW_PROJECTION,
                });
              },
            },
            ...(deps.exchange !== undefined ? { exchange: deps.exchange } : {}),
            ...(deps.maxAttempts !== undefined ? { maxAttempts: deps.maxAttempts } : {}),
            ...(deps.backoffMaxMs !== undefined ? { backoffMaxMs: deps.backoffMaxMs } : {}),
          },
        );
      try {
        // Multi-URL list → package read primitive iterates with bounded jittered backoff
        // (gateway/read.ts). SUBMIT is structurally excluded (GatewayReadActionName).
        const result = deps.metricsHooks
          ? await deps.metricsHooks.timeGateway("get_transaction__v1", readOnce)
          : await readOnce();
        rawBytes = result.capture.responseBytes;
        httpStatus = result.capture.statusCode;
        endpointFingerprint =
          result.capture.endpointFingerprint ??
          fingerprintEndpoint(result.capture.endpoint ?? deps.gatewayUrls[0]!);
      } catch (err) {
        deps.metricsHooks?.onT0ReadFailure();
        deps.metricsHooks?.onObservationAnomaly("TRANSPORT_ERROR");
        return {
          kind: "INDETERMINATE",
          detail:
            err instanceof Error
              ? `gateway T0 read failed: ${err.message}`
              : "gateway T0 read failed",
        };
      }

      const envelope = parseGatewayEnvelope(rawBytes);
      if (envelope.classification === "MALFORMED_ENVELOPE") {
        deps.metricsHooks?.onObservationAnomaly("MALFORMED_ENVELOPE");
        await persistSqlObservation({
          pool: deps.pool,
            metricsHooks: deps.metricsHooks,
          nodeId: deps.nodeId,
                  ...(bootPriors !== undefined ? { bootPriorRawByStreamKey: bootPriors } : {}),
          walletPublicKey,
          moneyPathStatementTimeoutMs: deps.moneyPathStatementTimeoutMs,
          endpointFingerprint,
          httpStatus,
          capture: {
            parseResult: "MALFORMED_ENVELOPE",
            rawResponseBytes: rawBytes,
            isGenesis: false,
            sSignature: "",
            pSignature: "",
            semanticFingerprint: "",
          },
          projection: EMPTY_ROW_PROJECTION,
        });
        return {
          kind: "UNVERIFIED",
          detail: `T0 envelope malformed: ${envelope.reason}`,
        };
      }

      type CaptureShape = {
        readonly parseResult: "VERIFIED_GENESIS" | "VERIFIED_HEAD";
        readonly rawResponseBytes: Uint8Array;
        readonly isGenesis: boolean;
        readonly sSignature: string;
        readonly pSignature: string;
        readonly semanticFingerprint: string;
      };

      let sequenceCapture: CaptureShape;
      let returnProjection: WalletStateProjection;
      let rowProjectionBase: Omit<
        ObservationRowProjection,
        "endpointFingerprint" | "walletId" | "httpStatus" | "observedAt"
      >;

      if (envelope.classification === "GENESIS") {
        const genesis = projectGenesisState();
        const fp = buildGenesisWalletHeadFingerprint(walletPublicKey, genesis);
        if (!fp.ok) {
          return { kind: "UNVERIFIED", detail: fp.detail };
        }
        sequenceCapture = {
          parseResult: "VERIFIED_GENESIS",
          rawResponseBytes: rawBytes,
          isGenesis: true,
          sSignature: "",
          pSignature: "",
          semanticFingerprint: fp.fingerprint.sha256,
        };
        returnProjection = genesisProjection();
        rowProjectionBase = {
          walletRole: "genesis",
          bAmount: "0",
          innerPreimageText: null,
          step1Signature: null,
          step2Signature: null,
          completedTransactionText: null,
          completedTransactionSha256: null,
        };
      } else {
        const verified = verifySettledTransaction(envelope.parsed, walletPublicKey);
        if (verified.verdict !== "VERIFIED") {
          const detail =
            verified.verdict === "UNVERIFIED_SIGNATURE"
              ? `T0 signature unverified step=${verified.failedStep}`
              : verified.verdict === "WALLET_ROLE_INVALID"
                ? `T0 role invalid: ${verified.detail}`
                : `T0 transaction not verified: ${verified.verdict}`;
          // verified.verdict here is one of UNVERIFIED_SIGNATURE | WALLET_ROLE_INVALID |
          // MALFORMED_TRANSACTION — all three are closed METRIC_ANOMALY_KINDS values.
          deps.metricsHooks?.onObservationAnomaly(verified.verdict);
          await persistSqlObservation({
            pool: deps.pool,
            metricsHooks: deps.metricsHooks,
            nodeId: deps.nodeId,
                  ...(bootPriors !== undefined ? { bootPriorRawByStreamKey: bootPriors } : {}),
            walletPublicKey,
            moneyPathStatementTimeoutMs: deps.moneyPathStatementTimeoutMs,
            endpointFingerprint,
            httpStatus,
            capture: {
              parseResult: verified.verdict,
              rawResponseBytes: rawBytes,
              isGenesis: false,
              sSignature: "",
              pSignature: "",
              semanticFingerprint: "",
            },
            projection: EMPTY_ROW_PROJECTION,
          });
          return { kind: "UNVERIFIED", detail };
        }
        sequenceCapture = {
          parseResult: "VERIFIED_HEAD",
          rawResponseBytes: rawBytes,
          isGenesis: false,
          sSignature: verified.projection.S,
          pSignature: verified.projection.P,
          semanticFingerprint: verified.semanticFingerprint,
        };
        returnProjection = verified.projection;
        rowProjectionBase = {
          walletRole: verified.projection.role,
          bAmount: verified.projection.B,
          innerPreimageText: verified.innerPreimageText,
          step1Signature: envelope.parsed.step_1_signature,
          step2Signature: envelope.parsed.step_2_signature,
          completedTransactionText: verified.completedTransactionText,
          completedTransactionSha256: verified.completedTransactionSha256,
        };
      }

      try {
        const persisted = await persistSqlObservation({
          pool: deps.pool,
            metricsHooks: deps.metricsHooks,
          nodeId: deps.nodeId,
                  ...(bootPriors !== undefined ? { bootPriorRawByStreamKey: bootPriors } : {}),
          walletPublicKey,
          moneyPathStatementTimeoutMs: deps.moneyPathStatementTimeoutMs,
          endpointFingerprint,
          httpStatus: httpStatus ?? 200,
          capture: sequenceCapture,
          projection: rowProjectionBase,
        });
        // Anomalous relationships (REGRESSION / JUMP / COLLISION / GENESIS_AFTER_HISTORY)
        // must never surface as VERIFIED — evidence + quarantine committed, but the money
        // path must fail closed (no RECEIVER_T0 bind / arm off a self-contradicting head).
        const anomalous =
          persisted.relationship === "REGRESSION" ||
          persisted.relationship === "UNEXPLAINED_JUMP" ||
          persisted.relationship === "GENESIS_AFTER_HISTORY" ||
          persisted.relationship === "SIGNATURE_COLLISION";
        if (anomalous) {
          deps.metricsHooks?.onObservationAnomaly(persisted.relationship);
          return {
            kind: "INDETERMINATE",
            detail: `T0 anomalous relationship ${persisted.relationship} (observation ${persisted.observationId})`,
          };
        }
        return {
          kind: "VERIFIED",
          observationId: persisted.observationId,
          projection: returnProjection,
        };
      } catch (err) {
        return {
          kind: "INDETERMINATE",
          detail: err instanceof Error ? err.message : "gateway T0 persist failed",
        };
      }
    },
  };
}
