// The RECEIVE_TERMINAL_CHECK confirm-read,
// plus the observation-ledger writer that makes each such read durable evidence.
//
// This is the production `ReadFreshHead` the landing oracle
// (packages/node-core/src/verifier/landing-path-oracle.ts) is injected with. Read path only:
// `get_transaction__v1` through the node-core bounded jittered multi-endpoint read primitive.
// SUBMIT is structurally unreachable from here (GatewayReadActionName) — the never-blind-retry rule.
//
// Every read lands a row in the observation ledger through the frozen serialized
// stream writer (advisory lock, relationship classify, previous_recorded, cursor upsert), so
// `observationId` names a durable row an independent verifier can re-read. That id becomes the
// proof's `freshHeadObservationId` and the operation's `terminal_observation_id`; a landing
// whose confirm-read was never persisted is not a landing.
//
// persistSqlObservation is the SINGLE durability owner for this path. It is used both by the
// read primitive's transport-error recorder and by the parsed-response path, so every attempted
// read produces exactly one observation/anomaly pair when the frozen classifier requires it.
//
// Fail-closed by throwing: `ReadFreshHead` has no fault channel, and the landing-proof rule admits no partial
// read. A malformed envelope, an unverifiable head, or a persist failure raises, the oracle
// call unwinds, and the caller records INDETERMINATE — no landing, no non-landing, no retry.

import type { Pool } from "pg";

import {
  buildGenesisWalletHeadFingerprint,
  buildGetTransactionActionData,

  fingerprintEndpoint,
  parseGatewayEnvelope,
  projectGenesisState,
  readGatewayAction,
  verifySettledTransaction,
  type FreshHeadRead,
  type GatewayExchangeTransport,
  type ObservationRowProjection,
  type ReadFreshHead,
} from "@zucoins/node-core";

import { persistSqlObservation } from "./sql-observation-persistence.js";

const DEFAULT_LIMITS = {
  readTimeoutMs: 10_000,
  maxRequestBytes: 1_048_576,
  maxResponseBytes: 4_194_304,
} as const;

const EMPTY_ROW_PROJECTION = {
  walletRole: null,
  bAmount: null,
  innerPreimageText: null,
  step1Signature: null,
  step2Signature: null,
  completedTransactionText: null,
  completedTransactionSha256: null,
} as const;

/** Raised for every read that cannot become a durable, verified head observation. */
export class FreshHeadReadError extends Error {
  constructor(detail: string) {
    super(`RECEIVE_TERMINAL_CHECK read is INDETERMINATE: ${detail}`);
    this.name = "FreshHeadReadError";
  }
}

export interface SqlFreshHeadReaderDeps {
  readonly pool: Pool;
  readonly nodeId: string;
  /** SPLITCHAIN_GATEWAY_URLS — non-empty required; there is no offline head stub. */
  readonly gatewayUrls: readonly string[];
  /** Offline fixtures inject a scripted exchange; production leaves it undefined. */
  readonly exchange?: GatewayExchangeTransport;
  /** GATEWAY_READ_RETRY_MAX_ATTEMPTS — absent resolves to the read primitive's default. */
  readonly maxAttempts?: number;
  /** GATEWAY_READ_BACKOFF_MAX_MS — absent resolves to the read primitive's default. */
  readonly backoffMaxMs?: number;
  /** Transaction-local money-path statement_timeout (ZTR-1156). */
  readonly moneyPathStatementTimeoutMs?: number;
  /**
   * ZTR-1162: production injects createObservedGatewayRead so readiness is stamped
   * on every outcome. Absent → bare readGatewayAction (unit tests).
   */
  readonly readGatewayAction?: typeof readGatewayAction;
}

/**
 * Build the durable `ReadFreshHead` port: one live `get_transaction__v1` read, appended to the
 * observation ledger, returned as {observationId, envelope} for `anchorFromRead`.
 *
 * A GENESIS head is a legitimate observation and is persisted; the oracle turns it into a
 * MISSING_BODY fault, because a genesis head anchors no path.
 */
export function createSqlFreshHeadReader(deps: SqlFreshHeadReaderDeps): ReadFreshHead {
  if (deps.gatewayUrls.length === 0) {
    throw new Error("createSqlFreshHeadReader requires at least one gateway URL");
  }

  return async (walletPublicKey: string): Promise<FreshHeadRead> => {
    const read = deps.readGatewayAction ?? readGatewayAction;
    const result = await read(
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
              nodeId: deps.nodeId,
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
    const rawBytes = result.capture.responseBytes;
    const httpStatus = result.capture.statusCode;
    const endpointFingerprint =
      result.capture.endpointFingerprint ??
      fingerprintEndpoint(result.capture.endpoint ?? deps.gatewayUrls[0]!);

    const envelope = parseGatewayEnvelope(rawBytes);
    if (envelope.classification === "MALFORMED_ENVELOPE") {
      try {
        await persistSqlObservation({
          pool: deps.pool,
          nodeId: deps.nodeId,
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
      } catch (error) {
        throw new FreshHeadReadError(
          error instanceof Error ? error.message : "malformed head observation persist failed",
        );
      }
      throw new FreshHeadReadError(`head envelope malformed: ${envelope.reason}`);
    }

    let parseResult: "VERIFIED_GENESIS" | "VERIFIED_HEAD";
    let sSignature: string;
    let pSignature: string;
    let semanticFingerprint: string;
    let rowProjectionBase: Omit<
      ObservationRowProjection,
      "endpointFingerprint" | "walletId" | "httpStatus" | "observedAt"
    >;

    if (envelope.classification === "GENESIS") {
      const genesis = projectGenesisState();
      const fp = buildGenesisWalletHeadFingerprint(walletPublicKey, genesis);
      if (!fp.ok) {
        throw new FreshHeadReadError(fp.detail);
      }
      parseResult = "VERIFIED_GENESIS";
      sSignature = "";
      pSignature = "";
      semanticFingerprint = fp.fingerprint.sha256;
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
        try {
          await persistSqlObservation({
            pool: deps.pool,
            nodeId: deps.nodeId,
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
        } catch (error) {
          throw new FreshHeadReadError(
            error instanceof Error ? error.message : "unverified head observation persist failed",
          );
        }
        throw new FreshHeadReadError(`head not verified for this wallet: ${verified.verdict}`);
      }
      parseResult = "VERIFIED_HEAD";
      sSignature = verified.projection.S;
      pSignature = verified.projection.P;
      semanticFingerprint = verified.semanticFingerprint;
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
      // ZTR-1275: confirm-reads must APPEND a DUPLICATE row on exact byte-identical
      // repeats so FRESH_VERIFIED_T0_EXACT can name a post-expiry observation id.
      // Only this reader sets appendExactRepeat; other persistSqlObservation callers
      // keep SUPPRESS_AS_SIGHTING default.
      const persisted = await persistSqlObservation({
        pool: deps.pool,
        nodeId: deps.nodeId,
        walletPublicKey,
        moneyPathStatementTimeoutMs: deps.moneyPathStatementTimeoutMs,
        endpointFingerprint,
        httpStatus: httpStatus ?? 200,
        capture: {
          parseResult,
          rawResponseBytes: rawBytes,
          isGenesis: parseResult === "VERIFIED_GENESIS",
          sSignature,
          pSignature,
          semanticFingerprint,
        },
        projection: rowProjectionBase,
        appendExactRepeat: true,
      });
      // Landing oracle must not mint proofs from anomalous heads. Evidence is durable;
      // the read fails closed so terminal_observation_id cannot pin a REGRESSION/JUMP.
      const anomalous =
        persisted.relationship === "REGRESSION" ||
        persisted.relationship === "UNEXPLAINED_JUMP" ||
        persisted.relationship === "GENESIS_AFTER_HISTORY" ||
        persisted.relationship === "SIGNATURE_COLLISION";
      if (anomalous) {
        throw new FreshHeadReadError(
          `head anomalous relationship ${persisted.relationship} (observation ${persisted.observationId})`,
        );
      }
      return { observationId: persisted.observationId, envelope };
    } catch (err) {
      throw err instanceof FreshHeadReadError
        ? err
        : new FreshHeadReadError(
            err instanceof Error ? err.message : "head observation persist failed",
          );
    }
  };
}
