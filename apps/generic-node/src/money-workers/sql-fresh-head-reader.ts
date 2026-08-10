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
// The stream writer is the SINGLE durability owner for this path, exactly as
// gateway-t0-observer.ts arranges it for T0: the read primitive's `ObservationRecorder` hook is
// left inert so one read cannot produce two ledger rows.
//
// Fail-closed by throwing: `ReadFreshHead` has no fault channel, and the landing-proof rule admits no partial
// read. A malformed envelope, an unverifiable head, or a persist failure raises, the oracle
// call unwinds, and the caller records INDETERMINATE — no landing, no non-landing, no retry.

import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";

import {
  buildGenesisWalletHeadFingerprint,
  buildGetTransactionActionData,
  createSerializedStreamWriter,
  createSqlStreamWriterEffects,
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

import { ensureNodeObserver } from "./gateway-t0-observer.js";

const DEFAULT_LIMITS = {
  readTimeoutMs: 10_000,
  maxRequestBytes: 1_048_576,
  maxResponseBytes: 4_194_304,
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
    const result = await readGatewayAction(
      "get_transaction__v1",
      // Canonical codec — shared with the other three wallet-head readers so the
      // field name cannot drift again.
      buildGetTransactionActionData(walletPublicKey),
      {
        endpoints: deps.gatewayUrls,
        limits: DEFAULT_LIMITS,
        // Inert on purpose — the stream writer below is the single durability owner.
        recorder: { recordObservation: async () => {} },
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

    const client = await deps.pool.connect();
    try {
      await client.query("BEGIN");
      await applyMoneyPathStatementTimeout(
        client,
        deps.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT,
      );
      const observerId = await ensureNodeObserver(client, deps.nodeId, endpointFingerprint);
      const wallet = await client.query<{ id: string }>(
        `SELECT id::text AS id FROM wallets WHERE public_key = $1 LIMIT 1`,
        [walletPublicKey],
      );
      const walletId = wallet.rows[0]?.id ?? null;

      let allocatedObservationId: string | null = null;
      const effects = createSqlStreamWriterEffects({
        sql: {
          query: async <R>(text: string, params: readonly unknown[]) => {
            const queried = await client.query(text, params as never[]);
            return { rows: queried.rows as R[] };
          },
        },
        project: (): ObservationRowProjection => ({
          endpointFingerprint,
          walletId,
          httpStatus: httpStatus ?? 200,
          observedAt: new Date(),
          ...rowProjectionBase,
        }),
        allocateObservationId: () => {
          allocatedObservationId = randomUUID();
          return allocatedObservationId;
        },
        takeAdvisoryLock: true,
      });
      const written = await createSerializedStreamWriter(effects).capture(
        { observerId, walletPublicKey },
        {
          parseResult,
          rawResponseBytes: rawBytes,
          isGenesis: parseResult === "VERIFIED_GENESIS",
          sSignature,
          pSignature,
          semanticFingerprint,
        },
      );

      let observationId: string;
      if (written.plan.kind === "APPEND") {
        if (allocatedObservationId === null) {
          throw new Error("stream writer APPEND without allocated observation id");
        }
        observationId = allocatedObservationId;
      } else {
        // Exact-byte re-observation: the cursor tip IS this read's observation. The oracle
        // reads the head twice; an unmoved head therefore anchors and confirms on one row.
        const tip = await client.query<{ id: string }>(
          `SELECT last_recorded_observation_id::text AS id
             FROM wallet_observation_cursors
            WHERE observer_id = $1::uuid AND wallet_public_key = $2`,
          [observerId, walletPublicKey],
        );
        const tipId = tip.rows[0]?.id;
        if (tipId === undefined) {
          throw new Error("stream writer SUPPRESS without cursor tip");
        }
        observationId = tipId;
      }

      await client.query("COMMIT");
      return { observationId, envelope };
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        /* keep the original failure */
      }
      throw err instanceof FreshHeadReadError
        ? err
        : new FreshHeadReadError(
            err instanceof Error ? err.message : "head observation persist failed",
          );
    } finally {
      client.release();
    }
  };
}
