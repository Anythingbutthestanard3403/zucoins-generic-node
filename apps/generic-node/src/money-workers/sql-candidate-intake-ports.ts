// SQL ports for RECEIVE candidate intake.

import type { Pool } from "pg";

import {
  GENESIS_PROJECTION,
  buildGetTransactionActionData,
  insertTransactionAttempt,
  parseGatewayEnvelope,
  readGatewayAction,
  verifySettledTransaction,
  type CandidatePersistPort,
  type CandidateRawCapturePort,
  type GatewayExchangeTransport,
  type GatewayLimits,
  type LocatedReceive,
  type LocateReceivePort,
  type PersistWinningCandidateInput,
  type PersistWinningCandidateResult,
  type SenderPreflightObservation,
  type SenderPreflightObserver,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { persistSqlObservation } from "./sql-observation-persistence.js";

const LOCATE_SQL = `
  SELECT o.id::text AS operation_id,
         o.amount_zkz AS amount_zkz,
         o.discriminator::text AS discriminator,
         o.anchor AS anchor,
         o.expiry_unix_time_secs::text AS expiry_unix_time_secs,
         o.status::text AS state,
         o.attention_required AS attention_required,
         w.id::text AS receiver_wallet_id,
         w.public_key AS receiver_pubkey,
         rc.code_status::text AS code_status,
         EXISTS (
           SELECT 1 FROM wallet_active_leases l
            WHERE l.operation_id = o.id
              AND l.wallet_id = w.id
              AND l.lease_role = 'RECEIVE_WINDOW'
         ) AS lease_owned,
         go.id::text AS t0_observation_id,
         go.s_signature AS t0_s,
         go.p_signature AS t0_p,
         go.b_amount AS t0_b
    FROM operations o
    JOIN receive_codes rc ON rc.operation_id = o.id
    JOIN wallets w ON w.id = o.receiver_wallet_id
    JOIN operation_observation_bindings b
      ON b.operation_id = o.id AND b.evidence_role = 'RECEIVER_T0'
    JOIN gateway_observations go ON go.id = b.observation_id
   WHERE o.kind = 'RECEIVE_EXTERNAL'
     AND o.status = 'READY'
     AND w.public_key = $1
     AND o.discriminator = $2::uuid
   LIMIT 1`;

const RECHECK_SQL = `
  SELECT o.id::text AS operation_id,
         o.amount_zkz AS amount_zkz,
         o.discriminator::text AS discriminator,
         o.anchor AS anchor,
         o.expiry_unix_time_secs::text AS expiry_unix_time_secs,
         o.status::text AS state,
         o.attention_required AS attention_required,
         w.id::text AS receiver_wallet_id,
         w.public_key AS receiver_pubkey,
         rc.code_status::text AS code_status,
         EXISTS (
           SELECT 1 FROM wallet_active_leases l
            WHERE l.operation_id = o.id
              AND l.wallet_id = w.id
              AND l.lease_role = 'RECEIVE_WINDOW'
         ) AS lease_owned,
         go.id::text AS t0_observation_id,
         go.s_signature AS t0_s,
         go.p_signature AS t0_p,
         go.b_amount AS t0_b
    FROM operations o
    JOIN receive_codes rc ON rc.operation_id = o.id
    JOIN wallets w ON w.id = o.receiver_wallet_id
    JOIN operation_observation_bindings b
      ON b.operation_id = o.id AND b.evidence_role = 'RECEIVER_T0'
    JOIN gateway_observations go ON go.id = b.observation_id
   WHERE o.id = $1::uuid
   LIMIT 1`;

type LocateRow = {
  readonly operation_id: string;
  readonly amount_zkz: string;
  readonly discriminator: string;
  readonly anchor: string;
  readonly expiry_unix_time_secs: string;
  readonly state: string;
  readonly attention_required: boolean;
  readonly receiver_wallet_id: string;
  readonly receiver_pubkey: string;
  readonly code_status: string;
  readonly lease_owned: boolean;
  readonly t0_observation_id: string;
  readonly t0_s: string | null;
  readonly t0_p: string | null;
  readonly t0_b: string | null;
};

function mapLocated(row: LocateRow): LocatedReceive {
  return {
    operationId: row.operation_id,
    amountZkz: row.amount_zkz,
    discriminator: row.discriminator,
    anchor: row.anchor,
    expiryUnixTimeSecs: row.expiry_unix_time_secs,
    receiverPubkey: row.receiver_pubkey,
    receiverWalletId: row.receiver_wallet_id,
    state: row.state,
    armed: row.code_status === "RELEASED",
    attentionRequired: row.attention_required === true,
    leaseOwned: row.lease_owned === true,
    receiverT0: {
      S0: row.t0_s ?? GENESIS_PROJECTION.S,
      P0: row.t0_p ?? GENESIS_PROJECTION.P,
      B0: row.t0_b ?? GENESIS_PROJECTION.B,
      observationId: row.t0_observation_id,
    },
  };
}

export function createSqlLocateReceivePort(query: SqlQueryFn): LocateReceivePort {
  return {
    async locate(keys) {
      // Keys.expiry is the PAYER's inner expiry and is deliberately NOT bound here.
      // Identity is receiver pubkey + discriminator (the discriminator is exactly the operation
      // UUID, so it is already unique). The node's own frozen expiry governs validity
      // and is enforced downstream in candidate-intake.ts.
      const rows = (await query(LOCATE_SQL, [
        keys.receiverPubkey,
        keys.discriminator,
      ])) as LocateRow[];
      const row = rows[0];
      return row === undefined ? null : mapLocated(row);
    },
    async recheck(operationId) {
      const rows = (await query(RECHECK_SQL, [operationId])) as LocateRow[];
      const row = rows[0];
      return row === undefined ? null : mapLocated(row);
    },
  };
}

export function createSqlCandidatePersistPort(query: SqlQueryFn): CandidatePersistPort {
  return {
    async claimAndPersist(
      input: PersistWinningCandidateInput,
    ): Promise<PersistWinningCandidateResult> {
      try {
        const phase = await insertTransactionAttempt(query, {
          operationId: input.operationId,
          innerPreimageText: input.innerPreimageText,
          innerSha256: input.innerSha256,
          formedAt: input.formedAt,
          payerStep1Signature: input.step1Signature,
        });
        if (phase !== "STEP1_SIGNATURE_PERSISTED") {
          return { ok: false, reason: "STATE_CHANGED" };
        }
        return { ok: true, attemptPhase: "STEP1_SIGNATURE_PERSISTED" };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/unique|duplicate|23505/i.test(msg)) {
          return { ok: false, reason: "ALREADY_CLAIMED" };
        }
        throw err;
      }
    },
  };
}

export function createCandidateRawCapturePort(nowIso: () => string): CandidateRawCapturePort {
  return {
    captureRaw(input) {
      return {
        innerPreimageText: input.innerPreimageText,
        step1Signature: input.step1Signature,
        capturedAt: nowIso(),
      };
    },
  };
}

const DEFAULT_LIMITS: GatewayLimits = {
  readTimeoutMs: 10_000,
  maxRequestBytes: 1_048_576,
  maxResponseBytes: 4_194_304,
};

export function createGatewaySenderPreflightObserver(deps: {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly endpoint: string;
  readonly limits?: GatewayLimits;
  readonly exchange?: GatewayExchangeTransport;
  /** GATEWAY_READ_RETRY_MAX_ATTEMPTS — absent resolves to the read primitive's default. */
  readonly maxAttempts?: number;
  /** GATEWAY_READ_BACKOFF_MAX_MS — absent resolves to the read primitive's default. */
  readonly backoffMaxMs?: number;
  readonly moneyPathStatementTimeoutMs?: number;
  /**
   * ZTR-1162: production injects createObservedGatewayRead so readiness is stamped
   * on every outcome. Absent → bare readGatewayAction (unit tests).
   */
  readonly readGatewayAction?: typeof readGatewayAction;
}): SenderPreflightObserver {
  return {
    async observe(senderPubkey, _role): Promise<SenderPreflightObservation> {
      try {
        const read = deps.readGatewayAction ?? readGatewayAction;
        const result = await read(
          "get_transaction__v1",
          // Canonical codec — shared with the other three wallet-head readers so the
          // field name cannot drift again.
          buildGetTransactionActionData(senderPubkey),
          {
            endpoints: [deps.endpoint],
            limits: deps.limits ?? DEFAULT_LIMITS,
            recorder: {
              recordObservation: async (observation) => {
                if (!observation.transportAmbiguous) return;
                await persistSqlObservation({
                  pool: deps.pool,
                  nodeId: deps.nodeId,
                  walletPublicKey: senderPubkey,
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
                  projection: {
                    walletRole: null,
                    bAmount: null,
                    innerPreimageText: null,
                    step1Signature: null,
                    step2Signature: null,
                    completedTransactionText: null,
                    completedTransactionSha256: null,
                  },
                });
              },
            },
            ...(deps.exchange !== undefined ? { exchange: deps.exchange } : {}),
            ...(deps.maxAttempts !== undefined ? { maxAttempts: deps.maxAttempts } : {}),
            ...(deps.backoffMaxMs !== undefined ? { backoffMaxMs: deps.backoffMaxMs } : {}),
          },
        );
        const envelope = parseGatewayEnvelope(result.capture.responseBytes);
        if (envelope.classification === "GENESIS") {
          return {
            kind: "VERIFIED",
            observationId: `preflight-genesis:${senderPubkey.slice(0, 12)}`,
            S: GENESIS_PROJECTION.S,
            P: GENESIS_PROJECTION.P,
            B: GENESIS_PROJECTION.B,
          };
        }
        if (envelope.classification !== "HEAD") {
          return { kind: "INDETERMINATE", detail: `envelope=${envelope.classification}` };
        }
        const verified = verifySettledTransaction(envelope.parsed, senderPubkey);
        if (verified.verdict !== "VERIFIED") {
          return { kind: "UNVERIFIED", detail: `sender preflight ${verified.verdict}` };
        }
        return {
          kind: "VERIFIED",
          observationId: `preflight-head:${verified.projection.S.slice(0, 16)}`,
          S: verified.projection.S,
          P: verified.projection.P,
          B: verified.projection.B,
        };
      } catch (err) {
        return {
          kind: "INDETERMINATE",
          detail: err instanceof Error ? err.message : "sender preflight failed",
        };
      }
    },
  };
}
