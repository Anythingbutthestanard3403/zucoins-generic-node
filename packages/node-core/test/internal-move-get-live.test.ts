import { describe, expect, it } from "vitest";

import { createSqlOperationRouteStore } from "../src/operation-route-store.js";
import type {
  MoveCreateStore,
  MoveReadProjection,
  StoredMoveOperation,
} from "../src/move/create.js";
import { SqlMoveCreateStore } from "../src/move/sql-store.js";

const OP_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const IMPL = "11111111-2222-4333-8444-555555555555";
const NODE = "99999999-8888-4777-8666-555555555555";
const SOURCE = "22222222-3333-4444-8555-666666666666";
const DESTINATION = "33333333-4444-4555-8666-777777777777";
const DESTINATION_WALLET = "44444444-5555-4666-8777-888888888888";
const SOURCE_TERMINAL = "55555555-6666-4777-8888-999999999999";
const DESTINATION_TERMINAL = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const KEY_ID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb";
const PREIMAGE = "zp-move-internal-expected-v1\n{\"spacing\":\"must stay exact\"}\n";
const SIGNATURE = `${"A".repeat(86)}==`;

function operation(overrides: Partial<StoredMoveOperation> = {}): StoredMoveOperation {
  return {
    operationId: OP_ID,
    implementerId: IMPL,
    nodeId: NODE,
    kind: "MOVE_INTERNAL",
    status: "INTERNAL_MOVE_LANDED",
    rowVersion: 7,
    attentionRequired: false,
    sourceWalletId: SOURCE,
    destinationId: DESTINATION,
    destinationWalletId: DESTINATION_WALLET,
    amountZkz: "1.25",
    clientReference: null,
    spawnedFromOperationId: null,
    leaseGroupId: OP_ID,
    idempotencyKey: "internal-move-live-read",
    requestSha256: "a".repeat(64),
    verificationMode: "INDEPENDENT",
    createdAt: Date.parse("2026-08-01T00:00:00.000Z"),
    updatedAt: Date.parse("2026-08-01T00:05:00.000Z"),
    ...overrides,
  };
}

function projection(overrides: Partial<MoveReadProjection> = {}): MoveReadProjection {
  return {
    attentionReason: null,
    terminalAt: "2026-08-01T00:05:00.000Z",
    verificationMaterialAvailableUntil: "2026-08-31T00:05:00.000Z",
    activeLeaseCount: 0,
    expectedArtifact: {
      keyId: KEY_ID,
      preimageText: PREIMAGE,
      preimageSha256: "b".repeat(64),
      signature: SIGNATURE,
    },
    executionFacts: {
      operationKind: "MOVE_INTERNAL",
      attemptPhase: "SETTLED_BODY_PERSISTED",
      signIntentPersisted: false,
      partialPersisted: false,
      partialFirstDelivered: false,
      submitStarted: true,
      submitReturned: true,
      verificationAccepted: true,
      terminalObservationsPresent: true,
    },
    sourceTerminalObservationId: SOURCE_TERMINAL,
    destinationTerminalObservationId: DESTINATION_TERMINAL,
    ...overrides,
  };
}

function routeStore(row: StoredMoveOperation, live: MoveReadProjection) {
  const move: MoveCreateStore = {
    findSourceWallet: async () => null,
    findDestination: async () => null,
    hasActiveLease: async () => false,
    insertAdmitted: async () => ({ kind: "IDEMPOTENCY_CONFLICT" }),
    findByIdempotency: async () => null,
    findByOperationId: async () => row,
    readProjection: async () => live,
  };
  return createSqlOperationRouteStore({
    nodeId: NODE,
    queueCap: 8,
    receive: {} as never,
    move,
    send: {} as never,
    sendSigner: {} as never,
  });
}

describe("GET /v1/internal-moves/:operation_id live projection", () => {
  it("returns persisted signed bytes and derives landed live facts", async () => {
    const got = await routeStore(operation(), projection()).getInternalMove(OP_ID, IMPL);

    expect(got).toEqual({
      operation: {
        operation_id: OP_ID,
        operation_type: "MOVE_INTERNAL",
        state: "INTERNAL_MOVE_LANDED",
        amount_zkz: "1.25",
        row_version: 7,
        attention_required: false,
        attention_reason: null,
        created_at: "2026-08-01T00:00:00.000Z",
        updated_at: "2026-08-01T00:05:00.000Z",
        terminal_at: "2026-08-01T00:05:00.000Z",
        verification_material_available_until: "2026-08-31T00:05:00.000Z",
        verification_mode: "INDEPENDENT",
      },
      source_wallet_id: SOURCE,
      destination_id: DESTINATION,
      spawned_from_operation_id: null,
      lease_status: "RELEASED",
      execution_phase: "LANDED_VERIFIED",
      expected_artifact: {
        key_id: KEY_ID,
        preimage_text: PREIMAGE,
        preimage_sha256: "b".repeat(64),
        signature: SIGNATURE,
      },
      source_terminal_observation_id: SOURCE_TERMINAL,
      destination_terminal_observation_id: DESTINATION_TERMINAL,
    });
    expect(got!.expected_artifact!.preimage_text).toBe(PREIMAGE);
    expect(got!.expected_artifact!.signature).toBe(SIGNATURE);
  });

  it.each([
    [2, false, "HELD"],
    [1, false, "PINNED_FOR_ATTENTION"],
    [2, true, "PINNED_FOR_ATTENTION"],
    [0, false, "RELEASED"],
  ] as const)("projects %i active leases and attention=%s as %s", async (activeLeaseCount, attentionRequired, expected) => {
    const got = await routeStore(
      operation({ attentionRequired, status: attentionRequired ? "NEEDS_ATTENTION" : "INTERNAL_MOVE_LANDED" }),
      projection({ activeLeaseCount, attentionReason: attentionRequired ? "SUBMIT_INDETERMINATE" : null }),
    ).getInternalMove(OP_ID, IMPL);
    expect(got!.lease_status).toBe(expected);
  });

  it("uses the production SQL adapter and returns persisted artifact columns without reconstruction", async () => {
    const statements: string[] = [];
    const sql = {
      async query<R>(text: string): Promise<{ rows: R[] }> {
        statements.push(text);
        if (text.includes("SELECT attempt_phase FROM operation_transactions")) {
          return {
            rows: [{
              attempt_phase: "SETTLED_BODY_PERSISTED",
              sign_intent_persisted: false,
              partial_persisted: false,
              partial_first_delivered: false,
            } as R],
          };
        }
        if (text.includes("SELECT o.attention_reason")) {
          return {
            rows: [{
              attention_reason: null,
              terminal_at_ms: Date.parse("2026-08-01T00:05:00.000Z"),
              verification_until_ms: Date.parse("2026-08-31T00:05:00.000Z"),
              active_lease_count: 0,
              signing_key_id: KEY_ID,
              preimage_text: PREIMAGE,
              preimage_sha256: "b".repeat(64),
              signature: SIGNATURE,
              source_terminal_observation_id: SOURCE_TERMINAL,
              destination_terminal_observation_id: DESTINATION_TERMINAL,
              submit_started: true,
              submit_returned: true,
              verification_accepted: true,
            } as R],
          };
        }
        if (text.includes("WHERE o.id = $1")) {
          return {
            rows: [{
              id: OP_ID,
              implementer_id: IMPL,
              node_id: NODE,
              kind: "MOVE_INTERNAL",
              status: "INTERNAL_MOVE_LANDED",
              row_version: 7,
              attention_required: false,
              source_wallet_id: SOURCE,
              destination_id: DESTINATION,
              destination_wallet_id: DESTINATION_WALLET,
              amount_zkz: "1.25",
              spawned_from_operation_id: null,
              lease_group_id: OP_ID,
              idempotency_key: "internal-move-live-read",
              request_sha256: "a".repeat(64),
              created_at_ms: Date.parse("2026-08-01T00:00:00.000Z"),
              updated_at_ms: Date.parse("2026-08-01T00:05:00.000Z"),
            } as R],
          };
        }
        throw new Error(`unexpected SQL: ${text}`);
      },
    };
    const move = new SqlMoveCreateStore({ sql });
    const ops = createSqlOperationRouteStore({
      nodeId: NODE,
      queueCap: 8,
      receive: {} as never,
      move,
      send: {} as never,
      sendSigner: {} as never,
    });

    const got = await ops.getInternalMove(OP_ID, IMPL);
    expect(got!.expected_artifact!.preimage_text).toBe(PREIMAGE);
    expect(got!.expected_artifact!.signature).toBe(SIGNATURE);
    expect(statements.some((text) => text.includes("LEFT JOIN operation_expected_artifacts"))).toBe(true);
    expect(statements.some((text) => text.includes("wallet_active_leases"))).toBe(true);
    expect(statements.some((text) => text.includes("move_observation_evidence"))).toBe(true);
    expect(statements.some((text) => text.includes("operation_wallets"))).toBe(false);
    expect(statements.some((text) => text.includes("gateway_submit_attempts"))).toBe(true);
    expect(statements.some((text) => text.includes("operation_verifications"))).toBe(true);
    expect(got!.source_terminal_observation_id).toBe(SOURCE_TERMINAL);
    expect(got!.destination_terminal_observation_id).toBe(DESTINATION_TERMINAL);
    expect(got!.execution_phase).toBe("LANDED_VERIFIED");
  });

  /**
   * Regression for producer/reader table mismatch (Review A FAIL on f8aa614):
   * persistMoveOutcome writes terminals only to move_observation_evidence; GET must
   * project those same columns. A synthetic SQL driver serves terminals only when the
   * SELECT text references move_observation_evidence — matching the real writer table —
   * and leaves them null if the reader still queries operation_wallets. Old head fails;
   * fixed head yields both IDs and LANDED_VERIFIED.
   */
  it("projects landed terminal IDs from move_observation_evidence (landing writer table)", async () => {
    const statements: string[] = [];
    const sql = {
      async query<R>(text: string): Promise<{ rows: R[] }> {
        statements.push(text);
        if (text.includes("SELECT attempt_phase FROM operation_transactions")) {
          return {
            rows: [{
              attempt_phase: "SETTLED_BODY_PERSISTED",
              sign_intent_persisted: false,
              partial_persisted: false,
              partial_first_delivered: false,
            } as R],
          };
        }
        if (text.includes("SELECT o.attention_reason")) {
          // Mimic durable state after persistMoveOutcome: terminals live only on evidence.
          const readsEvidence = text.includes("move_observation_evidence");
          const readsWalletsOnly =
            text.includes("operation_wallets") && !readsEvidence;
          // Fail closed if both wrong tables somehow appear — force evidence path.
          const source = readsEvidence ? SOURCE_TERMINAL : null;
          const destination = readsEvidence ? DESTINATION_TERMINAL : null;
          if (readsWalletsOnly) {
            // Old-head path: would return nulls even though landing wrote evidence.
          }
          return {
            rows: [{
              attention_reason: null,
              terminal_at_ms: Date.parse("2026-08-01T00:05:00.000Z"),
              verification_until_ms: Date.parse("2026-08-31T00:05:00.000Z"),
              active_lease_count: 0,
              signing_key_id: KEY_ID,
              preimage_text: PREIMAGE,
              preimage_sha256: "b".repeat(64),
              signature: SIGNATURE,
              source_terminal_observation_id: source,
              destination_terminal_observation_id: destination,
              submit_started: true,
              submit_returned: true,
              verification_accepted: true,
            } as R],
          };
        }
        if (text.includes("WHERE o.id = $1")) {
          return {
            rows: [{
              id: OP_ID,
              implementer_id: IMPL,
              node_id: NODE,
              kind: "MOVE_INTERNAL",
              status: "INTERNAL_MOVE_LANDED",
              row_version: 7,
              attention_required: false,
              source_wallet_id: SOURCE,
              destination_id: DESTINATION,
              destination_wallet_id: DESTINATION_WALLET,
              amount_zkz: "1.25",
              spawned_from_operation_id: null,
              lease_group_id: OP_ID,
              idempotency_key: "internal-move-live-read",
              request_sha256: "a".repeat(64),
              created_at_ms: Date.parse("2026-08-01T00:00:00.000Z"),
              updated_at_ms: Date.parse("2026-08-01T00:05:00.000Z"),
            } as R],
          };
        }
        throw new Error(`unexpected SQL: ${text}`);
      },
    };
    const move = new SqlMoveCreateStore({ sql });
    const ops = createSqlOperationRouteStore({
      nodeId: NODE,
      queueCap: 8,
      receive: {} as never,
      move,
      send: {} as never,
      sendSigner: {} as never,
    });

    const got = await ops.getInternalMove(OP_ID, IMPL);
    const projectionSql = statements.find((text) => text.includes("SELECT o.attention_reason"));
    expect(projectionSql).toBeDefined();
    expect(projectionSql!).toContain("move_observation_evidence");
    expect(projectionSql!).not.toContain("operation_wallets");
    // Landing writer columns (persistMoveOutcome UPDATE move_observation_evidence).
    expect(projectionSql!).toContain("source_terminal_observation_id");
    expect(projectionSql!).toContain("destination_terminal_observation_id");
    expect(got!.source_terminal_observation_id).toBe(SOURCE_TERMINAL);
    expect(got!.destination_terminal_observation_id).toBe(DESTINATION_TERMINAL);
    expect(got!.execution_phase).toBe("LANDED_VERIFIED");
    expect(got!.expected_artifact!.preimage_text).toBe(PREIMAGE);
    expect(got!.expected_artifact!.signature).toBe(SIGNATURE);
  });

  it("keeps terminal IDs null and phase non-landed when evidence row has no terminals", async () => {
    const sql = {
      async query<R>(text: string): Promise<{ rows: R[] }> {
        if (text.includes("SELECT attempt_phase FROM operation_transactions")) {
          return {
            rows: [{
              attempt_phase: "SETTLED_BODY_PERSISTED",
              sign_intent_persisted: false,
              partial_persisted: false,
              partial_first_delivered: false,
            } as R],
          };
        }
        if (text.includes("SELECT o.attention_reason")) {
          expect(text).toContain("move_observation_evidence");
          return {
            rows: [{
              attention_reason: null,
              terminal_at_ms: null,
              verification_until_ms: null,
              active_lease_count: 2,
              signing_key_id: KEY_ID,
              preimage_text: PREIMAGE,
              preimage_sha256: "b".repeat(64),
              signature: SIGNATURE,
              source_terminal_observation_id: null,
              destination_terminal_observation_id: null,
              submit_started: true,
              submit_returned: true,
              verification_accepted: false,
            } as R],
          };
        }
        if (text.includes("WHERE o.id = $1")) {
          return {
            rows: [{
              id: OP_ID,
              implementer_id: IMPL,
              node_id: NODE,
              kind: "MOVE_INTERNAL",
              status: "SUBMITTED",
              row_version: 3,
              attention_required: false,
              source_wallet_id: SOURCE,
              destination_id: DESTINATION,
              destination_wallet_id: DESTINATION_WALLET,
              amount_zkz: "1.25",
              spawned_from_operation_id: null,
              lease_group_id: OP_ID,
              idempotency_key: "internal-move-live-read",
              request_sha256: "a".repeat(64),
              created_at_ms: Date.parse("2026-08-01T00:00:00.000Z"),
              updated_at_ms: Date.parse("2026-08-01T00:01:00.000Z"),
            } as R],
          };
        }
        throw new Error(`unexpected SQL: ${text}`);
      },
    };
    const move = new SqlMoveCreateStore({ sql });
    const ops = createSqlOperationRouteStore({
      nodeId: NODE,
      queueCap: 8,
      receive: {} as never,
      move,
      send: {} as never,
      sendSigner: {} as never,
    });
    const got = await ops.getInternalMove(OP_ID, IMPL);
    expect(got!.source_terminal_observation_id).toBeNull();
    expect(got!.destination_terminal_observation_id).toBeNull();
    expect(got!.execution_phase).not.toBe("LANDED_VERIFIED");
    expect(got!.lease_status).toBe("HELD");
  });
});
