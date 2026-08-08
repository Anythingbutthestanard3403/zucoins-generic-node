// post-burn orchestration tests: completed-idempotency replay with
// exact stored bytes, fingerprint conflict resolved before any protected lookup, guarded
// partial uniqueness on the two mutation routes, and burn retention across every post-burn
// failure (404, handler crash). The protected-object surface is the injected handler
// registry — an absent handler is the absent-object 404, after the burn.

import { describe, expect, it } from "vitest";

import { reportingJsonResponse, type ReportingHttpResponse } from "./errors.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import { createReportingRequestHandler, type ReportingRouteHandler } from "./request-handler.js";
import type { CapturedReportRequest } from "./request-verifier.js";
import {
  IDEMPOTENCY_KEY,
  IMPLEMENTER_ID,
  ISSUED_MS,
  keyFromSeed,
  makeVerifier,
  MID_WINDOW_MS,
  NODE_ID,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
  utf8,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);
const MUTATION_TARGET = "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete";

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function mutationRequest(nonce: string, body: string, idempotencyKey = IDEMPOTENCY_KEY): CapturedReportRequest {
  return signRequest({
    privateKey: TEST_PRIV,
    method: "POST",
    target: MUTATION_TARGET,
    body,
    nonce,
    issuedAtMs: ISSUED_MS,
    expiresAtMs: ISSUED_MS + 60_000,
    idempotencyKey,
  });
}

function fixture(handlers: Readonly<Record<string, ReportingRouteHandler>>) {
  const store = new InMemoryReportingStore();
  seedGoldenStore(store, pubOf(TEST_PRIV));
  let requestCounter = 0;
  const handler = createReportingRequestHandler({
    verifier: makeVerifier(store),
    store,
    handlers,
    newRequestId: () => `request-${(requestCounter += 1)}`,
    nowMs: () => MID_WINDOW_MS,
  });
  return { store, handle: handler.handle };
}

function countingHandler(body = "{\"ok\":true}"): {
  calls: number;
  handler: ReportingRouteHandler;
} {
  const state = {
    calls: 0,
    handler: (): Promise<{
      response: ReportingHttpResponse;
      persistChild: () => Promise<string>;
    }> => {
      state.calls += 1;
      return Promise.resolve({
        response: reportingJsonResponse(200, body),
        persistChild: () => Promise.resolve("child-1"),
      });
    },
  };
  return state;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe("completed idempotency replay and conflict", () => {
  it("replays the stored exact status and bytes with Idempotency-Replayed on retry", async () => {
    const okHandler = countingHandler();
    const { handle } = fixture({ verification_complete: okHandler.handler });
    const first = await handle(mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}"));
    expect(first.status).toBe(200);
    expect(text(first.bodyBytes)).toBe("{\"ok\":true}");
    expect(okHandler.calls).toBe(1);

    const retry = await handle(mutationRequest("22222222-2222-4222-8222-222222222222", "{\"arm\":true}"));
    expect(retry.status).toBe(200);
    expect(retry.headers["idempotency-replayed"]).toBe("true");
    expect(text(retry.bodyBytes)).toBe("{\"ok\":true}");
    expect(okHandler.calls).toBe(1);
  });

  // parent PK is uuid insertable into reporting_mutation_idempotency.id; within
  // the UoW the same uuid is passed to persistChild as completedIdempotencyId (child
  // mutation_idempotency_id correlation). Replay still keys off the composite, not the PK.
  it("mints a uuid PK and passes it to persistChild for parent↔child correlation", async () => {
    let seenParentId: string | undefined;
    const correlating: ReportingRouteHandler = () =>
      Promise.resolve({
        response: reportingJsonResponse(200, "{\"ok\":true}"),
        persistChild: async (_tx, completedIdempotencyId) => {
          seenParentId = completedIdempotencyId;
          return "child-correlated-1";
        },
      });
    const { store, handle } = fixture({ verification_complete: correlating });
    const first = await handle(mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}"));
    expect(first.status).toBe(200);
    const completed = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      IDEMPOTENCY_KEY,
    );
    expect(completed).not.toBeNull();
    expect(completed!.id).toMatch(UUID_RE);
    expect(completed!.id.startsWith("idempotency-")).toBe(false);
    expect(completed!.reportingNonceId).not.toBe(completed!.id);
    expect(seenParentId).toBe(completed!.id);
    expect(completed!.childRecordId).toBe("child-correlated-1");
  });

  it("conflicts a changed fingerprint under the same key without running the handler again", async () => {
    const okHandler = countingHandler();
    const { store, handle } = fixture({ verification_complete: okHandler.handler });
    await handle(mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}"));
    const conflict = await handle(
      mutationRequest("22222222-2222-4222-8222-222222222222", "{\"arm\":false}"),
    );
    expect(conflict.status).toBe(409);
    expect(JSON.parse(text(conflict.bodyBytes)).error.code).toBe("idempotency_conflict");
    expect(okHandler.calls).toBe(1);
    // Both authenticated attempts burned their nonces.
    expect(store.listNonceEvidence().length).toBe(2);
  });

  it("guarded uniqueness stops a second completion of the same mutation under a new key", async () => {
    const okHandler = countingHandler();
    const { handle } = fixture({ verification_complete: okHandler.handler });
    await handle(mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}"));
    const second = await handle(
      mutationRequest("22222222-2222-4222-8222-222222222222", "{\"arm\":true}", "idempotency-key-0002"),
    );
    // The guarded partial-unique index over the actual (method, target, body) triple turns
    // the racing second completion into a 409, not a double-recorded mutation.
    expect(second.status).toBe(409);
    expect(JSON.parse(text(second.bodyBytes)).error.code).toBe("idempotency_conflict");
  });
});

describe("handler-result shape gate", () => {
  it("surfaces a 2xx result whose persistChild returns empty child id as internal_error, writing no completion row", async () => {
    const malformed: ReportingRouteHandler = () =>
      Promise.resolve({ response: reportingJsonResponse(200, "{\"ok\":true}"), persistChild: () => Promise.resolve("") });
    const { store, handle } = fixture({ verification_complete: malformed });
    const request = mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}");
    const response = await handle(request);
    expect(response.status).toBe(500);
    expect(JSON.parse(text(response.bodyBytes)).error.code).toBe("internal_error");
    // The burn is retained, but NO completion row exists (the malformed result never reaches
    // the completion write), so a replay meets the nonce guard rather than a replay lookup.
    expect(store.listNonceEvidence().length).toBe(1);
    const completed = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      IDEMPOTENCY_KEY,
    );
    expect(completed).toBeNull();
  });

  it.each([99, 600, 200.5])(
    "surfaces a non-integer or out-of-range status (%s) as internal_error, writing no completion row",
    async (status) => {
      const malformed: ReportingRouteHandler = () =>
        Promise.resolve({
          response: {
            status,
            headers: { "content-type": "application/json" },
            bodyBytes: utf8("{\"ok\":true}"),
          },
          persistChild: () => Promise.resolve("child-1"),
        });
      const { store, handle } = fixture({ verification_complete: malformed });
      const response = await handle(
        mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}"),
      );
      expect(response.status).toBe(500);
      expect(JSON.parse(text(response.bodyBytes)).error.code).toBe("internal_error");
      expect(store.listNonceEvidence().length).toBe(1);
      const completed = await store.findCompletedIdempotency(
        NODE_ID,
        IMPLEMENTER_ID,
        "verification_complete",
        IDEMPOTENCY_KEY,
      );
      expect(completed).toBeNull();
    },
  );
});

describe("burn retention across post-burn failure", () => {
  it("retains the burn on the absent-handler 404 and rejects the nonce replay afterwards", async () => {
    const { store, handle } = fixture({});
    const request = mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}");
    const absent = await handle(request);
    expect(absent.status).toBe(404);
    expect(store.listNonceEvidence().length).toBe(1);
    const replay = await handle(request);
    expect(replay.status).toBe(401);
    // nonce_replay is a credential-state rejection, so the wire carries the single collapsed
    // code; the replay detection itself is asserted on the server-side record.
    expect(JSON.parse(text(replay.bodyBytes)).error.code).toBe("invalid_api_key");
    expect(replay.collapsedRejection?.code).toBe("nonce_replay");
    expect(store.listNonceEvidence().length).toBe(1);
  });

  it("retains the burn on a handler crash, returning 500 with no completion row", async () => {
    const crashing: ReportingRouteHandler = () => Promise.reject(new Error("boom"));
    const { store, handle } = fixture({ verification_complete: crashing });
    const request = mutationRequest("11111111-1111-4111-8111-111111111111", "{\"arm\":true}");
    const crashed = await handle(request);
    expect(crashed.status).toBe(500);
    expect(JSON.parse(text(crashed.bodyBytes)).error.code).toBe("internal_error");
    expect(store.listNonceEvidence().length).toBe(1);
    const replay = await handle(request);
    expect(replay.status).toBe(401);
    // nonce_replay is a credential-state rejection, so the wire carries the single collapsed
    // code; the replay detection itself is asserted on the server-side record.
    expect(JSON.parse(text(replay.bodyBytes)).error.code).toBe("invalid_api_key");
    expect(replay.collapsedRejection?.code).toBe("nonce_replay");
    expect(store.listNonceEvidence().length).toBe(1);
  });
});

describe("read routes", () => {
  it("resolves a dark read route as 404 after the burn, and passes an injected handler through", async () => {
    const { handle } = fixture({});
    const readRequest = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: "11111111-1111-4111-8111-111111111111",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    expect((await handle(readRequest)).status).toBe(404);

    const readHandler: ReportingRouteHandler = () =>
      Promise.resolve({ response: reportingJsonResponse(200, "{\"events\":[]}"), persistChild: null });
    const secondFixture = fixture({ events_list: readHandler });
    const secondRead = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: "22222222-2222-4222-8222-222222222222",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const served = await secondFixture.handle(secondRead);
    expect(served.status).toBe(200);
    expect(text(served.bodyBytes)).toBe("{\"events\":[]}");
    expect(served.headers["idempotency-replayed"]).toBeUndefined();
  });
});


describe("mutation + completed idempotency atomicity", () => {
  it("commits child and completed parent together so a same-key retry replays exact bytes", async () => {
    const childCalls: string[] = [];
    const ok: ReportingRouteHandler = () =>
      Promise.resolve({
        response: reportingJsonResponse(200, '{"armed":true}'),
        persistChild: async () => {
          childCalls.push("child-atomic-1");
          return "child-atomic-1";
        },
      });
    const { store, handle } = fixture({ verification_complete: ok });
    const first = await handle(
      mutationRequest("11111111-1111-4111-8111-111111111111", '{"arm":true}'),
    );
    expect(first.status).toBe(200);
    expect(childCalls).toEqual(["child-atomic-1"]);
    const completed = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      IDEMPOTENCY_KEY,
    );
    expect(completed?.childRecordId).toBe("child-atomic-1");
    expect(text(completed!.responseBytes)).toBe('{"armed":true}');

    const retry = await handle(
      mutationRequest("22222222-2222-4222-8222-222222222222", '{"arm":true}'),
    );
    expect(retry.status).toBe(200);
    expect(retry.headers["idempotency-replayed"]).toBe("true");
    expect(text(retry.bodyBytes)).toBe('{"armed":true}');
    expect(childCalls).toEqual(["child-atomic-1"]);
  });

  it("rolls back the unit of work when persistChild throws — no completion row, burn retained", async () => {
    const failing: ReportingRouteHandler = () =>
      Promise.resolve({
        response: reportingJsonResponse(200, '{"ok":true}'),
        persistChild: () => Promise.reject(new Error("child write failed")),
      });
    const { store, handle } = fixture({ verification_complete: failing });
    const response = await handle(
      mutationRequest("11111111-1111-4111-8111-111111111111", '{"arm":true}'),
    );
    expect(response.status).toBe(500);
    expect(JSON.parse(text(response.bodyBytes)).error.code).toBe("internal_error");
    expect(store.listNonceEvidence().length).toBe(1);
    const completed = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      IDEMPOTENCY_KEY,
    );
    expect(completed).toBeNull();
  });

  it("returns CONFLICT from the store UoW when the parent key is already taken", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store, pubOf(TEST_PRIV));
    await store.insertCompletedIdempotency({
      id: "idempotency-preseed",
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      routeId: "verification_complete",
      idempotencyKey: IDEMPOTENCY_KEY,
      reportingNonceId: "nonce-preseed",
      childRecordId: "child-preseed",
      method: "POST",
      rawTarget: MUTATION_TARGET,
      bodySha256: "00".repeat(32),
      logicalFingerprint: "11".repeat(32),
      responseStatus: 200,
      responseBytes: new TextEncoder().encode('{"prior":true}'),
      completedAtMs: MID_WINDOW_MS,
    });
    let childRan = false;
    const childEffects = new Map<string, string>();
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        childRan = true;
        tx.stageChildEffect!(
          () => {
            childEffects.set("racer", "applied");
          },
          () => {
            childEffects.delete("racer");
          },
        );
        return "child-racer";
      },
      record: {
        id: "idempotency-racer",
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        routeId: "verification_complete",
        idempotencyKey: IDEMPOTENCY_KEY,
        reportingNonceId: "nonce-racer",
        method: "POST",
        rawTarget: MUTATION_TARGET,
        bodySha256: "ab".repeat(32),
        logicalFingerprint: "cd".repeat(32),
        responseStatus: 200,
        responseBytes: new TextEncoder().encode('{"racer":true}'),
        completedAtMs: MID_WINDOW_MS,
      },
    });
    expect(childRan).toBe(true);
    expect(childEffects.has("racer")).toBe(false);
    expect(outcome).toEqual({ kind: "CONFLICT" });
    const completed = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      IDEMPOTENCY_KEY,
    );
    expect(completed?.childRecordId).toBe("child-preseed");
  });
});

