import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiSoftRead } from "./api.js";
import {
  getOperationInventory,
  getWalletInventory,
  listAuditInventory,
  listDeviceKeys,
  postEnrollmentChallenge,
  postGenesisEnrol,
  listDestinationsInventory,
  listSendOperationsInventory,
  listWalletsInventory,
  pollSendState,
  postApprove,
  postBless,
  postHaltToggle,
  postIssueApiKey,
  postRecoveryAction,
  postReject,
  postRetire,
  postRevokeApiKey,
} from "./money.js";
import { useAuth } from "../store/auth.js";

function liveAuth(csrf = "csrf-x") {
  useAuth.setState({
    user: {
      userId: "u1",
      role: "admin",
      mustEnrolTotp: false,
      mustChangePassword: false,
      csrfToken: csrf,
    },
      });
}

function jsonRes(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status });
}

describe("money mutations — no demo/apiSoftRead success", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it("apiSoftRead throws on POST so mutations cannot hide 404/503", async () => {
    await expect(
      apiSoftRead("/external-sends/x/approve", { ok: true }, { method: "POST", body: "{}" }),
    ).rejects.toThrow(/apiSoftRead is read-only/);
  });
});

describe("inventory list*() propagate the caught ApiError's code/message/requestId", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it.each([
    ["listWalletsInventory", listWalletsInventory],
    ["listDestinationsInventory", listDestinationsInventory],
    ["listAuditInventory", listAuditInventory],
    ["listSendOperationsInventory", listSendOperationsInventory],
  ] as const)("%s surfaces the 500 detail instead of a bare live:false", async (_name, fn) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(500, { error: { code: "internal_error", message: "boom", request_id: "req-500" } }),
      ),
    );
    const r = await fn();
    expect(r.live).toBe(false);
    expect(r.data).toEqual([]);
    expect(r.error).toEqual({
      code: "internal_error",
      message: "boom",
      requestId: "req-500",
      status: 500,
    });
  });
});

describe("getOperationInventory", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it("returns null on 404 only", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(404, { error: { code: "not_found", message: "gone" } }),
      ),
    );
    await expect(getOperationInventory("op-1")).resolves.toBeNull();
  });

  it("rethrows 503 (outage is not absence)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(503, { error: { code: "service_unavailable", message: "down" } }),
      ),
    );
    await expect(getOperationInventory("op-1")).rejects.toMatchObject({
      status: 503,
      code: "service_unavailable",
    });
  });
});

describe("operationDetailPath", () => {
  it("routes sends to transfer dual-control and everything else to operation detail", async () => {
    const { operationDetailPath, isSendOperationType } = await import("./money.js");
    // Every type opens the operation detail view (SEND approve stays on /transfers).
    expect(operationDetailPath("op-1", "SEND_EXTERNAL")).toBe("/operations/op-1");
    expect(operationDetailPath("op-2", "RECEIVE_EXTERNAL")).toBe("/operations/op-2");
    expect(operationDetailPath("op-3", "MOVE_INTERNAL")).toBe("/operations/op-3");
    expect(operationDetailPath("op-4")).toBe("/operations/op-4");
    expect(isSendOperationType("SEND_EXTERNAL")).toBe(true);
    expect(isSendOperationType("RECEIVE_EXTERNAL")).toBe(false);
  });
});

describe("pollSendState — never invents APPROVED", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it("recovery 503 + inventory 503 + challenge 404 ⇒ unknown, not APPROVED", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/recovery")) {
        return jsonRes(503, { error: { code: "service_unavailable", message: "rec" } });
      }
      if (url.includes("/operations/") && !url.includes("recovery")) {
        return jsonRes(503, { error: { code: "service_unavailable", message: "inv" } });
      }
      if (url.includes("/approval-challenge")) {
        return jsonRes(404, { error: { code: "not_found", message: "gone" } });
      }
      return jsonRes(404, { error: { code: "not_found", message: url } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const r = await pollSendState("op-x", { attempts: 2, delayMs: 0 });
    expect(r.status).toBe("unknown");
    expect(r.source).toBe("unknown");
    expect(r.status).not.toBe("APPROVED");
  });

  it("accepts APPROVED only from recovery body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/recovery")) {
          return jsonRes(200, {
            operation_id: "op",
            operation_type: "SEND_EXTERNAL",
            status: "APPROVED",
            attention_required: false,
            attention_reason: null,
            classification: "WAITING",
            classification_rationale: "x",
            permitted_actions: [],
            held_leases: [],
            row_version: 2,
            lease_epoch: null,
            recovery_nonce: "n",
            recovery_nonce_issued_at: "t",
            recovery_nonce_expires_at: "t",
          });
        }
        return jsonRes(404, { error: { code: "not_found", message: "n" } });
      }),
    );
    const r = await pollSendState("op", { attempts: 1, delayMs: 0 });
    expect(r).toEqual({ status: "APPROVED", source: "recovery" });
  });

  it("accepts terminal status from inventory when recovery fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/recovery")) {
          return jsonRes(503, { error: { code: "service_unavailable", message: "x" } });
        }
        if (url.includes("/operations/")) {
          return jsonRes(200, {
            operation_id: "op",
            operation_type: "SEND_EXTERNAL",
            status: "REJECTED",
            amount_zkz: "0.01",
            row_version: 2,
            attention_required: false,
            attention_reason: null,
            created_at: "t",
          });
        }
        return jsonRes(404, { error: { code: "not_found", message: "n" } });
      }),
    );
    const r = await pollSendState("op", { attempts: 1, delayMs: 0 });
    expect(r).toEqual({ status: "REJECTED", source: "inventory" });
  });
});

describe("money mutations — CSRF + TOTP fail-closed", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  const approveBody = {
    challenge_nonce: "n",
    expected_row_version: 1,
    preimage_sha256: "a".repeat(64),
    device_key_id: null,
    device_signature: null,
  };

  it.each([
    ["postApprove", () => postApprove("op", approveBody, "12")],
    ["postReject", () => postReject("op", { expected_row_version: 1, reason: "x" }, "")],
    [
      "postRecoveryAction",
      () =>
        postRecoveryAction(
          "op",
          { action: "ACK", expected_row_version: 1, recovery_nonce: "n" },
          "abcdef",
        ),
    ],
    [
      "postBless",
      () =>
        postBless(
          "d1",
          {
            nonce: "n",
            issued_at: "t",
            expires_at: "t",
            device_key_id: "device-1",
            device_signature: "sig",
          },
          "12345",
        ),
    ],
    ["postRetire", () => postRetire("d1", "12345a")],
  ] as const)("%s rejects non-6-digit TOTP before fetch", async (_name, call) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(call()).rejects.toMatchObject({ code: "totp_required", status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("postApprove refuses empty CSRF before fetch", async () => {
    liveAuth("");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(postApprove("op", approveBody, "123456")).rejects.toMatchObject({
      code: "csrf_required",
      status: 403,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("complete admin inventories", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it.each([
    {
      name: "wallets",
      call: () => listWalletsInventory({ state: "AVAILABLE", limit: 2 }),
      firstPath: "/admin/v1/wallets?state=AVAILABLE&limit=2",
      cursorPath: "/admin/v1/wallets?state=AVAILABLE&limit=2&after=wallet-2",
      first: [{ wallet_id: "wallet-1" }, { wallet_id: "wallet-2" }],
      second: [{ wallet_id: "wallet-3" }],
      ids: (rows: readonly unknown[]) =>
        rows.map((row) => String((row as { wallet_id: unknown }).wallet_id)),
    },
    {
      name: "destinations",
      call: () => listDestinationsInventory({ state: "BLESSED", limit: 2 }),
      firstPath: "/admin/v1/destinations?state=BLESSED&limit=2",
      cursorPath: "/admin/v1/destinations?state=BLESSED&limit=2&after=destination-2",
      first: [{ destination_id: "destination-1" }, { destination_id: "destination-2" }],
      second: [{ destination_id: "destination-3" }],
      ids: (rows: readonly unknown[]) =>
        rows.map((row) => String((row as { destination_id: unknown }).destination_id)),
    },
    {
      name: "send operations",
      call: () => listSendOperationsInventory({ status: "CREATED", limit: 2 }),
      firstPath: "/admin/v1/operations?kind=SEND_EXTERNAL&status=CREATED&limit=2",
      cursorPath:
        "/admin/v1/operations?kind=SEND_EXTERNAL&status=CREATED&limit=2&after=operation-2",
      first: [{ operation_id: "operation-1" }, { operation_id: "operation-2" }],
      second: [{ operation_id: "operation-3" }],
      ids: (rows: readonly unknown[]) =>
        rows.map((row) => String((row as { operation_id: unknown }).operation_id)),
    },
    {
      name: "audit",
      call: () => listAuditInventory({ actor_kind: "ADMIN", action: "LOGIN", limit: 2 }),
      firstPath: "/admin/v1/audit?actor_kind=ADMIN&action=LOGIN&limit=2",
      cursorPath: "/admin/v1/audit?actor_kind=ADMIN&action=LOGIN&limit=2&after=audit-2",
      first: [{ id: "audit-1" }, { id: "audit-2" }],
      second: [{ id: "audit-3" }],
      ids: (rows: readonly unknown[]) =>
        rows.map((row) => String((row as { id: unknown }).id)),
    },
  ])("loads every $name page and keeps filters on the cursor request", async (scenario) => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === scenario.firstPath) {
        return jsonRes(200, {
          object: "list",
          data: scenario.first,
          has_more: true,
          next_cursor: scenario.name === "wallets"
            ? "wallet-2"
            : scenario.name === "destinations"
              ? "destination-2"
              : scenario.name === "send operations"
                ? "operation-2"
                : "audit-2",
        });
      }
      if (path === scenario.cursorPath) {
        return jsonRes(200, {
          object: "list",
          data: scenario.second,
          has_more: false,
          next_cursor: null,
        });
      }
      return jsonRes(500, { error: { code: "unexpected_path", message: path } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scenario.call();
    expect(result.live).toBe(true);
    expect(scenario.ids(result.data)).toEqual([
      scenario.ids(scenario.first)[0],
      scenario.ids(scenario.first)[1],
      scenario.ids(scenario.second)[0],
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("fails explicitly when a server repeats a cursor instead of looping forever", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(200, {
          object: "list",
          data: [{ wallet_id: "wallet-1" }],
          has_more: true,
          next_cursor: "same-cursor",
        })),
    );

    await expect(listWalletsInventory({ limit: 1 })).rejects.toMatchObject({
      code: "invalid_pagination_cursor",
    });
  });

  it("does not expose a partial inventory and preserves a later-page request id", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes("after=wallet-1")
          ? jsonRes(503, {
              error: {
                code: "service_unavailable",
                message: "page unavailable",
                request_id: "request-page-2",
              },
            })
          : jsonRes(200, {
              object: "list",
              data: [{ wallet_id: "wallet-1" }],
              has_more: true,
              next_cursor: "wallet-1",
            }),
      ),
    );

    const result = await listWalletsInventory({ limit: 1 });
    expect(result).toMatchObject({ live: false, data: [] });
    expect(result.error).toMatchObject({
      code: "service_unavailable",
      requestId: "request-page-2",
    });
  });
});

describe("getWalletInventory", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it("uses the wallet point-read so detail does not depend on list page position", async () => {
    const fetchMock = vi.fn(async () =>
      jsonRes(200, {
        wallet_id: "wallet-after-page-one",
        public_key: "pub/key+outside-first-page",
        state: "AVAILABLE",
        key_origin: "node_generated",
        recovery_verified: true,
        observed_balance_zkz: "3",
        holding_operation_id: null,
        holding_operation_status: null,
        holding_operation_expiry_unix_time_secs: null,
        holding_operation_attention_required: false,
        holding_operation_terminal_at: null,
        holding_lease_role: null,
        holding_operation_type: null,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(getWalletInventory("pub/key+outside-first-page")).resolves.toMatchObject({
      wallet_id: "wallet-after-page-one",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/v1/wallets/pub%2Fkey%2Boutside-first-page",
      expect.anything(),
    );
  });

  it("returns null only for 404 and preserves a 503 request id", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(404, {
          error: { code: "not_found", message: "gone", request_id: "request-404" },
        })),
    );
    await expect(getWalletInventory("missing")).resolves.toBeNull();

    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(503, {
          error: { code: "service_unavailable", message: "down", request_id: "request-503" },
        })),
    );
    await expect(getWalletInventory("present-but-down")).rejects.toMatchObject({
      code: "service_unavailable",
      requestId: "request-503",
    });
  });
});

describe("destination blessing device-key contract", () => {
  beforeEach(() => {
    liveAuth();
    vi.restoreAllMocks();
  });

  it("loads active device-key metadata from the admin inventory endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(200, {
          keys: [
            {
              id: "device-1",
              label: "Operator phone",
              enrolled_at: "2026-07-01T00:00:00.000Z",
            },
          ],
        }),
      ),
    );

    await expect(listDeviceKeys()).resolves.toEqual([
      {
        id: "device-1",
        label: "Operator phone",
        enrolled_at: "2026-07-01T00:00:00.000Z",
      },
    ]);
    expect(fetch).toHaveBeenCalledWith("/admin/v1/device-keys", expect.anything());
  });

  it("serializes the selected device key id into the exact blessing body", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonRes(200, { state: "BLESSED" }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await postBless(
      "destination-1",
      {
        nonce: "nonce-1",
        issued_at: "2026-07-31T00:00:00.000Z",
        expires_at: "2026-07-31T00:05:00.000Z",
        device_key_id: "device-1",
        device_signature: "signature-1",
      },
      "123456",
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init).toBeDefined();
    expect(init?.body).toBe(
      JSON.stringify({
        nonce: "nonce-1",
        issued_at: "2026-07-31T00:00:00.000Z",
        expires_at: "2026-07-31T00:05:00.000Z",
        device_key_id: "device-1",
        device_signature: "signature-1",
      }),
    );
  });

  it("posts implementer API key issue/revoke with Idempotency-Key", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/api-keys") && !path.includes("revoke")) {
        return jsonRes(200, {
          id: "cred-1",
          implementer_id: "11111111-1111-4111-8111-111111111111",
          raw_key: "ik_test_once",
          prefix: "ik_test",
          scopes: ["*"],
          key_version: 1,
          issued_at: "2026-08-03T00:00:00.000Z",
          expires_at: null,
        });
      }
      return jsonRes(200, { id: "cred-1", revoked: true });
    });
    vi.stubGlobal("fetch", fetchMock);

    await postIssueApiKey(undefined, "123456");
    await postRevokeApiKey("cred-1", "123456");
    await postHaltToggle({ engaged: false }, "123456");

    expect(fetchMock).toHaveBeenCalledTimes(3);
    for (const call of fetchMock.mock.calls) {
      const init = call[1] as RequestInit;
      const headers = init.headers as Headers;
      const idem = headers.get("Idempotency-Key");
      expect(idem).toBeTruthy();
      expect(idem!.length).toBeGreaterThanOrEqual(16);
    }
  });

  it("posts genesis enrol body with TOTP and idempotency", async () => {
    const fetchMock = vi.fn(async () =>
      jsonRes(200, {
        id: "device-1",
        label: "Phone",
        enrolled_at: "2026-07-18T00:00:00.000Z",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await postGenesisEnrol(
      {
        label: "Phone",
        new_device_key_id: "device-1",
        new_device_public_key: "pub",
        new_device_pop_signature: "sig",
        challenge_nonce: "nonce-1",
      },
      "123456",
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/v1/device-keys/enrol",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
      }),
    );
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.body).toBe(
      JSON.stringify({
        label: "Phone",
        new_device_key_id: "device-1",
        new_device_public_key: "pub",
        new_device_pop_signature: "sig",
        challenge_nonce: "nonce-1",
      }),
    );
  });

  it("posts enrollment challenge", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonRes(200, {
          nonce: "n",
          issued_at: "2026-07-18T00:00:00.000Z",
          expires_at: "2026-07-18T00:05:00.000Z",
          purpose: "zp-device-enrol-v1",
          canonical_version: 1,
          node_id: "node-1",
        }),
      ),
    );
    await expect(postEnrollmentChallenge()).resolves.toMatchObject({ nonce: "n" });
  });
});

describe("recovery action UI honesty", () => {
  it("partitions live vs reserved vs unknown without silent success", async () => {
    const { partitionRecoveryActions, recoveryActionLabel, isLiveRecoveryAction } = await import(
      "./money.js"
    );
    const { live, unavailable } = partitionRecoveryActions([
      "RETRY_OBSERVATION",
      "REBUILD_INTERNAL_MOVE",
      "FORCE_LANDED",
      "REDELIVER_EXACT_PARTIAL",
    ]);
    expect(live).toEqual(["RETRY_OBSERVATION", "REDELIVER_EXACT_PARTIAL"]);
    expect(unavailable.map((u) => u.action)).toEqual([
      "REBUILD_INTERNAL_MOVE",
      "FORCE_LANDED",
    ]);
    expect(unavailable[0]!.reason).toMatch(/Reserved/);
    expect(unavailable[1]!.reason).toMatch(/Not implemented|fail closed/i);
    expect(isLiveRecoveryAction("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED")).toBe(true);
    expect(recoveryActionLabel("CONTINUE_EXTERNAL_WAIT")).toBe(
      "Continue waiting for redemption",
    );
  });

  it("SPA live ∪ reserved catalog exactly equals the frozen OPERATOR_RECOVERY_ACTIONS", async () => {
    const {
      LIVE_RECOVERY_ACTIONS,
      RESERVED_RECOVERY_ACTIONS,
      OPERATOR_RECOVERY_ACTIONS,
    } = await import("./money.js");
    const { OPERATOR_RECOVERY_ACTIONS: CONTRACT } = await import(
      "@zucoins/generic-node-contracts/operator-halt"
    );
    const spa = new Set<string>([...LIVE_RECOVERY_ACTIONS, ...RESERVED_RECOVERY_ACTIONS]);
    const contract = new Set<string>(CONTRACT);
    expect(spa).toEqual(contract);
    expect(OPERATOR_RECOVERY_ACTIONS).toEqual(CONTRACT);
    // Live and reserved are disjoint and cover the catalog.
    for (const action of RESERVED_RECOVERY_ACTIONS) {
      expect(LIVE_RECOVERY_ACTIONS as readonly string[]).not.toContain(action);
    }
    expect(spa.size).toBe(CONTRACT.length);
  });
});

describe("generateRecoveryPackSecret (ZTR-1220)", () => {
  it("emits 26 Crockford-base32 chars the node alphabet accepts", async () => {
    const { generateRecoveryPackSecret } = await import("./money.js");
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for (let i = 0; i < 40; i++) {
      const s = generateRecoveryPackSecret();
      expect(s).toHaveLength(26);
      expect(new Set(s).size).toBeGreaterThanOrEqual(10);
      for (const c of s) expect(alphabet).toContain(c);
    }
  });

  it("redraws rather than returning a fixed tiled mock draw", async () => {
    const { generateRecoveryPackSecret } = await import("./money.js");
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    // Known-good CSPRNG-shaped secret (passes node recoverySecretWeakness).
    const good = "9F3KQ2XW7HB4TMZ0RCJ8PNVA5D";
    const real = globalThis.crypto;
    let calls = 0;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        getRandomValues: (arr: Uint8Array) => {
          calls += 1;
          // First draw: pure period-1 tiling (all '0') — structure guard must reject.
          // Later draws: emit a known-good alphabet index stream (tighter r4 floor
          // rejects simple arithmetic mock streams the r2 test used).
          if (calls === 1) {
            arr.fill(0);
            return arr;
          }
          for (let i = 0; i < arr.length; i++) {
            arr[i] = alphabet.indexOf(good[i % good.length]!);
          }
          return arr;
        },
      },
    });
    try {
      const s = generateRecoveryPackSecret();
      expect(s).toHaveLength(26);
      expect(s).not.toBe("0".repeat(26));
      expect(s).toBe(good);
      expect(calls).toBeGreaterThan(1);
    } finally {
      Object.defineProperty(globalThis, "crypto", { configurable: true, value: real });
    }
  });

  it("throws rather than last-resort-emitting a structure-failing secret", async () => {
    const { generateRecoveryPackSecret } = await import("./money.js");
    const real = globalThis.crypto;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        getRandomValues: (arr: Uint8Array) => {
          // Every draw is period-1 tiling — structure floor must never emit.
          arr.fill(0);
          return arr;
        },
      },
    });
    try {
      expect(() => generateRecoveryPackSecret()).toThrow(/structure floor|generation failed/);
    } finally {
      Object.defineProperty(globalThis, "crypto", { configurable: true, value: real });
    }
  });

  it("SPA structure floor rejects Review B r2 residual class (parity with node)", async () => {
    const { recoveryPackSecretStructureOk } = await import("./money.js");
    const residuals = [
      "C0RRECTH0RSEBATTERY0STAP1E",
      "C0RRECTH0RSEBATT3RYSTAP1E0",
      "C001R2R3E4C5T6H708R9S0E1B2",
      "P1EASE1ETME1NT0THEN0DE2024",
      "QWERTYASD1FGHZXCVBN12345AB",
      "0A1B2C3D4E5F6G7H8J9KMNPRST",
      "A1B2C3D4E5F6G7H8J9K0M1N2P3",
      "MANC0DE7P1NGETP1NPASS4N0DE",
      "M0A1S2T3E4R5K6E7Y8B9A0C1K2",
      "P0A1S2S3W4R5D6H7N8T9R0X1Y2",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(recoveryPackSecretStructureOk(secret)).toBe(false);
    }
    // Known-good still passes the SPA mirror.
    expect(recoveryPackSecretStructureOk("9F3KQ2XW7HB4TMZ0RCJ8PNVA5D")).toBe(true);
  });

  it("SPA structure floor rejects Review B r3 residual class (parity with node)", async () => {
    const { recoveryPackSecretStructureOk } = await import("./money.js");
    const residuals = [
      "1QAZ2WSX3EDC4RFV5TGB6YHN0P",
      "ZAQ1XSW2CDE3VFR4BGT5NHY6MJ",
      "THEQV1CKBR0WNFXJVMPS2024AX",
      "STR4NGERTH1NGS2024KEYABCXX",
      "HACKTHEP1ANET2024KEYM0RPHX",
      "TCERR0CESR0HYRETTABE1PATS2",
      "BP1CQ2DR3ES4FT5GV6HW7JX8KY",
      "AA1BB2CC3DD4EE5FF6GG7HH8JJ",
      "5AFMS49EKRX8DJQW1CHPV05GNT",
      "D0NTST0PBE1EV1N2024KEYABCX",
      "0NCEVP0NAT1ME1N20241ANDXXX",
      "MANP1NXG3TXKEYN0DE2024ABC2",
      "112358DN2QSG9S2VXRND2FH0HH",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(recoveryPackSecretStructureOk(secret)).toBe(false);
    }
    expect(recoveryPackSecretStructureOk("9F3KQ2XW7HB4TMZ0RCJ8PNVA5D")).toBe(true);
  });

  it("SPA structure floor rejects Review B r4 residual human-pattern class (parity with node)", async () => {
    const { recoveryPackSecretStructureOk } = await import("./money.js");
    const residuals = [
      "THECAKE1SA11EP0RTA12024XXA",
      "H0GWARTSEXPRESS2024KEYABXA",
      "GANGNAMSTY1E2024KEYABCDEXA",
      "HARRYP0TTERWAND2024KEYABXA",
      "STARWARSJED1K1GHT2024ABXAB",
      "GAME0FTHR0NES2024KEYABCXXA",
      "314159265358979323846ABCDA",
      "TAB1ECHA1RH0VSEWATER2024XA",
      "NEWY0RKC1TY2024KEYABCDEXAB",
      "SPH1NX0FB1ACKQVARTZ2024XXA",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(recoveryPackSecretStructureOk(secret)).toBe(false);
    }
    expect(recoveryPackSecretStructureOk("9F3KQ2XW7HB4TMZ0RCJ8PNVA5D")).toBe(true);
  });
});

describe("newIdempotencyKey (ZTR-1168)", () => {
  it("returns a string without throwing when randomUUID is absent", async () => {
    const { newIdempotencyKey } = await import("./money.js");
    const real = globalThis.crypto;
    let n = 0;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        getRandomValues: (arr: Uint8Array) => {
          n += 1;
          for (let i = 0; i < arr.length; i++) arr[i] = (i + n) & 0xff;
          return arr;
        },
      },
    });
    try {
      const a = newIdempotencyKey();
      const b = newIdempotencyKey();
      expect(typeof a).toBe("string");
      expect(a.length).toBeGreaterThan(10);
      expect(a).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
      expect(a).not.toBe(b);
    } finally {
      Object.defineProperty(globalThis, "crypto", { configurable: true, value: real });
    }
  });
});
