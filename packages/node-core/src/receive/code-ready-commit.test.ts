// CREATED→READY commit, 201 body, secrecy (steps 8–9).
import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  formReceiveCodeAndArtifact,
  type FormedReceiveCode,
  type NodeIdentitySigner,
  type ReceiveCodeFormationStore,
} from "./code-formation.js";
import {
  RECEIVE_READY_STATEMENTS,
  assertWithheldTransferCode,
  buildReceiveReady201Body,
  buildReceiveReadyEventData,
  commitReceiveReady,
  completeReadyFromDurableCode,
  isNonEmptySubscriptionHandle,
  type SqlExecutor,
} from "./code-ready-commit.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const WALLET_ID = "55555555-5555-4555-8555-555555555555";
const ARTIFACT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SIGNING_KEY_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const FORMATION_NOW_MS = (1_784_336_400 - 300) * 1000;
const TTL_BOUNDS = { defaultSecs: 300, minSecs: 60, maxSecs: 3600 } as const;
// Frozen expiry is 1784336400 = 2026-07-18T01:00:00.000Z; readyAt must be before that.
const READY_AT = "2026-07-18T00:55:00.000Z";
const CREATED_AT = "2026-07-18T00:50:00.000Z";
/** Create-time handle re-embedded on READY (ZTR-1142 — never null). */
const SUBSCRIPTION_HANDLE = "sh_test_ready_handle_plaintext";

function paddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function nodeSigner(): NodeIdentitySigner {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 0x00),
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return {
    signingKeyId: SIGNING_KEY_ID,
    sign(preimageBytes: Uint8Array): string {
      return paddedBase64Url(sign(null, Buffer.from(preimageBytes), privateKey));
    },
  };
}

class MemoryFormationStore implements ReceiveCodeFormationStore {
  preimage: {
    artifactId: string;
    operationId: string;
    preimageText: string;
    preimageSha256: string;
    signingKeyId: string | null;
    signature: string | null;
  } | null = null;

  async persistArtifactPreimage(input: {
    readonly artifactId: string;
    readonly operationId: string;
    readonly preimageText: string;
    readonly preimageSha256: string;
  }) {
    this.preimage = {
      artifactId: input.artifactId,
      operationId: input.operationId,
      preimageText: input.preimageText,
      preimageSha256: input.preimageSha256,
      signingKeyId: null,
      signature: null,
    };
    return { artifactId: input.artifactId, alreadyPresent: false };
  }

  async persistArtifactSignature(input: {
    readonly artifactId: string;
    readonly signingKeyId: string;
    readonly signature: string;
    readonly expectedPreimageSha256: string;
  }) {
    if (!this.preimage) throw new Error("no preimage");
    this.preimage = {
      ...this.preimage,
      signingKeyId: input.signingKeyId,
      signature: input.signature,
    };
  }

  async loadArtifactPreimage(operationId: string) {
    if (!this.preimage || this.preimage.operationId !== operationId) return null;
    return { ...this.preimage };
  }

  async hasSignerAuditForArtifact() {
    return this.preimage?.signature !== null && this.preimage !== null;
  }

  async hasCompleteCodeRecord() {
    return false;
  }
}

async function formFixture(): Promise<FormedReceiveCode> {
  const store = new MemoryFormationStore();
  const result = await formReceiveCodeAndArtifact({
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    operationId: OPERATION_ID,
    receiverWalletId: WALLET_ID,
    receiverPubkey: PUBKEY,
    amountZkz: "2.25",
    anchor: "ord_7YQ3",
    afterLanding: { kind: "HOLD", destination_id: null },
    t0: {
      observationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      s0: "",
      p0: "",
      b0: "0",
    },
    requestedTtlSecs: 300,
    ttlBounds: TTL_BOUNDS,
    nowUnixMs: FORMATION_NOW_MS,
    artifactId: ARTIFACT_ID,
    signer: nodeSigner(),
    store,
  });
  if (!result.ok) throw new Error(result.detail);
  return result.formed;
}

class FakeSql implements SqlExecutor {
  readonly calls: { text: string; params: readonly unknown[] }[] = [];
  status: "CREATED" | "READY" = "CREATED";
  rowVersion = 1;
  responseBody: string | null = null;
  codeInserted = false;
  destinationEligible = true;
  leaseHeld = true;

  async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
    this.calls.push({ text, params });
    const normalized = text.replace(/\s+/g, " ").trim();

    if (normalized === RECEIVE_READY_STATEMENTS.RECHECK_CREATED_AND_LEASE) {
      if (!this.leaseHeld || this.status !== "CREATED") return { rows: [] };
      return {
        rows: [
          {
            operation_id: OPERATION_ID,
            row_version: this.rowVersion,
            amount_zkz: "2.25",
            created_at: CREATED_AT,
            updated_at: CREATED_AT,
          } as R,
        ],
      };
    }
    if (normalized === RECEIVE_READY_STATEMENTS.RECHECK_DESTINATION_ELIGIBLE) {
      return {
        rows: this.destinationEligible
          ? ([{ destination_id: params[0] }] as R[])
          : [],
      };
    }
    if (normalized === RECEIVE_READY_STATEMENTS.INSERT_RECEIVE_CODE) {
      if (this.codeInserted) {
        const err = new Error("unique") as Error & { code: string };
        err.code = "23505";
        throw err;
      }
      this.codeInserted = true;
      return { rows: [] };
    }
    if (normalized === RECEIVE_READY_STATEMENTS.CAS_CREATED_TO_READY) {
      if (this.status !== "CREATED" || params[1] !== this.rowVersion) {
        return { rows: [] };
      }
      this.status = "READY";
      this.rowVersion += 1;
      return {
        rows: [
          {
            operation_id: OPERATION_ID,
            row_version: this.rowVersion,
            updated_at: READY_AT,
          } as R,
        ],
      };
    }
    if (normalized === RECEIVE_READY_STATEMENTS.COMPLETE_IDEMPOTENCY_201) {
      if (this.responseBody !== null) return { rows: [] };
      this.responseBody = String(params[1]);
      return { rows: [{ operation_id: OPERATION_ID } as R] };
    }
    if (normalized === RECEIVE_READY_STATEMENTS.SELECT_RECEIVE_CODE) {
      return {
        rows: this.codeInserted ? ([{ operation_id: OPERATION_ID }] as R[]) : [],
      };
    }
    throw new Error(`unexpected SQL: ${normalized.slice(0, 80)}`);
  }
}

describe("buildReceiveReady201Body", () => {
  it("sets transfer_code:null and code_status:AWAITING_ARM literally", async () => {
    const formed = await formFixture();
    const body = buildReceiveReady201Body({
      formed,
      rowVersion: 2,
      createdAt: CREATED_AT,
      updatedAt: READY_AT,
      subscriptionHandle: SUBSCRIPTION_HANDLE,
    });
    const parsed = JSON.parse(body) as {
      transfer_code: unknown;
      code_status: string;
      subscription_handle: string;
      expected_artifact: { key_id: string; preimage_text: string; preimage_sha256: string; signature: string };
      t0: { observation_id: string; projection: { s: string; p: string; b_zkz: string } };
      discriminator: string;
      operation: { state: string };
    };
    expect(parsed.transfer_code).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(parsed, "transfer_code")).toBe(true);
    expect(parsed.code_status).toBe("AWAITING_ARM");
    expect(parsed.operation.state).toBe("READY");
    expect(parsed.discriminator).toBe(OPERATION_ID);
    expect(parsed.subscription_handle).toBe(SUBSCRIPTION_HANDLE);
    expect(parsed.expected_artifact.key_id).toBe(SIGNING_KEY_ID);
    expect(parsed.expected_artifact.preimage_text).toBe(formed.artifact.envelope.preimage_text);
    expect(parsed.t0.projection).toEqual({ s: "", p: "", b_zkz: "0" });
    // Secrecy: plaintext absent.
    expect(body.includes(formed.transferCode.transferCodeText)).toBe(false);
    assertWithheldTransferCode(body, formed.transferCode.transferCodeText);
  });

  it("rejects null/empty subscriptionHandle (frozen READY schema — ZTR-1142)", async () => {
    const formed = await formFixture();
    expect(isNonEmptySubscriptionHandle(null)).toBe(false);
    expect(isNonEmptySubscriptionHandle("")).toBe(false);
    expect(isNonEmptySubscriptionHandle(SUBSCRIPTION_HANDLE)).toBe(true);
    expect(() =>
      buildReceiveReady201Body({
        formed,
        rowVersion: 2,
        createdAt: CREATED_AT,
        updatedAt: READY_AT,
        subscriptionHandle: "",
      }),
    ).toThrow(/subscriptionHandle must be a non-empty string/);
    // Runtime cast: production callers must not pass null; builder throws if they do.
    expect(() =>
      buildReceiveReady201Body({
        formed,
        rowVersion: 2,
        createdAt: CREATED_AT,
        updatedAt: READY_AT,
        subscriptionHandle: null as unknown as string,
      }),
    ).toThrow(/subscriptionHandle must be a non-empty string/);
  });

  it("event data also withholds the code", async () => {
    const formed = await formFixture();
    const data = buildReceiveReadyEventData(formed, WALLET_ID);
    const parsed = JSON.parse(data) as { transfer_code: unknown; code_status: string };
    expect(parsed.transfer_code).toBeNull();
    expect(parsed.code_status).toBe("AWAITING_ARM");
    assertWithheldTransferCode(data, formed.transferCode.transferCodeText);
  });
});

describe("commitReceiveReady", () => {
  it("persists withheld code, CAS to READY, appends event, completes 201", async () => {
    const formed = await formFixture();
    const sql = new FakeSql();
    const events: { dataText: string }[] = [];
    const result = await commitReceiveReady({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      readyAt: READY_AT,
      destinationId: null,
      createdAt: CREATED_AT,
      subscriptionHandle: SUBSCRIPTION_HANDLE,
      sql,
      events: {
        async appendReceiveReady(input) {
          events.push({ dataText: input.dataText });
        },
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.responseStatus).toBe(201);
    expect(result.codeStatus).toBe("AWAITING_ARM");
    expect(sql.codeInserted).toBe(true);
    expect(sql.status).toBe("READY");
    expect(sql.responseBody).toBe(result.responseBody);
    expect(events).toHaveLength(1);
    const body = JSON.parse(result.responseBody) as {
      transfer_code: unknown;
      code_status: string;
      subscription_handle: string;
    };
    expect(body.transfer_code).toBeNull();
    expect(body.code_status).toBe("AWAITING_ARM");
    expect(body.subscription_handle).toBe(SUBSCRIPTION_HANDLE);
    assertWithheldTransferCode(result.responseBody, formed.transferCode.transferCodeText);
    assertWithheldTransferCode(events[0]!.dataText, formed.transferCode.transferCodeText);

    // INSERT_RECEIVE_CODE params include the plaintext (durable withheld form) and AWAITING_ARM.
    const insert = sql.calls.find((c) =>
      c.text.replace(/\s+/g, " ").trim().startsWith("INSERT INTO receive_codes"),
    );
    expect(insert).toBeDefined();
    expect(insert!.params).toContain(formed.transferCode.transferCodeText);
    expect(insert!.params).toContain(formed.transferCode.transferCodeSha256);
    expect(insert!.text).toMatch(/AWAITING_ARM/);
  });

  it("rejects when subscription_handle is missing/empty before any durable write (ZTR-1142)", async () => {
    const formed = await formFixture();
    const sql = new FakeSql();
    const result = await commitReceiveReady({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      readyAt: READY_AT,
      destinationId: null,
      // Simulate race / fail-open prior-load: empty handle must not READY.
      subscriptionHandle: "",
      sql,
      events: { async appendReceiveReady() {} },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("subscription_handle_missing");
    expect(sql.codeInserted).toBe(false);
    expect(sql.status).toBe("CREATED");
    expect(sql.responseBody).toBeNull();
  });

  it("rejects when lease is lost", async () => {
    const formed = await formFixture();
    const sql = new FakeSql();
    sql.leaseHeld = false;
    const result = await commitReceiveReady({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      readyAt: READY_AT,
      destinationId: null,
      subscriptionHandle: SUBSCRIPTION_HANDLE,
      sql,
      events: { async appendReceiveReady() {} },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("lease_lost");
  });

  it("rejects when destination eligibility fails", async () => {
    const formed = await formFixture();
    // INTERNAL_MOVE formed would carry destination; recheck uses destinationId input.
    const sql = new FakeSql();
    sql.destinationEligible = false;
    const result = await commitReceiveReady({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      readyAt: READY_AT,
      destinationId: "66666666-6666-4666-8666-666666666666",
      subscriptionHandle: SUBSCRIPTION_HANDLE,
      sql,
      events: { async appendReceiveReady() {} },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("destination_not_eligible");
  });

  it("rejects when frozen expiry is already past readyAt", async () => {
    const formed = await formFixture();
    const sql = new FakeSql();
    const result = await commitReceiveReady({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      // Far future readyAt past the frozen expiry 1784336400.
      readyAt: new Date((1_784_336_400 + 10) * 1000).toISOString(),
      destinationId: null,
      subscriptionHandle: SUBSCRIPTION_HANDLE,
      sql,
      events: { async appendReceiveReady() {} },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("expiry_passed");
  });
});

describe("completeReadyFromDurableCode", () => {
  it("guardedly completes CREATED→READY without re-inserting the code", async () => {
    const formed = await formFixture();
    const sql = new FakeSql();
    sql.codeInserted = true; // durable code already present
    const result = await completeReadyFromDurableCode({
      formed,
      receiverWalletId: WALLET_ID,
      leaseEpoch: 1n,
      readyAt: READY_AT,
      destinationId: null,
      createdAt: CREATED_AT,
      subscriptionHandle: SUBSCRIPTION_HANDLE,
      sql,
      events: { async appendReceiveReady() {} },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.responseStatus).toBe(201);
    // No second INSERT attempted (would unique-violate).
    const inserts = sql.calls.filter((c) =>
      c.text.replace(/\s+/g, " ").trim().startsWith("INSERT INTO receive_codes"),
    );
    expect(inserts).toHaveLength(0);
    expect(sql.status).toBe("READY");
  });
});

describe("assertWithheldTransferCode", () => {
  it("throws when the plaintext leaks onto a surface", async () => {
    const formed = await formFixture();
    expect(() =>
      assertWithheldTransferCode(
        `leaked:${formed.transferCode.transferCodeText}`,
        formed.transferCode.transferCodeText,
      ),
    ).toThrow(/secrecy breach/);
  });

  it("passes when only the digest is present", async () => {
    const formed = await formFixture();
    expect(() =>
      assertWithheldTransferCode(
        JSON.stringify({ transfer_code_sha256: formed.transferCode.transferCodeSha256 }),
        formed.transferCode.transferCodeText,
      ),
    ).not.toThrow();
  });
});

describe("INSERT_RECEIVE_CODE statement catalogue", () => {
  it("pins AWAITING_ARM and the withheld text column", () => {
    expect(RECEIVE_READY_STATEMENTS.INSERT_RECEIVE_CODE).toMatch(/AWAITING_ARM/);
    expect(RECEIVE_READY_STATEMENTS.INSERT_RECEIVE_CODE).toMatch(/transfer_code_text/);
    expect(RECEIVE_READY_STATEMENTS.CAS_CREATED_TO_READY).toMatch(/status = 'READY'/);
    expect(RECEIVE_READY_STATEMENTS.CAS_CREATED_TO_READY).toMatch(/status = 'CREATED'/);
  });
});
