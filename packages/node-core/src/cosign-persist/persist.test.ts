import { describe, expect, it } from "vitest";
import {
  persistCosignCompletedBody,
  persistCosignPreimage,
} from "./persist.js";
import type {
  CosignCompletedBody,
  CosignPreimage,
  CosignPreimageStore,
} from "./types.js";

function createInMemoryStore(): CosignPreimageStore & {
  preimages: CosignPreimage[];
  completedBodies: CosignCompletedBody[];
} {
  const preimages: CosignPreimage[] = [];
  const completedBodies: CosignCompletedBody[] = [];

  return {
    preimages,
    completedBodies,
    async insertPreimage(row: CosignPreimage) {
      preimages.push(row);
    },
    async findPreimageById(preimageId: string) {
      return preimages.find((p) => p.preimage_id === preimageId) ?? null;
    },
    async findPreimageByOperation(operationId: string) {
      return preimages.find((p) => p.operation_id === operationId) ?? null;
    },
    async insertCompletedBody(row: CosignCompletedBody) {
      completedBodies.push(row);
    },
    async findCompletedBodyByPreimageId(preimageId: string) {
      return completedBodies.find((c) => c.preimage_id === preimageId) ?? null;
    },
    async findCompletedBodyByOperation(operationId: string) {
      return completedBodies.find((c) => c.operation_id === operationId) ?? null;
    },
  };
}

const EXACT_PREIMAGE_TEXT = '{"inner":{"amount":"1000","currency":"ZKZ"},"step_1_signature":"abc123sig"}';
const EXACT_COMPLETED_TEXT = '{"inner":{"amount":"1000","currency":"ZKZ"},"step_1_signature":"abc123sig","step_2_signature":"def456sig"}';

describe("persistCosignPreimage", () => {
  it("persists preimage byte-exact and returns its SHA-256", async () => {
    const store = createInMemoryStore();
    const result = await persistCosignPreimage(store, {
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      preimage_text: EXACT_PREIMAGE_TEXT,
      inner_preimage_text: '{"amount":"1000","currency":"ZKZ"}',
      inner_sha256: "innerhash",
      step_1_signature: "abc123sig",
    });

    expect(result.persisted).toBe(true);
    if (!result.persisted) return;
    expect(result.preimage_sha256).toHaveLength(64);

    const stored = store.preimages[0]!;
    expect(stored.preimage_text).toBe(EXACT_PREIMAGE_TEXT);
    expect(stored.preimage_octets).toBe(Buffer.byteLength(EXACT_PREIMAGE_TEXT, "utf8"));
    expect(stored.operation_id).toBe("op-1");
    expect(stored.tenant_id).toBe("t-1");
  });

  it("rejects a second preimage for the same operation (insert-only)", async () => {
    const store = createInMemoryStore();
    const req = {
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      preimage_text: EXACT_PREIMAGE_TEXT,
      inner_preimage_text: "{}",
      inner_sha256: "h",
      step_1_signature: "s",
    };

    await persistCosignPreimage(store, req);
    const second = await persistCosignPreimage(store, { ...req, preimage_id: "pi-2" });

    expect(second.persisted).toBe(false);
    if (!second.persisted) {
      expect(second.reason).toBe("PREIMAGE_ALREADY_EXISTS");
    }
  });

  it("preserves unicode byte-exact content", async () => {
    const store = createInMemoryStore();
    const unicodeText = '{"memo":"ZKZ note \u2603\u2764"}';
    const result = await persistCosignPreimage(store, {
      preimage_id: "pi-u",
      operation_id: "op-u",
      tenant_id: "t-1",
      preimage_text: unicodeText,
      inner_preimage_text: "{}",
      inner_sha256: "h",
      step_1_signature: "s",
    });

    expect(result.persisted).toBe(true);
    const stored = store.preimages[0]!;
    expect(stored.preimage_text).toBe(unicodeText);
    expect(stored.preimage_octets).toBe(Buffer.byteLength(unicodeText, "utf8"));
  });
});

describe("persistCosignCompletedBody", () => {
  it("persists completed body linked to preimage with both signatures", async () => {
    const store = createInMemoryStore();
    await persistCosignPreimage(store, {
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      preimage_text: EXACT_PREIMAGE_TEXT,
      inner_preimage_text: "{}",
      inner_sha256: "h",
      step_1_signature: "abc123sig",
    });

    const result = await persistCosignCompletedBody(store, {
      completed_id: "cb-1",
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      completed_transaction_text: EXACT_COMPLETED_TEXT,
      step_2_signature: "def456sig",
    });

    expect(result.persisted).toBe(true);
    if (!result.persisted) return;
    expect(result.completed_transaction_sha256).toHaveLength(64);

    const stored = store.completedBodies[0]!;
    expect(stored.completed_transaction_text).toBe(EXACT_COMPLETED_TEXT);
    expect(stored.preimage_id).toBe("pi-1");
    expect(stored.step_2_signature).toBe("def456sig");
  });

  it("rejects completed body when preimage does not exist", async () => {
    const store = createInMemoryStore();
    const result = await persistCosignCompletedBody(store, {
      completed_id: "cb-1",
      preimage_id: "pi-missing",
      operation_id: "op-1",
      tenant_id: "t-1",
      completed_transaction_text: EXACT_COMPLETED_TEXT,
      step_2_signature: "sig",
    });

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("PREIMAGE_NOT_FOUND");
    }
  });

  it("rejects a second completed body for the same preimage (insert-only)", async () => {
    const store = createInMemoryStore();
    await persistCosignPreimage(store, {
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      preimage_text: EXACT_PREIMAGE_TEXT,
      inner_preimage_text: "{}",
      inner_sha256: "h",
      step_1_signature: "s",
    });

    const req = {
      completed_id: "cb-1",
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      completed_transaction_text: EXACT_COMPLETED_TEXT,
      step_2_signature: "sig",
    };

    await persistCosignCompletedBody(store, req);
    const second = await persistCosignCompletedBody(store, { ...req, completed_id: "cb-2" });

    expect(second.persisted).toBe(false);
    if (!second.persisted) {
      expect(second.reason).toBe("COMPLETED_BODY_ALREADY_EXISTS");
    }
  });

  it("completed body SHA-256 matches the exact text bytes", async () => {
    const store = createInMemoryStore();
    await persistCosignPreimage(store, {
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      preimage_text: EXACT_PREIMAGE_TEXT,
      inner_preimage_text: "{}",
      inner_sha256: "h",
      step_1_signature: "s",
    });

    const result = await persistCosignCompletedBody(store, {
      completed_id: "cb-1",
      preimage_id: "pi-1",
      operation_id: "op-1",
      tenant_id: "t-1",
      completed_transaction_text: EXACT_COMPLETED_TEXT,
      step_2_signature: "sig2",
    });

    expect(result.persisted).toBe(true);
    if (!result.persisted) return;

    const { createHash } = await import("node:crypto");
    const expected = createHash("sha256").update(EXACT_COMPLETED_TEXT, "utf8").digest("hex");
    expect(result.completed_transaction_sha256).toBe(expected);
  });
});
