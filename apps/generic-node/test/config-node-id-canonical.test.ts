import { describe, expect, it } from "vitest";

import {
  loadNodeConfig,
  NodeConfigurationError,
  withCanonicalNodeId,
} from "../src/config/index.js";

// NODE_ID canonicalization for Railway's raw-hex secret(32).
// Railway template generates NODE_ID as a 32-char hex string (no dashes);
// the schema requires canonical UUID format (8-4-4-4-12).

function validEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "development",
    DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
    SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
    PUBLIC_BASE_URL: "https://node.internal.example/",
    NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    ...overrides,
  };
}

describe("withCanonicalNodeId", () => {
  it("passes through an already-canonical UUID unchanged", () => {
    const source = { NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
  });

  it("converts a raw 32-char lowercase hex string to canonical UUID", () => {
    const source = { NODE_ID: "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
  });

  it("converts a raw 32-char uppercase hex string to lowercase canonical UUID", () => {
    const source = { NODE_ID: "AAAAAAAABBBB4CCC8DDDEEEEEEEEEEEE" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
  });

  it("converts a mixed-case raw hex string to lowercase canonical UUID", () => {
    const source = { NODE_ID: "aAbBcCdDeEfF00112233445566778899" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("aabbccdd-eeff-0011-2233-445566778899");
  });

  it("leaves source unchanged when NODE_ID is undefined", () => {
    const source = { OTHER: "value" };
    const result = withCanonicalNodeId(source);
    expect(result).toBe(source);
  });

  it("leaves invalid values untouched so the schema rejects them", () => {
    const source = { NODE_ID: "not-a-uuid" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("not-a-uuid");
  });

  it("leaves a 31-char hex string untouched (wrong length)", () => {
    const source = { NODE_ID: "aaaaaaaabbbb4ccc8dddeeeeeeeeeee" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("aaaaaaaabbbb4ccc8dddeeeeeeeeeee");
  });

  it("inserts dashes at the correct 8-4-4-4-12 positions", () => {
    // 1234567890abcdef1234567890abcdef
    // 12345678-90ab-cdef-1234-567890abcdef
    const source = { NODE_ID: "1234567890abcdef1234567890abcdef" };
    const result = withCanonicalNodeId(source);
    expect(result.NODE_ID).toBe("12345678-90ab-cdef-1234-567890abcdef");
  });
});

describe("NODE_ID canonicalization through loadNodeConfig", () => {
  it("accepts a raw 32-char hex NODE_ID and produces a canonical UUID in config", () => {
    const config = loadNodeConfig(
      validEnv({ NODE_ID: "aabbccddeeff00112233445566778899" }),
    );
    expect(config.NODE_ID).toBe("aabbccdd-eeff-0011-2233-445566778899");
  });

  it("accepts an already-canonical UUID NODE_ID", () => {
    const config = loadNodeConfig(
      validEnv({ NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }),
    );
    expect(config.NODE_ID).toBe("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
  });

  it("rejects an invalid NODE_ID that is neither canonical nor raw hex", () => {
    let error: unknown;
    try {
      loadNodeConfig(validEnv({ NODE_ID: "not-valid" }));
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(NodeConfigurationError);
    expect((error as NodeConfigurationError).issues.join("\n")).toContain("NODE_ID");
  });

  it("produces a NODE_ID that satisfies the canonical UUID regex", () => {
    const config = loadNodeConfig(
      validEnv({ NODE_ID: "1234567890abcdef1234567890abcdef" }),
    );
    expect(config.NODE_ID).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});
