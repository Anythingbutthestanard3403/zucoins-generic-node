import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { RECEIVE_CREATE_SYNC_201_SUPERSESSION } from "./receive-create-201-supersession.ts";

const here = dirname(fileURLToPath(import.meta.url));

describe("RECEIVE_CREATE_SYNC_201_SUPERSESSION (ZTR-1170)", () => {
  it("records superseded status and served 202 create contract", () => {
    expect(RECEIVE_CREATE_SYNC_201_SUPERSESSION.status).toBe("superseded");
    expect(RECEIVE_CREATE_SYNC_201_SUPERSESSION.served_create_status).toBe(202);
    expect(RECEIVE_CREATE_SYNC_201_SUPERSESSION.served_create_code_status).toBe(
      "NOT_CREATED",
    );
    expect(RECEIVE_CREATE_SYNC_201_SUPERSESSION.clause).toMatch(/§4\.1/);
  });

  it("createReceive first-completion path stores 202 (not 201)", () => {
    const storePath = join(
      here,
      "..",
      "..",
      "..",
      "node-core",
      "src",
      "operation-route-store.ts",
    );
    const src = readFileSync(storePath, "utf8");
    expect(src).toMatch(/completeOperation\([^)]*202/);
    expect(src).toMatch(/status:\s*202\s+as const/);
  });
});
