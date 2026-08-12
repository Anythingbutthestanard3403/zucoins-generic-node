import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  APPROVAL_METHOD_AUTO_POLICY_ENUM_INVARIANTS,
  APPROVAL_METHOD_AUTO_POLICY_ENUM_SCHEMA_FILE,
} from "../src/schema/approval-method-auto-policy-enum.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  resolve(here, "../src/schema", APPROVAL_METHOD_AUTO_POLICY_ENUM_SCHEMA_FILE),
  "utf8",
);

describe("approval-method-auto-policy-enum schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = APPROVAL_METHOD_AUTO_POLICY_ENUM_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });
});
