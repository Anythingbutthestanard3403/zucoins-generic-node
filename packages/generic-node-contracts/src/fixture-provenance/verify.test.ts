import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { FIXTURE_PROVENANCE_REGISTRY, fixtureById } from "./registry.ts";
import type { FixtureProvenanceRecord } from "./types.ts";
import { diffFixtureExpectation, validateFixtureRecord } from "./validate.ts";
import { diffRegistryCoverage, packageRoot, verifyRecordDigests, verifyRegistryDigests } from "./verify.ts";

/**
 * the fixture-provenance surface integrity and mutation tests. The green pass recomputes every pinned digest from
 * the committed frozen bytes; the red passes feed the actual breaking input — a mutated
 * signed-preimage golden, a mutated money-amount vector, a tampered record digest, a missing
 * file, an unregistered fixture — into an isolated temp copy of the family, never into the
 * real tree (no committed test writes a golden).
 */

let tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots) {
    rmSync(root, { recursive: true, force: true });
  }
  tempRoots = [];
});

const requireRecord = (fixtureId: string): FixtureProvenanceRecord => {
  const record = fixtureById(fixtureId);
  if (!record) {
    throw new Error(`test setup: ${fixtureId} not registered`);
  }
  return record;
};

const copyFamilyToTempRoot = (record: FixtureProvenanceRecord): string => {
  const root = mkdtempSync(join(tmpdir(), "fixture-provenance-"));
  tempRoots.push(root);
  for (const file of record.files) {
    const target = join(root, file.path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(packageRoot, file.path), target);
  }
  return root;
};

const flipDigestChar = (sha256: string): string =>
  sha256.startsWith("0") ? `1${sha256.slice(1)}` : `0${sha256.slice(1)}`;

describe("the fixture-provenance surface fixture integrity — green against the committed tree", () => {
  it("recomputes every pinned digest from the frozen files with zero mismatches", () => {
    expect(verifyRegistryDigests()).toEqual([]);
  });

  it("verifies each registered fixture individually", () => {
    for (const record of FIXTURE_PROVENANCE_REGISTRY) {
      expect(verifyRecordDigests(record), record.fixtureId).toEqual([]);
    }
  });
});

describe("the fixture-provenance surface mutation detection (known drift classes)", () => {
  it("reddens when a signed-preimage golden byte mutates", () => {
    const record = requireRecord("transfer-code/receive-code.v1");
    const root = copyFamilyToTempRoot(record);
    expect(verifyRecordDigests(record, root)).toEqual([]);

    const preimage = join(root, "goldens/transfer-code/receive-code.v1.json.txt");
    const bytes = readFileSync(preimage);
    bytes[10] = bytes[10] === 0x7a ? 0x79 : 0x7a;
    writeFileSync(preimage, bytes);

    const mismatches = verifyRecordDigests(record, root);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.path).toBe("goldens/transfer-code/receive-code.v1.json.txt");
    expect(mismatches[0]?.expected).toBe(record.files.find((f) => f.path.endsWith("json.txt"))?.sha256);
    expect(mismatches[0]?.actual).not.toBe(mismatches[0]?.expected);
  });

  it("reddens when a money-amount vector value mutates", () => {
    const record = requireRecord("amounts/arithmetic.vectors");
    const root = copyFamilyToTempRoot(record);

    const vectors = join(root, "src/amounts/__vectors__/arithmetic.vectors.json");
    const original = readFileSync(vectors, "utf8");
    expect(original).toContain('"expected": "7.5"');
    writeFileSync(vectors, original.replace('"expected": "7.5"', '"expected": "7.6"'));

    const mismatches = verifyRecordDigests(record, root);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.path).toBe("src/amounts/__vectors__/arithmetic.vectors.json");
  });

  it("reddens when a registry-referenced digest is tampered", () => {
    const record = requireRecord("transfer-code/send-code.v1");
    const first = record.files[0];
    if (!first) {
      throw new Error("test setup: record has no files");
    }
    const tampered: FixtureProvenanceRecord = {
      ...record,
      files: [{ ...first, sha256: flipDigestChar(first.sha256) }, ...record.files.slice(1)],
    };
    const mismatches = verifyRecordDigests(tampered);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.path).toBe(first.path);
    expect(mismatches[0]?.expected).toBe(tampered.files[0]?.sha256);
  });

  it("reports a missing fixture file instead of passing or throwing", () => {
    const record = requireRecord("receive-golden/gen");
    const root = copyFamilyToTempRoot(record);
    rmSync(join(root, "src/receive-golden/gen/target.step-1.json"));

    const mismatches = verifyRecordDigests(record, root);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.path).toBe("src/receive-golden/gen/target.step-1.json");
    expect(mismatches[0]?.actual).toBe("missing");
  });

  it("detects a mutated byte-class flag against an independent expectation", () => {
    const record = requireRecord("transfer-code/receive-code.v1");
    const expectation = {
      byteClass: record.byteClass,
      originKind: record.provenance.originKind,
      captureDate: record.provenance.captureDate,
    };
    expect(diffFixtureExpectation(record, expectation)).toEqual([]);

    const mutated: FixtureProvenanceRecord = { ...record, byteClass: "suite-tuple" };
    const drift = diffFixtureExpectation(mutated, expectation);
    expect(drift).toHaveLength(1);
    expect(drift[0]).toContain("byteClass");
  });

  it("detects a mutated capture date against an independent expectation", () => {
    const record = requireRecord("receive-golden/negative-vectors");
    const expectation = {
      byteClass: record.byteClass,
      originKind: record.provenance.originKind,
      captureDate: record.provenance.captureDate,
    };
    expect(diffFixtureExpectation(record, expectation)).toEqual([]);

    const mutated: FixtureProvenanceRecord = {
      ...record,
      provenance: { ...record.provenance, captureDate: "1999-01-01" },
    };
    const drift = diffFixtureExpectation(mutated, expectation);
    expect(drift).toHaveLength(1);
    expect(drift[0]).toContain("captureDate");
  });
});

describe("the fixture-provenance surface unknown and unregistered fixture rejection", () => {
  it("reports an unregistered on-disk fixture as an orphan", () => {
    const record = requireRecord("transfer-code/receive-code.v1");
    const root = copyFamilyToTempRoot(record);
    const orphan = join(root, "goldens", "unregistered");
    mkdirSync(orphan, { recursive: true });
    writeFileSync(join(orphan, "surprise.meta.json"), "{}");

    const diff = diffRegistryCoverage(root);
    expect(diff.orphanFixtures).toEqual(["goldens/unregistered/surprise.meta.json"]);
  });

  it("reports every registered fixture absent from a foreign root as dangling", () => {
    const root = mkdtempSync(join(tmpdir(), "fixture-provenance-"));
    tempRoots.push(root);

    const diff = diffRegistryCoverage(root);
    expect(diff.orphanFixtures).toEqual([]);
    expect(diff.danglingRecords).toEqual(
      FIXTURE_PROVENANCE_REGISTRY.map((record) => record.indexPath).sort(),
    );
  });
});

describe("the fixture-provenance surface malformed provenance record rejection", () => {
  it("rejects a record that is not an object", () => {
    expect(validateFixtureRecord(null)).toContain("record must be an object");
    expect(validateFixtureRecord("transfer-code/receive-code.v1")).toContain("record must be an object");
  });

  it("rejects a record with every required field missing", () => {
    const violations = validateFixtureRecord({});
    expect(violations.length).toBeGreaterThanOrEqual(5);
    expect(violations.some((v) => v.startsWith("fixtureId"))).toBe(true);
    expect(violations.some((v) => v.startsWith("byteClass"))).toBe(true);
    expect(violations.some((v) => v.startsWith("indexPath"))).toBe(true);
    expect(violations.some((v) => v.startsWith("files"))).toBe(true);
    expect(violations.some((v) => v.startsWith("provenance"))).toBe(true);
  });

  it("rejects blank provenance fields — no silently-blank field", () => {
    const record = requireRecord("amounts/boundary.vectors");
    const violations = validateFixtureRecord({
      ...record,
      provenance: { ...record.provenance, captureMethod: "", walletVersion: "" },
    });
    expect(violations.some((v) => v.startsWith("provenance.captureMethod"))).toBe(true);
    expect(violations.some((v) => v.startsWith("provenance.walletVersion"))).toBe(true);
  });

  it("rejects a malformed capture date", () => {
    const record = requireRecord("amounts/boundary.vectors");
    for (const captureDate of ["2026-13-01", "2026-02-30", "19 July 2026", "2026/07/19"]) {
      const violations = validateFixtureRecord({
        ...record,
        provenance: { ...record.provenance, captureDate },
      });
      expect(violations.some((v) => v.startsWith("provenance.captureDate")), captureDate).toBe(true);
    }
  });

  it("rejects an out-of-vocabulary byte-class flag", () => {
    const record = requireRecord("receive-golden/gen");
    const violations = validateFixtureRecord({ ...record, byteClass: "signed_preimage" });
    expect(violations.some((v) => v.startsWith("byteClass"))).toBe(true);
  });

  it("rejects a malformed digest and a dangling indexPath", () => {
    const record = requireRecord("event-commit/commit.vectors");
    const badDigest = validateFixtureRecord({
      ...record,
      files: [{ path: record.indexPath, sha256: "deadbeef" }],
    });
    expect(badDigest.some((v) => v.includes("sha256"))).toBe(true);

    const dangling = validateFixtureRecord({ ...record, indexPath: "src/event-commit/__vectors__/other.vectors.json" });
    expect(dangling.some((v) => v.includes("indexPath"))).toBe(true);
  });

  it("rejects a hand-typed digest that does not match the frozen file", () => {
    const record = requireRecord("artifacts/zp-receive-expected-v1");
    const preimage = record.files.find((file) => file.path.endsWith("preimage.txt"));
    if (!preimage) {
      throw new Error("test setup: no preimage file");
    }
    const handTyped: FixtureProvenanceRecord = {
      ...record,
      files: record.files.map((file) =>
        file.path === preimage.path ? { ...file, sha256: flipDigestChar(file.sha256) } : file,
      ),
    };
    expect(validateFixtureRecord(handTyped)).toEqual([]);
    const mismatches = verifyRecordDigests(handTyped);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.path).toBe(preimage.path);
  });
});
