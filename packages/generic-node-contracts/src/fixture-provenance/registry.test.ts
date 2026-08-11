import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  FIXTURE_INDEX_PATHS,
  FIXTURE_PROVENANCE_COUNT,
  FIXTURE_PROVENANCE_REGISTRY,
  fixtureById,
  fixtureByIndexPath,
} from "./registry.ts";
import { diffFixtureExpectation, validateFixtureRecord, type FixtureExpectation } from "./validate.ts";
import {
  diffRegistryCoverage,
  discoverFixtureIndexPaths,
  packageRoot,
} from "./verify.ts";
import type { FixtureByteClass, FixtureOriginKind } from "./types.ts";

/**
 * the fixture-provenance surface closure tests for the fixture provenance registry. The registry is cross-checked
 * against two independent sources: the on-disk fixture index set (rediscovered by glob, never
 * consulted from the registry) and the expectation table below, pinned independently in this
 * test file — the package's digest-pinning convention (golden regeneration and quarantine)
 * applied to provenance metadata, so mutating a record's byte-class flag or
 * capture date fails here.
 */

const EXPECTATIONS: Readonly<Record<string, FixtureExpectation>> = {
  "amounts/arithmetic.vectors": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "amounts/boundary.vectors": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "amounts/emission.vectors": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "approval/zp-send-external-approval-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-20" },
  "artifacts/node-identity.pub": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-07-20" },
  "artifacts/zp-move-internal-expected-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-20" },
  "artifacts/zp-receive-expected-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-20" },
  "artifacts/zp-send-external-expected-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-20" },
  "event-commit/commit.vectors": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "push/delivered-envelope.data.v1": { byteClass: "unsigned-evidence", originKind: "canonical-constructor", captureDate: "2026-08-11" },
  "receive-golden/attack-vectors": { byteClass: "signed-preimage", originKind: "canonical-constructor", captureDate: "2026-07-21" },
  "receive-golden/gen": { byteClass: "signed-preimage", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "receive-golden/negative-vectors": { byteClass: "signed-preimage", originKind: "canonical-constructor", captureDate: "2026-07-19" },
  "recovery/manifest": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-21" },
  "recovery/zp-backup-wallet-export-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-21" },
  "recovery/zp-recovery-verification-v1": { byteClass: "suite-tuple", originKind: "canonical-constructor", captureDate: "2026-07-21" },
  "transfer-code/receive-code.v1": { byteClass: "signed-preimage", originKind: "wallet-capture", captureDate: "2026-07-19" },
  "transfer-code/send-code.v1": { byteClass: "signed-preimage", originKind: "wallet-capture", captureDate: "2026-07-19" },
};

const BYTE_CLASS_VALUES: readonly FixtureByteClass[] = ["signed-preimage", "suite-tuple", "unsigned-evidence"];
const ORIGIN_KIND_VALUES: readonly FixtureOriginKind[] = ["wallet-capture", "gateway-capture", "canonical-constructor"];

describe("the fixture-provenance surface fixture provenance registry closure (fixture-provenance/registry.ts)", () => {
  it("discovers a non-empty on-disk fixture index set (guards against a broken glob)", () => {
    expect(discoverFixtureIndexPaths().length).toBeGreaterThan(0);
  });

  it("covers exactly the on-disk fixture index set — no orphan fixture, no dangling reference", () => {
    // The machine-checkable form of the review-indicator diff:
    // find packages/generic-node-contracts -iname '*.meta.json' -o -iname 'manifest.json' -o -iname '*.vectors.json'
    const diff = diffRegistryCoverage();
    expect(diff.orphanFixtures).toEqual([]);
    expect(diff.danglingRecords).toEqual([]);
    expect([...FIXTURE_INDEX_PATHS].sort()).toEqual(discoverFixtureIndexPaths());
  });

  it("has a unique fixtureId and a unique indexPath for every record", () => {
    const ids = FIXTURE_PROVENANCE_REGISTRY.map((record) => record.fixtureId);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(FIXTURE_INDEX_PATHS).size).toBe(FIXTURE_INDEX_PATHS.length);
  });

  it("holds a stable, total sort by fixtureId", () => {
    const ids = FIXTURE_PROVENANCE_REGISTRY.map((record) => record.fixtureId);
    expect(ids).toEqual([...ids].sort((a, b) => a.localeCompare(b)));
  });

  it("passes structural validation for every record — no silently-blank field", () => {
    for (const record of FIXTURE_PROVENANCE_REGISTRY) {
      expect(validateFixtureRecord(record), record.fixtureId).toEqual([]);
    }
  });

  it("registers every record under the closed tri-state byte-class and origin vocabularies", () => {
    for (const record of FIXTURE_PROVENANCE_REGISTRY) {
      expect(BYTE_CLASS_VALUES).toContain(record.byteClass);
      expect(ORIGIN_KIND_VALUES).toContain(record.provenance.originKind);
    }
  });

  it("matches the independently-pinned expectation table (byte class, origin, capture date)", () => {
    expect(Object.keys(EXPECTATIONS).sort()).toEqual(
      FIXTURE_PROVENANCE_REGISTRY.map((record) => record.fixtureId).sort(),
    );
    for (const record of FIXTURE_PROVENANCE_REGISTRY) {
      const expectation = EXPECTATIONS[record.fixtureId];
      expect(expectation, record.fixtureId).toBeDefined();
      expect(diffFixtureExpectation(record, expectation as FixtureExpectation)).toEqual([]);
    }
  });

  it("covers every file in each fixture family directory — no silently-undigested sibling", () => {
    const families = new Map<string, string[]>();
    for (const record of FIXTURE_PROVENANCE_REGISTRY) {
      const dir = dirname(record.indexPath);
      families.set(dir, [...(families.get(dir) ?? []), ...record.files.map((file) => file.path)]);
    }
    for (const [dir, covered] of families) {
      const onDisk = readdirSync(join(packageRoot, dir), { withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => `${dir}/${entry.name}`)
        .sort();
      expect([...new Set(covered)].sort(), dir).toEqual(onDisk);
    }
  });
});

const readJson = (path: string): unknown => JSON.parse(readFileSync(join(packageRoot, path), "utf8"));

const dig = (value: unknown, keys: readonly string[]): unknown =>
  keys.reduce<unknown>(
    (acc, key) => (typeof acc === "object" && acc !== null ? (acc as Record<string, unknown>)[key] : undefined),
    value,
  );

const pinnedDigest = (fixtureId: string, filePath: string): string => {
  const record = fixtureById(fixtureId);
  expect(record, fixtureId).toBeDefined();
  const file = record?.files.find((entry) => entry.path === filePath);
  expect(file, `${fixtureId} ${filePath}`).toBeDefined();
  return file?.sha256 ?? "";
};

describe("the fixture-provenance surface sidecar consistency — registry digests match the pre-existing pinned digests", () => {
  const checks: readonly { fixtureId: string; sidecar: string; pairs: readonly [readonly string[], string][] }[] = [
    {
      fixtureId: "transfer-code/receive-code.v1",
      sidecar: "goldens/transfer-code/receive-code.v1.meta.json",
      pairs: [
        [["digests", "json_sha256"], "goldens/transfer-code/receive-code.v1.json.txt"],
        [["digests", "b64url_sha256"], "goldens/transfer-code/receive-code.v1.b64url.txt"],
      ],
    },
    {
      fixtureId: "transfer-code/send-code.v1",
      sidecar: "goldens/transfer-code/send-code.v1.meta.json",
      pairs: [
        [["digests", "json_sha256"], "goldens/transfer-code/send-code.v1.json.txt"],
        [["digests", "b64url_sha256"], "goldens/transfer-code/send-code.v1.b64url.txt"],
      ],
    },
    {
      fixtureId: "approval/zp-send-external-approval-v1",
      sidecar: "goldens/approval/zp-send-external-approval-v1.meta.json",
      pairs: [[["artifact_digest_sha256"], "goldens/approval/zp-send-external-approval-v1.preimage.txt"]],
    },
    {
      fixtureId: "artifacts/zp-move-internal-expected-v1",
      sidecar: "goldens/artifacts/zp-move-internal-expected-v1.meta.json",
      pairs: [[["artifact_digest_sha256"], "goldens/artifacts/zp-move-internal-expected-v1.preimage.txt"]],
    },
    {
      fixtureId: "artifacts/zp-receive-expected-v1",
      sidecar: "goldens/artifacts/zp-receive-expected-v1.meta.json",
      pairs: [[["artifact_digest_sha256"], "goldens/artifacts/zp-receive-expected-v1.preimage.txt"]],
    },
    {
      fixtureId: "artifacts/zp-send-external-expected-v1",
      sidecar: "goldens/artifacts/zp-send-external-expected-v1.meta.json",
      pairs: [[["artifact_digest_sha256"], "goldens/artifacts/zp-send-external-expected-v1.preimage.txt"]],
    },
    {
      fixtureId: "artifacts/node-identity.pub",
      sidecar: "goldens/artifacts/node-identity.pub.meta.json",
      pairs: [[["sha256"], "goldens/artifacts/node-identity.pub.b64"]],
    },
    {
      fixtureId: "receive-golden/gen",
      sidecar: "src/receive-golden/gen/manifest.json",
      pairs: [
        [["predecessor", "step_1_sha256"], "src/receive-golden/gen/predecessor.step-1.json"],
        [["predecessor", "step_2_sha256"], "src/receive-golden/gen/predecessor.step-2.json"],
        [["predecessor", "settled_sha256"], "src/receive-golden/gen/predecessor.settled.json"],
        [["target", "step_1_sha256"], "src/receive-golden/gen/target.step-1.json"],
        [["target", "step_2_sha256"], "src/receive-golden/gen/target.step-2.json"],
        [["target", "settled_sha256"], "src/receive-golden/gen/target.settled.json"],
        [["target", "receiver_terminal_head", "preimage_sha256"], "src/receive-golden/gen/receiver-head-fingerprint.txt"],
      ],
    },
    {
      fixtureId: "receive-golden/negative-vectors",
      sidecar: "src/receive-golden/negative-vectors/manifest.json",
      pairs: [
        [["vectors", "0", "inner_sha256"], "src/receive-golden/negative-vectors/funded-sender-genesis-predecessor.inner.json"],
        [["vectors", "1", "inner_sha256"], "src/receive-golden/negative-vectors/wrong-sender-balance.inner.json"],
        [["vectors", "2", "inner_sha256"], "src/receive-golden/negative-vectors/wrong-receiver-balance.inner.json"],
      ],
    },
  ];

  it("every pinned registry digest equals the digest the family's own sidecar/manifest recorded independently", () => {
    for (const { fixtureId, sidecar, pairs } of checks) {
      const sidecarJson = readJson(sidecar);
      for (const [keys, filePath] of pairs) {
        expect(dig(sidecarJson, keys), `${fixtureId} ${filePath}`).toBe(pinnedDigest(fixtureId, filePath));
      }
    }
  });
});

describe("the fixture-provenance surface registry derived accessors", () => {
  it("FIXTURE_PROVENANCE_COUNT equals the registry length", () => {
    expect(FIXTURE_PROVENANCE_COUNT).toBe(FIXTURE_PROVENANCE_REGISTRY.length);
  });

  it("fixtureById returns the record, or undefined for an unknown id", () => {
    expect(fixtureById("transfer-code/receive-code.v1")?.indexPath).toBe(
      "goldens/transfer-code/receive-code.v1.meta.json",
    );
    expect(fixtureById("does-not-exist/fixture")).toBeUndefined();
  });

  it("fixtureByIndexPath returns the covering record, or undefined for an unregistered path", () => {
    expect(fixtureByIndexPath("src/amounts/__vectors__/boundary.vectors.json")?.fixtureId).toBe(
      "amounts/boundary.vectors",
    );
    expect(fixtureByIndexPath("src/nowhere/manifest.json")).toBeUndefined();
  });
});
