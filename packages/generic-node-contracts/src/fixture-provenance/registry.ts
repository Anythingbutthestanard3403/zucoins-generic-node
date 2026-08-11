import type { FixtureProvenanceRecord } from "./types.ts";

import { AMOUNTS_FIXTURE_RECORDS } from "./records/amounts.ts";
import { APPROVAL_FIXTURE_RECORDS } from "./records/approval.ts";
import { ARTIFACTS_FIXTURE_RECORDS } from "./records/artifacts.ts";
import { EVENT_COMMIT_FIXTURE_RECORDS } from "./records/event-commit.ts";
import { PUSH_FIXTURE_RECORDS } from "./records/push.ts";
import { SEND_REDEMPTION_FIXTURE_RECORDS } from "./records/send-redemption.ts";
import { RECEIVE_GOLDEN_FIXTURE_RECORDS } from "./records/receive-golden.ts";
import { RECOVERY_DRILL_FIXTURE_RECORDS } from "./records/recovery-drill.ts";
import { TRANSFER_CODE_FIXTURE_RECORDS } from "./records/transfer-code.ts";

/**
 * the fixture-provenance surface fixture provenance registry — the package-wide assembly of every frozen byte
 * fixture's provenance record, one record per immutable `fixtureId`. This is a pure leaf:
 * nothing here touches the filesystem, hashes bytes, or performs runtime discovery (that is
 * `verify.ts`, consumed by tests and by the later the fixture-provenance drift gate drift gate). It is NOT the concern-manifest registry
 * concern-manifest assembly (`src/registry.ts`) and NOT the drift-audit auditor
 * (`src/drift-audit/registry.ts`) — those index concern manifests, a different artifact.
 *
 * Membership is a hand-wired static import list — never a glob — so the record set is closed
 * and type-checked at build time and a new fixture family must be added here explicitly. The
 * coverage test independently rediscovers the on-disk fixture index set (`*.meta.json`,
 * `manifest.json`, `*.vectors.json`) and asserts exact two-directional equality with this
 * list: an unregistered fixture (orphan) or a record pointing at a missing file (dangling
 * reference) fails the suite.
 *
 * Entries are held in a stable, total sort by `fixtureId`. Written pre-sorted; the closure
 * test re-derives the sequence and asserts it.
 */
export const FIXTURE_PROVENANCE_REGISTRY: readonly FixtureProvenanceRecord[] = [
  ...AMOUNTS_FIXTURE_RECORDS,
  ...APPROVAL_FIXTURE_RECORDS,
  ...ARTIFACTS_FIXTURE_RECORDS,
  ...EVENT_COMMIT_FIXTURE_RECORDS,
  ...PUSH_FIXTURE_RECORDS,
  ...RECEIVE_GOLDEN_FIXTURE_RECORDS,
  ...RECOVERY_DRILL_FIXTURE_RECORDS,
  ...SEND_REDEMPTION_FIXTURE_RECORDS,
  ...TRANSFER_CODE_FIXTURE_RECORDS,
];

/** Count of registered fixture provenance records. */
export const FIXTURE_PROVENANCE_COUNT: number = FIXTURE_PROVENANCE_REGISTRY.length;

/** Every registered index path, in registry sequence. */
export const FIXTURE_INDEX_PATHS: readonly string[] = FIXTURE_PROVENANCE_REGISTRY.map(
  (record) => record.indexPath,
);

/** The record for an immutable fixture id, or `undefined` when the id is not registered. */
export const fixtureById = (fixtureId: string): FixtureProvenanceRecord | undefined =>
  FIXTURE_PROVENANCE_REGISTRY.find((record) => record.fixtureId === fixtureId);

/** The record covering an on-disk fixture index path, or `undefined` when it is not registered. */
export const fixtureByIndexPath = (indexPath: string): FixtureProvenanceRecord | undefined =>
  FIXTURE_PROVENANCE_REGISTRY.find((record) => record.indexPath === indexPath);
