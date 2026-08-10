/**
 * the concern-manifest registry contract drift-audit harness — registry discovery (work-ahead slice).
 *
 * The AUDITOR that the concern-manifest registry's exit criteria name ("verified by an Automated contract drift
 * audit"), NOT the freeze verdict and NOT the `src/registry.ts` assembly the concern
 * manifests reserve for the concern-manifest registry itself. It reads only committed repo files at test time and
 * freezes data; it performs no runtime behavior (CONTRACT_FREEZE-compatible).
 *
 * Two manifest shapes coexist on the branch today: six concerns self-register the canonical
 * `ConcernManifest` (via `defineConcernManifest`), while the rest carry heterogeneous
 * provisional shapes pending migration. This module classifies both — registered concerns get
 * full structural audit; provisional ones are enumerated, never failed — so the harness stays
 * green on today's main while still catching real drift.
 */
import { createHash } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ConcernManifest } from "../testkit/concernManifest.ts";

import * as adminAuthErrors from "../admin-auth-errors/manifest.ts";
import * as amounts from "../amounts/manifest.ts";
import * as apiSchema from "../api-schema/manifest.ts";
import * as approval from "../approval/manifest.ts";
import * as artifacts from "../artifacts/manifest.ts";
import * as authErrors from "../auth-errors/manifest.ts";
import * as compatLiterals from "../compat-literals/manifest.ts";
import * as credentialMatrix from "../credential-matrix/manifest.ts";
import * as cryptoGoldens from "../crypto-goldens/manifest.ts";
import * as custody from "../custody/manifest.ts";
import * as engineStartup from "../engine-startup/manifest.ts";
import * as eventCommit from "../event-commit/manifest.ts";
import * as eventSequencing from "../event-sequencing/manifest.ts";
import * as handoffProof from "../handoff-proof/manifest.ts";
import * as implementerEvents from "../implementer-events/manifest.ts";
import * as instructionOrigin from "../instruction-origin/manifest.ts";
import * as landingProof from "../landing-proof/manifest.ts";
import * as launchDeferral from "../launch-deferral/manifest.ts";
import * as machineManifests from "../machine-manifests/manifest.ts";
import * as noCallback from "../no-callback/manifest.ts";
import * as noCallbackAttack from "../no-callback/attack-manifest.ts";
import * as observation from "../observation/manifest.ts";
import * as operations from "../operations/manifest.ts";
import * as operatorHalt from "../operator-halt/manifest.ts";
import * as poolPolicy from "../pool-policy/manifest.ts";
import * as readiness from "../readiness/manifest.ts";
import * as receiveExpiry from "../receive-expiry/manifest.ts";
import * as reportingAuth from "../reporting-auth/manifest.ts";
import * as reportingBehavior from "../reporting-behavior/manifest.ts";
import * as reportingPersistence from "../reporting-persistence/manifest.ts";
import * as reportingTuples from "../reporting-tuples/manifest.ts";
import * as routePolicy from "../route-policy/manifest.ts";
import * as sequenceRecovery from "../sequence-recovery/manifest.ts";
import * as transferCode from "../transfer-code/manifest.ts";
import * as vault from "../vault/manifest.ts";
import * as walletState from "../wallet-state/manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
/** `packages/generic-node-contracts` — two levels above `src/drift-audit`. */
export const packageRoot = join(here, "..", "..");
/** Repo root — four levels above `src/drift-audit`. */
export const repoRoot = join(packageRoot, "..", "..");

/**
 * Every concern module that ships a `manifest.ts`, keyed by its exact on-disk directory name.
 * Statically imported (not dynamically discovered) so `tsc -b` type-checks the edge and so the
 * on-disk census below can prove this table is neither missing a concern nor carrying a stale
 * one. A new concern directory that adds a `manifest.ts` but is not wired in here fails the
 * census — that is the intended "unregistered concern" drift signal, not a harness defect.
 */
export const CONCERN_MODULES: Readonly<Record<string, object>> = {
  "admin-auth-errors": adminAuthErrors,
  amounts,
  "api-schema": apiSchema,
  approval,
  artifacts,
  "auth-errors": authErrors,
  "compat-literals": compatLiterals,
  "credential-matrix": credentialMatrix,
  "crypto-goldens": cryptoGoldens,
  custody,
  "engine-startup": engineStartup,
  "event-commit": eventCommit,
  "event-sequencing": eventSequencing,
  "handoff-proof": handoffProof,
  "implementer-events": implementerEvents,
  "instruction-origin": instructionOrigin,
  "landing-proof": landingProof,
  "launch-deferral": launchDeferral,
  "machine-manifests": machineManifests,
  // `no-callback` self-registers two independent ConcernManifests across two files (the no-callback channel freeze in
  // manifest.ts, the no-callback doc/attack census in attack-manifest.ts — kept apart per that directory's own convention
  // "earlier slices win"); merged under the one directory key concernDirsOnDisk()'s manifest.ts
  // glob already recognizes, so no on-disk-census shape change is needed.
  "no-callback": { ...noCallback, ...noCallbackAttack },
  observation,
  operations,
  "operator-halt": operatorHalt,
  "pool-policy": poolPolicy,
  readiness,
  "receive-expiry": receiveExpiry,
  "reporting-auth": reportingAuth,
  "reporting-behavior": reportingBehavior,
  "reporting-persistence": reportingPersistence,
  "reporting-tuples": reportingTuples,
  "route-policy": routePolicy,
  "sequence-recovery": sequenceRecovery,
  "transfer-code": transferCode,
  vault,
  "wallet-state": walletState,
};

const isStringArray = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

/**
 * Structural predicate for the canonical `ConcernManifest` (testkit/concernManifest.ts). A
 * provisional manifest ({ concern, ticket/frozenBy, ... }) fails this and is routed to the
 * provisional census instead of the registered audit.
 */
export const isConcernManifest = (value: unknown): value is ConcernManifest => {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.concernId === "string" &&
    isStringArray(candidate.decisionRefs) &&
    typeof candidate.frozenValues === "object" &&
    candidate.frozenValues !== null &&
    Array.isArray(candidate.goldenRefs) &&
    isStringArray(candidate.scanRules) &&
    isStringArray(candidate.sourceDocCitations)
  );
};

export interface RegisteredConcern {
  readonly dir: string;
  readonly exportName: string;
  readonly manifest: ConcernManifest;
}

/** Every concern export matching the canonical `ConcernManifest` shape, across all modules. */
export const listRegisteredConcerns = (): RegisteredConcern[] => {
  const registered: RegisteredConcern[] = [];
  for (const [dir, moduleNamespace] of Object.entries(CONCERN_MODULES)) {
    for (const [exportName, value] of Object.entries(moduleNamespace)) {
      if (isConcernManifest(value)) {
        registered.push({ dir, exportName, manifest: value });
      }
    }
  }
  return registered.sort((a, b) => a.dir.localeCompare(b.dir));
};

export interface ProvisionalConcern {
  readonly dir: string;
  /** Best-effort concern label pulled from the provisional export, for enumeration only. */
  readonly label: string;
}

const provisionalLabel = (moduleNamespace: object): string => {
  for (const value of Object.values(moduleNamespace)) {
    if (typeof value === "object" && value !== null) {
      const concern = (value as Record<string, unknown>).concern;
      if (typeof concern === "string") {
        return concern;
      }
    }
  }
  return "unlabelled";
};

/** Concern directories whose manifest has NOT migrated to the canonical shape yet. */
export const listProvisionalConcerns = (): ProvisionalConcern[] => {
  const registeredDirs = new Set(listRegisteredConcerns().map((concern) => concern.dir));
  const provisional: ProvisionalConcern[] = [];
  for (const [dir, moduleNamespace] of Object.entries(CONCERN_MODULES)) {
    if (!registeredDirs.has(dir)) {
      provisional.push({ dir, label: provisionalLabel(moduleNamespace) });
    }
  }
  return provisional.sort((a, b) => a.dir.localeCompare(b.dir));
};

/**
 * Test-only escape hatch for `concernDirsOnDisk()` / `unregisteredConcernDirs()`: lets
 * a test point the REAL scan at a genuinely independent fixture tree instead of this package's
 * own `src/`. Defaults to `packageRoot/src` — every non-test call site is unaffected.
 *
 * Exists so a positive-detection test can drive the actual production functions against a real
 * unregistered concern dir without either (a) mutating `packages/generic-node-contracts/src/`
 * itself, which risks the cross-file FS race with dependency-boundary.test.ts's own
 * `src/**` glob, or (b) re-deriving the expected on-disk set from the registry being validated
 * (the tautology this option exists to avoid — see census-filter.test.ts).
 */
export interface ConcernScanOptions {
  readonly srcDir?: string;
}

/**
 * Concern directory names discovered on disk via the per-concern manifest glob (the census
 * denominator). Excludes any directory under the reserved `zz-*` prefix.
 *
 * `zz-*` is reserved for on-disk test fixtures. Fixtures for this module's own tests now live
 * under `os.tmpdir()` via the `srcDir` option above (census-filter.test.ts), never
 * under this package's `src/`, so they can never trigger the cross-file FS race with
 * dependency-boundary.test.ts's own `src/**` glob. Any future on-disk-fixture test in this
 * directory that does plant under `src/` MUST still use the `zz-*` prefix to inherit this
 * exclusion.
 */
export const concernDirsOnDisk = (options: ConcernScanOptions = {}): string[] =>
  globSync(join(options.srcDir ?? join(packageRoot, "src"), "*", "manifest.ts"))
    .map((file) => basename(dirname(file)))
    .filter((dir) => !dir.startsWith("zz-"))
    .sort();

/**
 * Concern directories a currently-queued PR is known to add a `src/<dir>/manifest.ts` for,
 * but that have not landed yet (work-ahead slice). Nothing here is statically imported (the
 * directory doesn't exist on this branch yet) — each name is enumerated only, never audited.
 *
 * A dir named here is PENDING: its landing is expected and must not flip the census
 * hard-fail red. Promotion path: once the landing PR adds its own static import +
 * `CONCERN_MODULES` entry, remove its name from this list so it flows through the normal
 * registered/provisional census like every other concern.
 */
// : every previously-pending concern dir has landed with a static import +
// CONCERN_MODULES entry (and freeze-test backstop). The list is intentionally empty — a new
// queued landing re-adds its name here until it is wired.
export const PENDING_CONCERN_DIRS: readonly string[] = [];

/** On-disk concern dirs neither statically wired nor a known-pending queued landing — genuine drift. */
export const unregisteredConcernDirs = (options: ConcernScanOptions = {}): string[] => {
  const known = new Set([...Object.keys(CONCERN_MODULES), ...PENDING_CONCERN_DIRS]);
  return concernDirsOnDisk(options).filter((dir) => !known.has(dir));
};

/**
 * Concern dirs that have physically landed on disk (a `manifest.ts` exists) under a name still
 * listed in `PENDING_CONCERN_DIRS`, yet are NOT wired into `CONCERN_MODULES`. This is the
 * landed-but-unwired blind spot: `unregisteredConcernDirs()` whitelists every pending name, so a
 * queued landing that arrives on disk without its static import + `CONCERN_MODULES` entry would
 * otherwise escape the census entirely — unaudited while the census stays green. Surfacing these
 * dirs makes that state non-silent: each is a manifest that has landed but receives zero
 * structural audit until it is wired (or its name is otherwise discharged from the pending list).
 */
export const landedButUnwiredConcernDirs = (options: ConcernScanOptions = {}): string[] => {
  const pending = new Set(PENDING_CONCERN_DIRS);
  const wired = new Set(Object.keys(CONCERN_MODULES));
  return concernDirsOnDisk(options).filter((dir) => pending.has(dir) && !wired.has(dir));
};

/**
 * `zz-*` directories present on disk but excluded from the concern census.
 * Surfaced for observability: a non-empty list means test fixtures are currently planted,
 * confirming the exclusion filter is active. This makes the silent `zz-*` exemption in
 * `concernDirsOnDisk()` non-silent — an operator can verify the filter is firing.
 */
export const excludedFixtureDirs = (): string[] =>
  globSync(join(packageRoot, "src", "*", "manifest.ts"))
    .map((file) => basename(dirname(file)))
    .filter((dir) => dir.startsWith("zz-"))
    .sort();

/** Statically-wired `CONCERN_MODULES` entries with no on-disk `manifest.ts` — a stale registry entry. */
export const staleConcernEntries = (): string[] => {
  const onDisk = new Set(concernDirsOnDisk());
  return Object.keys(CONCERN_MODULES).filter((dir) => !onDisk.has(dir));
};

/** SHA-256 (hex) of a repo file addressed relative to the package root. */
export const sha256OfPackageFile = (relativePath: string): string =>
  createHash("sha256").update(readFileSync(join(packageRoot, relativePath))).digest("hex");
