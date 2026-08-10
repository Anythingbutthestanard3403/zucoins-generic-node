/**
 * the concern-manifest registry package registry — the closed, package-wide assembly of every concern's self-registered
 * `ConcernManifest` (the "the concern-manifest registry leave-behind" shape from `testkit/concernManifest.ts`). This is
 * the assembly the concern manifests reserve for the concern-manifest registry itself; it is NOT the drift-audit auditor
 * under `src/drift-audit/`, which verifies disposition at test time by reading committed bytes.
 * Nothing here touches the filesystem, hashes bytes, or performs runtime discovery, so this module
 * stays a pure zero-dependency leaf and is safe to consume on a production path.
 *
 * Membership is a hand-wired static import list — never a glob — so the set is closed and
 * type-checked at build time and a new concern must be added here explicitly. The closure test
 * (`registry.test.ts`) independently rediscovers the on-disk manifest set and asserts it equals
 * this list, so an omission or a stale entry fails the suite instead of silently narrowing the
 * census.
 *
 * Entries are held in a stable, total sort by `(concernDir, exportName)`. `concernId` is
 * deliberately not the sort key: several concerns share one — the transfer-code/reporting concern spans the three reporting
 * dirs, the auth-errors/route-policy concern spans auth-errors/credential-matrix/route-policy, the events concern spans the two event dirs —
 * and `no-callback` self-registers the no-callback concern twice, across `manifest.ts` and `attack-manifest.ts`, so
 * only the directory-plus-export pair is unique per entry.
 */
import type { ConcernManifest } from "./testkit/concernManifest.ts";

import { AMOUNTS_CONCERN_MANIFEST } from "./amounts/manifest.ts";
import { ADMIN_AUTH_ERRORS_CONCERN_MANIFEST } from "./admin-auth-errors/manifest.ts";
import { API_SCHEMA_CONCERN_MANIFEST } from "./api-schema/manifest.ts";
import { APPROVAL_CONCERN_MANIFEST } from "./approval/manifest.ts";
import { ARTIFACTS_CONCERN_MANIFEST } from "./artifacts/manifest.ts";
import { AUTH_ERRORS_CONCERN_MANIFEST } from "./auth-errors/manifest.ts";
import { COMPAT_LITERALS_CONCERN_MANIFEST } from "./compat-literals/manifest.ts";
import { CREDENTIAL_MATRIX_CONCERN_MANIFEST } from "./credential-matrix/manifest.ts";
import { CRYPTO_GOLDENS_CONCERN_MANIFEST } from "./crypto-goldens/manifest.ts";
import { CUSTODY_CONCERN_MANIFEST } from "./custody/manifest.ts";
import { ENGINE_STARTUP_CONCERN_MANIFEST } from "./engine-startup/manifest.ts";
import { EVENT_COMMIT_CONCERN_MANIFEST } from "./event-commit/manifest.ts";
import { EVENT_SEQUENCING_CONCERN_MANIFEST } from "./event-sequencing/manifest.ts";
import { HANDOFF_PROOF_CONCERN_MANIFEST } from "./handoff-proof/manifest.ts";
import { IMPLEMENTER_EVENTS_CONCERN_MANIFEST } from "./implementer-events/manifest.ts";
import { INSTRUCTION_ORIGIN_CONCERN_MANIFEST } from "./instruction-origin/manifest.ts";
import { LANDING_PROOF_CONCERN_MANIFEST } from "./landing-proof/manifest.ts";
import { LAUNCH_DEFERRAL_CONCERN_MANIFEST } from "./launch-deferral/manifest.ts";
import { MACHINE_MANIFESTS_CONCERN_MANIFEST } from "./machine-manifests/manifest.ts";
import { ATTACK_SURFACE_CONCERN_MANIFEST } from "./no-callback/attack-manifest.ts";
import { NO_CALLBACK_CONCERN_MANIFEST } from "./no-callback/manifest.ts";
import { OBSERVATION_CONCERN_MANIFEST } from "./observation/manifest.ts";
import { OPERATIONS_CONCERN_MANIFEST } from "./operations/manifest.ts";
import { OPERATOR_HALT_CONCERN_MANIFEST } from "./operator-halt/manifest.ts";
import { POOL_POLICY_CONCERN_MANIFEST } from "./pool-policy/manifest.ts";
import { READINESS_CONCERN_MANIFEST } from "./readiness/manifest.ts";
import { REPORTING_AUTH_CONCERN_MANIFEST } from "./reporting-auth/manifest.ts";
import { REPORTING_BEHAVIOR_CONCERN_MANIFEST } from "./reporting-behavior/manifest.ts";
import { REPORTING_TUPLES_CONCERN_MANIFEST } from "./reporting-tuples/manifest.ts";
import { ROUTE_POLICY_CONCERN_MANIFEST } from "./route-policy/manifest.ts";
import { TRANSFER_CODE_CONCERN_MANIFEST } from "./transfer-code/manifest.ts";
import { VAULT_CONCERN_MANIFEST } from "./vault/manifest.ts";
import { WALLET_STATE_CONCERN_MANIFEST } from "./wallet-state/manifest.ts";

/** One entry in the package registry: a self-registered manifest and where it lives. */
export interface RegisteredConcern {
  /** The exclusive on-disk concern directory under `src/` that owns this manifest. */
  readonly concernDir: string;
  /** The exported binding the concern uses to self-register the manifest. Unique within a dir. */
  readonly exportName: string;
  /** The concern's self-registered canonical manifest. */
  readonly manifest: ConcernManifest;
}

/**
 * Every self-registered concern manifest in the package, in the stable `(concernDir, exportName)`
 * sort. Written pre-sorted; the closure test re-derives the on-disk set and asserts both this
 * membership and this sequence.
 */
export const CONCERN_REGISTRY: readonly RegisteredConcern[] = [
  { concernDir: "admin-auth-errors", exportName: "ADMIN_AUTH_ERRORS_CONCERN_MANIFEST", manifest: ADMIN_AUTH_ERRORS_CONCERN_MANIFEST },
  { concernDir: "amounts", exportName: "AMOUNTS_CONCERN_MANIFEST", manifest: AMOUNTS_CONCERN_MANIFEST },
  { concernDir: "api-schema", exportName: "API_SCHEMA_CONCERN_MANIFEST", manifest: API_SCHEMA_CONCERN_MANIFEST },
  { concernDir: "approval", exportName: "APPROVAL_CONCERN_MANIFEST", manifest: APPROVAL_CONCERN_MANIFEST },
  { concernDir: "artifacts", exportName: "ARTIFACTS_CONCERN_MANIFEST", manifest: ARTIFACTS_CONCERN_MANIFEST },
  { concernDir: "auth-errors", exportName: "AUTH_ERRORS_CONCERN_MANIFEST", manifest: AUTH_ERRORS_CONCERN_MANIFEST },
  { concernDir: "compat-literals", exportName: "COMPAT_LITERALS_CONCERN_MANIFEST", manifest: COMPAT_LITERALS_CONCERN_MANIFEST },
  { concernDir: "credential-matrix", exportName: "CREDENTIAL_MATRIX_CONCERN_MANIFEST", manifest: CREDENTIAL_MATRIX_CONCERN_MANIFEST },
  { concernDir: "crypto-goldens", exportName: "CRYPTO_GOLDENS_CONCERN_MANIFEST", manifest: CRYPTO_GOLDENS_CONCERN_MANIFEST },
  { concernDir: "custody", exportName: "CUSTODY_CONCERN_MANIFEST", manifest: CUSTODY_CONCERN_MANIFEST },
  { concernDir: "engine-startup", exportName: "ENGINE_STARTUP_CONCERN_MANIFEST", manifest: ENGINE_STARTUP_CONCERN_MANIFEST },
  { concernDir: "event-commit", exportName: "EVENT_COMMIT_CONCERN_MANIFEST", manifest: EVENT_COMMIT_CONCERN_MANIFEST },
  { concernDir: "event-sequencing", exportName: "EVENT_SEQUENCING_CONCERN_MANIFEST", manifest: EVENT_SEQUENCING_CONCERN_MANIFEST },
  { concernDir: "handoff-proof", exportName: "HANDOFF_PROOF_CONCERN_MANIFEST", manifest: HANDOFF_PROOF_CONCERN_MANIFEST },
  { concernDir: "implementer-events", exportName: "IMPLEMENTER_EVENTS_CONCERN_MANIFEST", manifest: IMPLEMENTER_EVENTS_CONCERN_MANIFEST },
  { concernDir: "instruction-origin", exportName: "INSTRUCTION_ORIGIN_CONCERN_MANIFEST", manifest: INSTRUCTION_ORIGIN_CONCERN_MANIFEST },
  { concernDir: "landing-proof", exportName: "LANDING_PROOF_CONCERN_MANIFEST", manifest: LANDING_PROOF_CONCERN_MANIFEST },
  { concernDir: "launch-deferral", exportName: "LAUNCH_DEFERRAL_CONCERN_MANIFEST", manifest: LAUNCH_DEFERRAL_CONCERN_MANIFEST },
  { concernDir: "machine-manifests", exportName: "MACHINE_MANIFESTS_CONCERN_MANIFEST", manifest: MACHINE_MANIFESTS_CONCERN_MANIFEST },
  { concernDir: "no-callback", exportName: "ATTACK_SURFACE_CONCERN_MANIFEST", manifest: ATTACK_SURFACE_CONCERN_MANIFEST },
  { concernDir: "no-callback", exportName: "NO_CALLBACK_CONCERN_MANIFEST", manifest: NO_CALLBACK_CONCERN_MANIFEST },
  { concernDir: "observation", exportName: "OBSERVATION_CONCERN_MANIFEST", manifest: OBSERVATION_CONCERN_MANIFEST },
  { concernDir: "operations", exportName: "OPERATIONS_CONCERN_MANIFEST", manifest: OPERATIONS_CONCERN_MANIFEST },
  { concernDir: "operator-halt", exportName: "OPERATOR_HALT_CONCERN_MANIFEST", manifest: OPERATOR_HALT_CONCERN_MANIFEST },
  { concernDir: "pool-policy", exportName: "POOL_POLICY_CONCERN_MANIFEST", manifest: POOL_POLICY_CONCERN_MANIFEST },
  { concernDir: "readiness", exportName: "READINESS_CONCERN_MANIFEST", manifest: READINESS_CONCERN_MANIFEST },
  { concernDir: "reporting-auth", exportName: "REPORTING_AUTH_CONCERN_MANIFEST", manifest: REPORTING_AUTH_CONCERN_MANIFEST },
  { concernDir: "reporting-behavior", exportName: "REPORTING_BEHAVIOR_CONCERN_MANIFEST", manifest: REPORTING_BEHAVIOR_CONCERN_MANIFEST },
  { concernDir: "reporting-tuples", exportName: "REPORTING_TUPLES_CONCERN_MANIFEST", manifest: REPORTING_TUPLES_CONCERN_MANIFEST },
  { concernDir: "route-policy", exportName: "ROUTE_POLICY_CONCERN_MANIFEST", manifest: ROUTE_POLICY_CONCERN_MANIFEST },
  { concernDir: "transfer-code", exportName: "TRANSFER_CODE_CONCERN_MANIFEST", manifest: TRANSFER_CODE_CONCERN_MANIFEST },
  { concernDir: "vault", exportName: "VAULT_CONCERN_MANIFEST", manifest: VAULT_CONCERN_MANIFEST },
  { concernDir: "wallet-state", exportName: "WALLET_STATE_CONCERN_MANIFEST", manifest: WALLET_STATE_CONCERN_MANIFEST },
];

/** Every self-registered manifest, in registry sequence. */
export const CONCERN_MANIFESTS: readonly ConcernManifest[] = CONCERN_REGISTRY.map(
  (concern) => concern.manifest,
);

/** Count of self-registered concern manifests in the package. */
export const CONCERN_MANIFEST_COUNT: number = CONCERN_REGISTRY.length;

/**
 * The registry entry for a concern directory, or `undefined`. Returns the first match when a
 * directory self-registers more than one manifest (`no-callback`); iterate `CONCERN_REGISTRY`
 * for every entry.
 */
export const concernByDir = (concernDir: string): RegisteredConcern | undefined =>
  CONCERN_REGISTRY.find((concern) => concern.concernDir === concernDir);
