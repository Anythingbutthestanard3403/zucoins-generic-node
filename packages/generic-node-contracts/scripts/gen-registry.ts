import { CUSTODY_CONTRACT } from "../src/custody/manifest.ts";
import { VAULT_CONTRACT } from "../src/vault/manifest.ts";
import { OBSERVATION_CONTRACT } from "../src/observation/manifest.ts";
import { ENGINE_STARTUP_CONTRACT } from "../src/engine-startup/manifest.ts";
import { HANDOFF_PROOF_CONTRACT } from "../src/handoff-proof/manifest.ts";
import { LANDING_PROOF_CONTRACT } from "../src/landing-proof/manifest.ts";
import { amountsContract } from "../src/amounts/manifest.ts";
import { amountEnforcementContract } from "../src/amounts/enforcement-manifest.ts";
import { poolPolicyContract } from "../src/pool-policy/manifest.ts";
import { poolTransactionsContract } from "../src/pool-policy/transactions-manifest.ts";
import { POOL_PRESSURE_SCENARIOS } from "../src/pool-policy/scenarios.ts";
import { receiveExpiryContract } from "../src/receive-expiry/manifest.ts";
import { expiryOrderingContract } from "../src/receive-expiry/ordering-manifest.ts";
import { receiveExpiryFaultInjectionContract } from "../src/receive-expiry/phases.ts";
import { walletStateContract } from "../src/wallet-state/manifest.ts";
import { walletStateAlignmentContract } from "../src/wallet-state/alignment-manifest.ts";
import { walletStateMatrixContract } from "../src/wallet-state/matrix.ts";

import * as operations from "../src/operations/operations.contract.ts";
import * as lifecycle from "../src/operations/lifecycle.contract.ts";
import * as states from "../src/operations/states.contract.ts";
import * as events from "../src/operations/events.contract.ts";
import * as routes from "../src/operations/routes.contract.ts";
import * as capabilities from "../src/operations/capabilities.contract.ts";
import * as halt from "../src/operator-halt/halt.contract.ts";
import * as gating from "../src/operator-halt/gating.contract.ts";
import * as races from "../src/operator-halt/races.contract.ts";
import { READINESS_CONTRACT } from "../src/readiness/manifest.ts";
import * as compatLiterals from "../src/compat-literals/compat-literals.contract.ts";
import * as forbiddenAliases from "../src/compat-literals/forbidden-aliases.contract.ts";
import * as literalKinds from "../src/compat-literals/kinds.ts";
import * as replacementPolicy from "../src/compat-literals/replacement-policy.ts";
import * as literalInventory from "../src/compat-literals/inventory.contract.ts";
import * as constructionSites from "../src/compat-literals/construction-sites.contract.ts";
import * as artifacts from "../src/artifacts/expected-artifacts.contract.ts";
import { INSTRUCTION_ORIGIN_CONCERN_MANIFEST } from "../src/instruction-origin/manifest.ts";
import * as purposes from "../src/machine-manifests/purposes.contract.ts";
import * as fields from "../src/machine-manifests/fields.contract.ts";
import * as prefixes from "../src/machine-manifests/prefixes.contract.ts";
import * as versions from "../src/machine-manifests/versions.contract.ts";
import * as genesis from "../src/machine-manifests/genesis.contract.ts";
import * as suiteTuples from "../src/machine-manifests/suite-tuples.contract.ts";
import * as gatewayEnvelopes from "../src/machine-manifests/gateway-envelopes.contract.ts";
import * as roleProjections from "../src/machine-manifests/role-projections.contract.ts";
import * as api from "../src/machine-manifests/api.contract.ts";
import * as schemaVocabs from "../src/machine-manifests/schema-vocabs.contract.ts";
import * as negativeVectors from "../src/machine-manifests/negative-vectors.contract.ts";

import { CONTRACT_DRIFT_MANIFEST } from "../src/drift-audit/contract-manifest.ts";

import { toSortedPlainObject } from "../src/testkit/serialize.ts";

/**
 * the concern-manifest registry.1 closed-set gen registry — the single source of truth `scripts/emit-json.ts` (the
 * writer) and `gen/json-sync.test.ts` (the byte-compare gate) both read, so they can never
 * silently drift from one another. Pure module: no filesystem writes at import scope, safe to
 * import from a test.
 *
 * `recipe` records which of the three deterministic `JSON.stringify(v, null, 2)`-based
 * renderings (see `renderSnapshot`) produced each committed `gen/<file>.json`. Every entry is
 * byte-rendered and byte-verified — there is no value-only escape hatch, so re-running the
 * emitter always reproduces the committed bytes exactly.
 */
export type GenRecipe = "sorted-nl" | "raw-nl" | "raw-no-nl";

export interface GenSnapshot {
  readonly file: string;
  readonly value: unknown;
  readonly recipe: GenRecipe;
}

/** Renders a snapshot's value exactly as its recipe committed it — never a fourth encoding. */
export const renderSnapshot = (snapshot: GenSnapshot): string => {
  const body =
    snapshot.recipe === "sorted-nl"
      ? toSortedPlainObject(snapshot.value as object)
      : snapshot.value;
  const json = JSON.stringify(body, null, 2);
  return snapshot.recipe === "raw-no-nl" ? json : `${json}\n`;
};

/**
 * Unsorted entry table, grouped by concern for readability. `GEN_SNAPSHOTS` (below) is the
 * stable file-name-sorted export both the emitter and the test actually consume.
 */
const entries: readonly GenSnapshot[] = [
  { file: "operations.json", value: operations, recipe: "sorted-nl" },
  { file: "lifecycle.json", value: lifecycle, recipe: "sorted-nl" },
  { file: "states.json", value: states, recipe: "sorted-nl" },
  { file: "events.json", value: events, recipe: "sorted-nl" },
  { file: "routes.json", value: routes, recipe: "sorted-nl" },
  { file: "capabilities.json", value: capabilities, recipe: "sorted-nl" },
  { file: "halt.json", value: halt, recipe: "sorted-nl" },
  { file: "gating.json", value: gating, recipe: "sorted-nl" },
  { file: "races.json", value: races, recipe: "sorted-nl" },
  { file: "readiness.json", value: READINESS_CONTRACT, recipe: "sorted-nl" },
  { file: "compat-literals.json", value: compatLiterals, recipe: "sorted-nl" },
  { file: "forbidden-aliases.json", value: forbiddenAliases, recipe: "sorted-nl" },
  { file: "literal-kinds.json", value: literalKinds, recipe: "sorted-nl" },
  { file: "replacement-policy.json", value: replacementPolicy, recipe: "sorted-nl" },
  { file: "literal-inventory.json", value: literalInventory, recipe: "sorted-nl" },
  { file: "construction-sites.json", value: constructionSites, recipe: "sorted-nl" },
  { file: "artifacts.json", value: artifacts, recipe: "sorted-nl" },
  {
    file: "instruction-origin.json",
    value: INSTRUCTION_ORIGIN_CONCERN_MANIFEST.frozenValues,
    recipe: "sorted-nl",
  },
  { file: "purposes.json", value: purposes, recipe: "sorted-nl" },
  { file: "fields.json", value: fields, recipe: "sorted-nl" },
  { file: "prefixes.json", value: prefixes, recipe: "sorted-nl" },
  { file: "versions.json", value: versions, recipe: "sorted-nl" },
  { file: "genesis.json", value: genesis, recipe: "sorted-nl" },
  { file: "suite-tuples.json", value: suiteTuples, recipe: "sorted-nl" },
  { file: "gateway-envelopes.json", value: gatewayEnvelopes, recipe: "sorted-nl" },
  { file: "role-projections.json", value: roleProjections, recipe: "sorted-nl" },
  { file: "api.json", value: api, recipe: "sorted-nl" },
  { file: "schema-vocabs.json", value: schemaVocabs, recipe: "sorted-nl" },
  { file: "negative-vectors.json", value: negativeVectors, recipe: "sorted-nl" },

  { file: "custody.json", value: CUSTODY_CONTRACT, recipe: "sorted-nl" },
  { file: "vault.json", value: VAULT_CONTRACT, recipe: "sorted-nl" },
  { file: "observation.json", value: OBSERVATION_CONTRACT, recipe: "sorted-nl" },
  { file: "engine-startup.json", value: ENGINE_STARTUP_CONTRACT, recipe: "sorted-nl" },
  { file: "handoff-proof.json", value: HANDOFF_PROOF_CONTRACT, recipe: "sorted-nl" },
  { file: "landing-proof.json", value: LANDING_PROOF_CONTRACT, recipe: "sorted-nl" },

  { file: "amounts.json", value: amountsContract, recipe: "raw-nl" },
  { file: "amount-enforcement.json", value: amountEnforcementContract, recipe: "raw-nl" },
  { file: "pool-policy.json", value: poolPolicyContract, recipe: "raw-nl" },
  { file: "pool-transactions.json", value: poolTransactionsContract, recipe: "raw-nl" },
  { file: "pool-scenarios.json", value: POOL_PRESSURE_SCENARIOS, recipe: "raw-nl" },

  { file: "receive-expiry.json", value: receiveExpiryContract, recipe: "raw-no-nl" },
  { file: "receive-expiry-ordering.json", value: expiryOrderingContract, recipe: "raw-no-nl" },
  {
    file: "receive-expiry-phases.json",
    value: receiveExpiryFaultInjectionContract,
    recipe: "raw-no-nl",
  },
  { file: "wallet-state.json", value: walletStateContract, recipe: "raw-no-nl" },
  {
    file: "wallet-state-alignment.json",
    value: walletStateAlignmentContract,
    recipe: "raw-no-nl",
  },
  { file: "wallet-state-matrix.json", value: walletStateMatrixContract, recipe: "raw-no-nl" },

  {
    file: "contract-drift-manifest.json",
    value: CONTRACT_DRIFT_MANIFEST,
    recipe: "sorted-nl",
  },
];

/** Stable file-name-sorted census both `emit-json.ts` and `gen/json-sync.test.ts` iterate. */
export const GEN_SNAPSHOTS: readonly GenSnapshot[] = [...entries].sort((a, b) =>
  a.file.localeCompare(b.file),
);

/**
 * Closed-set gate: throws when `onDiskFiles` and `registeredFiles` are not exactly the same set
 * (an on-disk file with no registry entry, a registry entry with no on-disk file, or a
 * duplicate on either side). Pure — takes the two file-name lists as data, never re-derives them
 * itself, so a test can drive it against independent fixtures.
 */
export const assertGenCoverage = (
  onDiskFiles: readonly string[],
  registeredFiles: readonly string[],
): void => {
  const onDiskSet = new Set(onDiskFiles);
  const registeredSet = new Set(registeredFiles);
  if (onDiskSet.size !== onDiskFiles.length) {
    throw new Error(`duplicate on-disk gen file(s): ${onDiskFiles.join(", ")}`);
  }
  if (registeredSet.size !== registeredFiles.length) {
    throw new Error(`duplicate registered gen snapshot(s): ${registeredFiles.join(", ")}`);
  }
  const onlyOnDisk = onDiskFiles.filter((file) => !registeredSet.has(file));
  const onlyRegistered = registeredFiles.filter((file) => !onDiskSet.has(file));
  if (onlyOnDisk.length > 0 || onlyRegistered.length > 0) {
    throw new Error(
      `gen coverage breach — on-disk only: [${onlyOnDisk.join(", ")}], registered only: [${onlyRegistered.join(", ")}]`,
    );
  }
};
