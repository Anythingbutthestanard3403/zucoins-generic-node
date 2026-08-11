# Release target registry

`targets.v1.json` is the sole authority for mapping repository changes to logical release targets. Classification reports impact only: it never grants deployment authority. The classifier fails closed on unknown non-documentation paths and on drift between registry watch patterns and committed Railway config.

Provider service and environment IDs, credentials, tokens, deployment IDs, URLs, and raw provider responses are deliberately excluded from git. Scheduled drift checks receive IDs through protected runtime JSON and persist only schema-validated, sanitized evidence.

## Classifier output and control-glob tiers (ZTR-678)

`scripts/release-targets.mjs classify` emits a stable JSON object with `registry` (provenance, below), `manualReviewRequired`, `affectedTargets` (each `{ id, active, deployMode, reasonCodes }`), `controlPaths`, and `ignoredPaths`. `reasonCodes` are `SOURCE_PATH` (a real deploy-source glob) and `BLOCKED_NOT_DEPLOYABLE` (the inactive `generic-node`), and no others: a control-glob hit is IMPACT-DESCRIPTIVE only and MERGE-NEUTRAL (D9.33), so it is NEVER fanned into a deploy target's `affectedTargets` — it appears solely in `controlPaths`. A control-only change can therefore never be stranded on a funded deploy that merge never triggers.

### Registry provenance (ZTR-808)

A classification verdict is a function of its arguments alone. When `classify` (or the
`release-targets-strict-dual.mjs` fence beneath it) is given `--base` / `--head`, it reads
`targets.v1.json` **and `targets.schema.json` at `--head`**, never from the caller's
checkout — a tree parked behind the registry commit that classifies the changed paths
otherwise emits a confidently wrong `UNCLASSIFIED_PATH`.

Every result, success or refusal, carries `registry`:

| field | meaning |
| --- | --- |
| `source` | `ref` (pinned at `--head`), `worktree` (ref-less `--paths-from-stdin` only), or `provided` (registry object injected by a caller — no revision to name) |
| `ref` | the resolving ref, or `null` |
| `blobSha` / `schemaBlobSha` | git blob SHAs of the registry and schema actually used — cite these to make a gate result reproducible |
| `worktreeDiverged` | `true` when the checked-out registry differs from the one used; `null` when the worktree copy is unreadable |

A ref that will not resolve is `REGISTRY_REF_UNRESOLVED` (exit 2), never a silent fall
back to the working tree. So a cited refusal distinguishes "the classifier does not know
this path" from "your checkout is old".

### Verdict-integrity registry pin (ZTR-812)

`scripts/verdict-integrity.mjs` grades same-head supersession edges with
`isDeploying()`, which keys off `target.active` / `target.deployMode`. It therefore
has the same provenance requirement as `classify`: the registry it reads must be a
function of the revision under test, not of the caller's checkout.

**Which ref:** each same-head group resolves the registry at the group's `head_sha` —
the pin the verdict already carries. There is no `--base`/`--head` range argument
here; the verdict's own head is the only revision that can answer "was this target
deployable when this verdict was written?". A tree parked before a registry flip
(e.g. ZTR-577 activating `generic-node`) otherwise grades an escalating
`NO_DEPLOY → deploying` edge as non-escalating and skips the blob-proof requirement
— fail-open, the opposite direction from the ZTR-808 false-refusal incident.

Every `evaluateHeadGroup` / family result carries the same `registry` provenance
object as `classify` (`source`, `ref`, `blobSha`, `schemaBlobSha`,
`worktreeDiverged`). An injected registry (unit tests) reports `source: "provided"`.
An unresolvable head is `REGISTRY_REF_UNRESOLVED` / `REGISTRY_REF_UNPARSABLE`
(exit 2) — never a silent fall back to the working tree.

`controlGlobs` split into two review-DEPTH tiers. The partition lives in `release-targets.mjs`, not the registry, on the same registry-INDEPENDENT precedent as the money-path sentinel's hardcoded glob set, so a data edit cannot relax it — and `release/targets.v1.json` is itself a funded-affecting control path. Fail-closed: any control path not on the benign allowlist is treated as funded-affecting (strict).

- **benign-governance** — `docs/DECISIONS.md`, `CLAUDE.md`, `AGENTS.md`, `.claude/agents/**`, `.codex/agents/**`. (`docs/decisions/**` matches ignoredGlobs `docs/**` and is already merge-neutral; the generated aggregate `docs/DECISIONS.md` carries the benign-governance signal for a decision change.) Touched alone: `manualReviewRequired: false`, empty `affectedTargets`. Merge-neutral, non-funded; under the four-role roster the ordinary single-reviewer path applies (still gated on a reviewer PASS). Decision-register integrity shells are **not** on this list.
- **funded-affecting-control** — `release/**`, `scripts/release-targets*.mjs` (including the dual-review machine fence `scripts/release-targets-strict-dual.mjs`), `scripts/claim*.py` (the claim windows the fence reads to prove verdict provenance — ZTR-1064), `scripts/money-path-scan*.mjs`, `scripts/verdict-integrity*.mjs`, `scripts/verify-railway-release-binding*.mjs`, `scripts/check-phantom-settles*.mjs`, `scripts/build-decisions.mjs`, `scripts/check-decision-ids.sh`, `scripts/check-decision-citations.sh`, `scripts/release-lease.mjs`, `scripts/release-lease.test.mjs`, `scripts/release-lease/**`, `.github/workflows/**` (the release/QA / decision-authority fence itself). Touched alone: `manualReviewRequired: true`. Forces STRICT (dual) review before merge. Relative to the prior control-fan-out that stranded these PRs, this is the intentional softening the ticket asked for: the PR is mergeable after dual review rather than undeliverable. The `manualReviewRequired` flag itself grants no deploy authority and relaxes none.

**Machine enforcement of STRICT dual (ZTR-678 D1):** the merger preflight is the VERIFIED path `scripts/release-targets-strict-dual.mjs check --base <base> --head <head> --pr <n>`, which DERIVES the pass count from the PR's own head-pinned, per-lane-deduped, claim-window-checked verdict comments (ZTR-1064) and requires two DISTINCT reviewer runs. Exit `3` refuses single-PASS merge when `manualReviewRequired` or `moneyPathHit` is set. `--pass-count <n>` is **not** the preflight — it is an audited operator override that verifies NOTHING (no head pin, no lane, no provenance) and prints an AUDIT line; reserve it for a fence that cannot reach the evidence or a sanctioned single-run-legacy `DUAL_SINGLE_RUN` during migration, and never as `--pr`'s equal. The fence matches `scripts/release-targets*.mjs` so weakening it is itself funded-affecting-control. Agent prose in `merger.md` / `reviewer.md` documents the call site only.

This is a review-DEPTH signal only, orthogonal to and distinct from the money-path sentinel (D9.41): a control-glob hit is not a money-path hit, and vice-versa. `SOURCE_PATH` funded detection is unchanged — a PR touching a real funded source glob (e.g. `apps/node/**`) still surfaces `funded-manual-node` as `SOURCE_PATH` funded routing regardless of any co-changed control path, and a co-changed funded-affecting-control path keeps `manualReviewRequired: true` alongside it.

## Enforcement status (D9.23)

Per `docs/DECISIONS.md` D9.23, all repo GitHub Actions workflows — including `ci.yml`, which carries the `release-classification` job below — are DISABLED repo-wide pending a Riley decision to re-enable them. The `release-classification` job and its wiring into the `ci/zucoins/required` gate remain committed (D9.23 disabled the workflows, it did not delete them) but are **dormant**: they do not execute while the workflow is disabled, and no PR should be read as carrying active CI enforcement of this registry until Riley restores CI.

The real, current enforcement point is local and pre-merge, per D9.23's local-only verification rule: the pushing lane (or the release executor at merge time) runs, in a private clone at the exact head SHA about to be pushed or merged:

```
node scripts/release-targets.mjs validate
node scripts/release-targets.mjs classify --base <base-sha> --head <head-sha> --output release-classification.json
```

`validate` must report `VALID`; `classify`'s JSON output — including `manualReviewRequired`, `affectedTargets`, and `controlPaths` (see "Classifier output and control-glob tiers" above) — is recorded verbatim as release evidence in the PR/handoff comment, in place of the CI artifact upload the dormant job would otherwise produce. This applies until Riley re-enables the `ci.yml` workflow (`gh workflow enable`), at which point the committed job resumes as the live enforcement path with no further changes required.

## Scheduled binding drift check

The registry's committed binding facts are compared against the live Railway service
binding on a schedule by `scripts/verify-railway-release-binding.mjs`. Its schedule lives
in [`release/drift-check/`](drift-check/README.md): a shared entrypoint
(`run-scheduled-drift-check.mjs`) drives every target whose
`externalBinding.driftCheck` is `scheduled-read-only`, run today via the local operator /
scheduled-agent cadence `pnpm run release:drift` (D9.23 local-only model) and staged as a
Railway-native cron service for a live-operations-engineer to provision. It is not a GitHub
Actions workflow (D9.23). Operator cadence, expected output, and the drift-alarm response
path are in [`docs/runbooks/release-binding-drift-check.md`](../docs/runbooks/release-binding-drift-check.md).

Decommissioned targets (`funded-manual-node` per D9.61, `public-reference-node` per D9.61) are
excluded by the `active: false` gate on their registry rows and are not drift-checked.

## Scheduled backup assurance (sibling control)

Railway *backup-schedule* drift (and opt-in throwaway restore-drill RPO/RTO evidence) is a
separate detective control from binding drift. Its schedule lives in
[`ops/backup-assurance/`](../ops/backup-assurance/README.md) (release target
`backup-assurance-runner`, deactivated with its dead Railway project by ZPAY-265 /
D10.55 — the local run is the control of record until ZPAY-275 re-provisions it);
run locally with `pnpm run backup:assurance`. It replaces the
disabled `.github/workflows/backup-drift.yml` under D9.23 — see
[`docs-site/content/runbook/database-backup-dr.md`](../docs-site/content/runbook/database-backup-dr.md).

## Evidence contract

Each release handoff retains the deterministic classifier JSON, provider/health evidence applicable to the selected target, the immutable image digest or commit SHA, and the target's rollback reference. A target appearing in classifier output means only that it is affected. Approval, migration, health, live-acceptance, and rollback gates remain separate.

A `QA_VERDICT_V2` covering a change in this registry's control scope cites the registry itself as `target_registry_ref`: `release/targets.v1.json@<git-blob-sha>`, the git blob SHA of `release/targets.v1.json` as it exists at the reviewed head (`git rev-parse <head-sha>:release/targets.v1.json`). This pins the verdict to the exact registry contents reviewed, independent of the commit SHA, so a later commit that leaves the registry byte-identical does not require a fresh registry review.

## Retired: `hosted-platform` (ZPAY-264 / D10.53)

`hosted-platform` is `active: false`, `deployMode: "none"`, `externalBinding: null`. Its
Railway project no longer exists in any reachable workspace, so the row named a target that
deployed nothing while `apps/platform/dashboard/**` and `apps/platform/ops/**` — which
genuinely rebuild the live service — classified only to it. The live hosted platform is
`platform-v2`, built by Railway from `apps/platform-v2/railway.json`; its registry
`watchPatterns` are held equal to that file, and `WATCH_PATTERN_UNCLASSIFIED` now fails
closed if any target watches a path its own `classificationGlobs` do not reach.

The retired row keeps its `classificationGlobs` and `watchPatterns` on purpose: a deleted
path is still a changed path, and the eventual v1-removal commit must classify rather than
raise `UNCLASSIFIED_PATH`.

`app.zupayments.com` currently answers the Railway edge's `Application not found` and is
left dangling deliberately — see D10.53(7) for the three grounds and the owner action.

## Watch-pattern rationale: `/package.json`

The retired `hosted-platform` and (when active) `funded-manual-node` watch lists include `/package.json` (root, not per-package) deliberately: the root `package.json` pins the pnpm/Node toolchain and workspace-wide scripts, so a change there can alter what gets installed or how any workspace package builds, even without touching that package's own source. It is deploy-relevant for every Railway-built target and is kept in active targets' watch lists for that reason, consistent with `/pnpm-lock.yaml` and `/pnpm-workspace.yaml` already being present for the same reason.

## Rollback evidence

Record the last-known-good commit or immutable artifact digest before release, the observed health gate after release, and the operator/runbook used to restore it. Never persist private URLs, credentials, provider IDs, or raw provider payloads in an artifact.

## Funded node boundary

The `funded-manual-node` record is descriptive. It cannot authorize, select, or execute a deployment. It is `active: false`; its `classificationGlobs` are `apps/node/**` (the v1 treasury-node image) plus shared/toolchain globs — a **different node** than `generic-node`. Its `deployMode: automatic` / `approval: agent-autonomous-d9.47` / `liveAcceptance: testwallet-bounded-d9.46` fields are de-gated **only** under the D9.46 test-wallet carve-out and D9.47's extension of it to this one v1 target. **Scope: `funded-manual-node` alone** — these de-gated values must never be read across onto `generic-node` or any other row (that misread is the ZTR-938 incident ZTR-974/D10.25 exist to prevent recurrence of). D9.61 decommissioned the two dead Railway service bindings this target once pointed at; the registry row itself remains because the live, funded E2E node still runs the v1 image these fields describe. If ZTR-907 scraps v1 (`apps/node/**`), this target retires with it — until then it is v1-only and out of scope for `generic-node` work.

## Generic node boundary

Default image CMD is **custody main** (`dist/main.js`, ZTR-903 after ZTR-896
Stage-2 composition). Readiness is schema ∧ DB ∧ vault ∧ observation per the
custody boot lane (`09-operations-recovery.md` §7 / `03-node-core.md` §3).

Stage-1 (`dist/stage1-main.js`) remains a **named** non-money / zero-custody
variant (CMD override or `pnpm start:stage1`). Its readiness contract is
migrations-complete plus a fresh database `SELECT 1`. It mounts no vault,
private-key submit, or money workers when run under that entrypoint.

`generic-node` is an active release target. Money path admission still requires
operator dry-run evidence (ZTR-905) and related go-live binds; CMD alone does not
authorize live funded ZKZ beyond AGENTS rule 6 test-coin policy.

**Registry fields (D10.25):** `liveAcceptance` reads `custody-present-testcoin-bounded-d10.1`
— this node holds real custody (sealed vault, `NODE_IDENTITY` signing, dual control, ARM,
TOTP); live-acceptance risk is bounded by D10.1 (test coins) and golden rule 6, not by an
absence of keys. `deployMode: manual-riley-gated` / `approval: riley-explicit-in-session`
are unchanged and are a deliberate, narrower override of D10.8's default merger
deploy-and-verify authority, enforced in code by `GENERIC_NODE_CUSTODY_TRIPWIRE`
(`scripts/release-targets.mjs`). **Scope: `generic-node` alone** — do not copy
`funded-manual-node`'s de-gated values (D9.46/D9.47, v1-only, see "Funded node boundary"
above) onto this target.

**Custody rollback:** use stop-first drain deploy
(`docs/runbooks/stop-first-drain-deploy.md`) when money workers may be armed.
**Stage-1-only rollback:** stop the service / pin image and re-run with
explicit Stage-1 CMD if zero-custody shell is required.
