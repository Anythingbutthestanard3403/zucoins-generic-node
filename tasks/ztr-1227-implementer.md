# ZTR-1227 — implementer handoff

## Summary

Built the missing strict-dual release fence stack that `ORCHESTRATION.md` / merger
agents already name. Ported the proven Merchant Wallets fence (ZTR-1064 lineage)
and adapted the deploy registry for the Generic Node monorepo layout.

## Acceptance criteria

1. **`scripts/release-targets-strict-dual.mjs` exists** and is callable at the
   ORCHESTRATION path — **SATISFIED**.
2. **Enforces dual PASS PR comments** (head-pinned, claim-window, unedited,
   reviewer-A/B distinct runs) via `release-targets-verdict-evidence.mjs` +
   `claim.py windows` — **SATISFIED** (full MW evidence module + tests).
3. **Single-review path** when dual not required (`DUAL_NOT_REQUIRED`) —
   **SATISFIED**.
4. **Exit non-zero with precise reason** — exit 3 `REFUSE_MERGE` + reasonCode;
   exit 2 gate-did-not-run — **SATISFIED**.
5. **ORCHESTRATION no longer points at a missing file** — added
   `ORCHESTRATION.md` documenting the fence — **SATISFIED**.

## Governing spec

- Ticket ZTR-1227 body + sweeper AC (2026-08-11).
- Operating discipline already encoded in MW
  `scripts/release-targets-strict-dual.mjs` / verdict-evidence (PR #1794 forgery
  class, F1–F5, ZPAY-216).
- `ORCHESTRATION.md` (this PR) § Review depth / Dual review.

## Files

| Path | Why |
|------|-----|
| `scripts/release-targets-strict-dual.mjs` | Machine dual-review merge fence |
| `scripts/release-targets-strict-dual.test.mjs` | 50 fence unit/integration tests |
| `scripts/release-targets-verdict-evidence.mjs` | PR comment + claim-window evidence |
| `scripts/release-targets.mjs` | Classify / registry validate (control globs) |
| `scripts/release-targets.test.mjs` | GN-adapted classifier tests (14) |
| `scripts/money-path-scan.mjs` | Money-path sentinel (orthogonal dual axis) |
| `scripts/money-path-scan.test.mjs` | Money-path tests (22) |
| `scripts/claim.py` + `scripts/claim.test.py` | Claim windows the fence reads (33 py tests) |
| `release/targets.v1.json` | GN registry (generic-node active; other targets inactive stubs for REQUIRED set) |
| `release/targets.schema.json` | Registry schema |
| `release/provider-evidence.schema.json` | Evidence schema |
| `release/README.md` | Registry / rollback docs |
| `ORCHESTRATION.md` | Documents fence path + dual rules |
| `package.json` | `release:validate` / `release:test` / `release:fence` |

## Verification (at head)

```
node scripts/release-targets.mjs validate
  → VALID, 10 targets

node --test scripts/release-targets-strict-dual.test.mjs \
            scripts/money-path-scan.test.mjs \
            scripts/release-targets.test.mjs
  → tests 86, pass 86, fail 0

python3 scripts/claim.test.py
  → Ran 33 tests … OK

npx eslint scripts/release-targets*.mjs scripts/money-path-scan.mjs
  → clean

CLI smoke:
  paths-from-stdin benign + pass-count 0 → exit 0 DUAL_NOT_REQUIRED
  node-core path + pass-count 1 → exit 3 STRICT_DUAL_INSUFFICIENT
  node-core path + pass-count 2 → exit 0 DUAL_SATISFIED
  fence self path + pass-count 1 → exit 3 STRICT_DUAL_INSUFFICIENT
```

Root `tsc -b` was attempted via linked `node_modules` and failed on missing
workspace package resolution (`@zucoins/node-core`, `pg`, …) — pre-existing
worktree install gap, not introduced by these pure `.mjs`/`.py` scripts.

## Notes / deferred

- Verified `--pr` path needs live `gh` + Linear; covered by unit tests that
  inject comments/windows. Operator override `--pass-count` remains for audited
  merger bypass only.
- Inactive registry stubs (hosted-platform, platform-v2, …) exist only so the
  shared `REQUIRED_TARGETS` contract stays intact; they have empty/minimal
  classification globs and `active: false`.
- `verdict-integrity.mjs` not landed (0-byte stub on main; out of AC scope).
