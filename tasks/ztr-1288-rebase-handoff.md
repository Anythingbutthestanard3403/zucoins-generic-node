# ZTR-1288 rebase handoff (post ZTR-1287 / 1284 / 1285)

- PR #143 rebased onto latest `origin/main` (includes ZTR-1287, 1284, 1285 polish).
- First rebase onto 81ba43a was clean; second rebase onto 1cfbf6b+ needed one comment-only conflict (kept main).
- Post-rebase green fixes retained:
  - `api` → `implementer` in `ALLOWED_INTERNAL_IMPORTS` (identity router).
  - `implementer-funding-wallet.sql` in migration-integrity SCHEMA_FILES / NO_TABLE / GREENFIELD.
  - Neutrality "sweep" comments already fixed on main (1285/1283 path).
  - prefer-const already on main (`58e4abb`).
  - contract-drift-manifest route-policy golden sha synced.
- Dual review must re-run at new head (prior DUAL_SATISFIED was bb0316fb).
