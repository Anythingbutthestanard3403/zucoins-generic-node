# ZTR-1135 / ZTR-1136 implementation report

## Scope

Shared implementation for operator-driven restore-hold exit and externally witnessed backup continuity.

## Delivered behavior

- Scheduled backup boot configuration now requires `BACKUP_CONTINUITY_MARKERS_PATH`.
- Every successful scheduled backup derives lifecycle epoch, node-wide nonce-burn high-water, and terminal lifecycle hash from the healthy live database, then emits a provenance-bound marker tied to the backup artifact SHA/path.
- Legacy/self-derived markers without `successful_scheduled_backup` provenance are refused.
- `dr markers check` derives the restored local continuity point from the live database and returns typed decisions.
- `dr markers release` re-derives under restore/head/nonce locks and atomically appends `AUTH_HOLD_RELEASED` for held heads plus clears `restore_hold`.
- Release events retain the canonical lifecycle writer, hash chain, epoch, nonce evidence, and head-advance path. Clearing `restore_hold` alone remains denied by `auth_hold`.
- Restore runbook now documents external marker custody, check/release order, refusal handling, and post-release ceremony/admission verification.

## Test coverage

- Marker parse/provenance, exact comparison, live-DB derivation, rollback/refusal reasons.
- Typed CLI refusal for absent trusted marker.
- Scheduled backup success writes a marker file bound to the published artifact.
- Release SQL shape and canonical head advance.
- PG restore/force test extended through restore denial, single-hold fault case 9, atomic dual release, `AUTH_HOLD_RELEASED`, and admitted reporting.
- Existing force/SS3 PG fixtures updated for marker provenance.

## Verification ledger

- `pnpm run build` (apps/generic-node): PASS.
- Changed-file ESLint: PASS.
- Focused non-PG Vitest: 5 files, 42 tests PASS with teardown bypassed via explicit unused `TEST_DATABASE_URL` because the shared local PostgreSQL instance was saturated in `CheckpointDone` by concurrent database-drop jobs.
- Required final focused PG and canonical package test/lint/build results will be appended to the PR/ticket handoff at the exact pushed SHA.

## Environment note

The first focused run executed all 42 tests successfully but Vitest global teardown timed out dropping its scratch database while the shared PostgreSQL server had multiple unrelated concurrent `DROP DATABASE` sessions waiting on `CheckpointDone`. Product assertions were green; this is tracked separately from final exact-head evidence and does not waive the PG gate.
