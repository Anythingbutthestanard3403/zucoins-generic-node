# ZTR-1272 — Implementer cutover: stop supplying source wallet

**Linear:** https://linear.app/zutopia/issue/ZTR-1272  
**Depends on:** ZTR-1271 (PR #130 merged)  
**Branch:** `ztr-1272-source-omit-cutover`  
**Claim run:** `997569c4-0b59-455d-ae96-5cb8e68f090b`

## Scope (docs + checklist only)

1. `docs/operations/auto-approve-external-sends.md` — omit source as default; legacy explicit; E2E path; never chain-submit
2. Pack P checklist + dual-control guide text (`apps/generic-node/admin/src/lib/packs.ts`)
3. Written Zukaz cutover checklist with config keys to remove
4. Ops README index cross-link
5. Drift-gate clean; money-path scan expected non-money if docs-only (admin packs.ts may hit — prefer docs)

## Non-goals

- Zukaz application code in this repo
- Auto-approve rule JSON schema changes
- Removing explicit source support on the API

## AC

- [x] Implementer-facing send docs present omitted source as default
- [x] Auto-approve E2E doc updated
- [x] Pack P guide updated
- [x] Zukaz cutover checklist with fields/config to remove
- [x] Legacy explicit source documented
- [x] No copy claims the node chain-submits SEND
