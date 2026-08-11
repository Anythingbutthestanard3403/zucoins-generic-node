#!/usr/bin/env bash
# verify-local.sh — stub (ZTR-1205)
#
# Merchant-Wallets has a full pre-push local verification runner. This repo does
# not yet have an equivalent pipeline (tsc/vitest package layout differs). Until
# a real port lands, fail loud so lanes never treat a missing gate as green.
#
# See ZTR-1227 for the dual-review fence; a full verify-local port is out of
# ZTR-1205 scope. Until then run the package checks listed in
# .claude/agents/implementer.md by hand:
#   pnpm install && tsc -b && pnpm --filter <pkg> test && pnpm --filter <pkg> lint
set -euo pipefail
echo "verify-local.sh: not implemented — see ZTR-1227 (and ZTR-1205 handoff)" >&2
echo "  Run the implementer verification set manually (pnpm install, tsc -b, package test/lint)." >&2
exit 2
