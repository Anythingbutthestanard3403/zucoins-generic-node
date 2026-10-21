# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The operator of a self-hosted SplitChain custody node. The same people switch constantly between
an installed PWA on their phone (approving queued operations, checking health, engaging halt)
and a desktop browser (setup, wallet and connector configuration, audit, recovery ceremony).
Neither device is secondary. They hold the master key; nobody upstream can recover a key,
roll back a signature, or undo a submit for them.

## Product Purpose

The operator console (`apps/generic-node/admin`) is how a human runs the node: see whether the
node is healthy and ready, approve or reject operations that need a human, watch reserve and
worker wallets, configure connectors (implementer integrations, API keys, auto-approve and
verification policy), and perform the custody rituals (device enrolment, TOTP, backup,
recovery ceremony, halt). Success is an operator who always knows what the node holds, what is
in flight, and what is waiting on them, and who never acts on a false reading.

## Positioning

The node performs exactly three money operations and nothing else: `RECEIVE_EXTERNAL`,
`MOVE_INTERNAL`, `SEND_EXTERNAL`. Anything shaped like a business process belongs to the
implementer above it. There is no sandbox mode: every configured gateway is live production.
Settlement is asserted only from a fresh verified chain read, never from a gateway
acknowledgement. The console's honesty about what is known versus asserted is the product.

## Operating Context

- Day-0 funnel before any money screen: password change, TOTP enrolment, PWA install, device
  enrolment, vault, backup pack, prove. Money routes stay locked until it completes.
- Primary sections: Overview, Wallets, Connectors, Activity, Settings. Seventeen legacy routes
  deep-link into them.
- Approve inbox is the most frequent phone task; approvals may require device signing and TOTP.
- Counterintuitive states that must read as correct, not as bugs: `INDETERMINATE` submits,
  leases that do not auto-release, `restore_hold` / `auth_hold`, halt engaged.
- Operators work these screens at 3am during incidents.

## Capabilities and Constraints

- Served by the node itself under a strict CSP: `style-src 'self' 'unsafe-inline'`, no third-party
  font or asset hosts. Fonts are system stacks or files bundled with the app (tests enforce
  `--font: ui-sans-serif…` and `--mono: ui-monospace…`).
- Drift-gate forbidden vocabulary applies to all admin source (`.ts/.tsx/.md`): payment, refund,
  sweep, treasury, checkout, payout, withdrawal, order, merchant, reservation, outbound, drain,
  ZUC, finalised, fulfilled, treasury settlement.
- Existing tests assert copy, roles, `data-testid`s, nav labels, and some stylesheet rules
  (global `:focus-visible` with `var(--accent)`, `.table-wrap` overflow-x, 720px reflow rules).
- Stack: React 19, React Router 7, TanStack Query, Zustand, Vite. No UI component library.
- Shell-only service worker; admin and API JSON are never cached as money truth.

## Brand Commitments

- Name: "Zu Node" (manifest and title).
- Standing visual preference (chosen 2026-10-20 over two rolled direction hands): the category
  standard dark fintech console, executed straight, no irony or smuggled quirk. Craft bar:
  Mercury. Light theme remains available.

## Evidence on Hand

Real product copy, labels and states live in `admin/src/lib/labels.ts` and page components.
Operational truth lives in `docs/operations/`. No customer logos, testimonials, or metrics exist;
none may be invented.

## Product Principles

1. Truth over reassurance: never show a state the chain has not confirmed as if it had.
2. What waits on the operator comes first; everything else is reference.
3. Irreversible actions look and feel irreversible, with the ceremony they require.
4. Phone and desktop are equal citizens; every action reachable by thumb and by keyboard.
5. Calm at 3am: legible under stress, no decoration competing with state.

## Accessibility & Inclusion

WCAG 2.2 AA: visible focus on every control, 1.4.10 reflow down to 320px, 44px touch targets
for primary actions, axe-core checks in the test suite.
