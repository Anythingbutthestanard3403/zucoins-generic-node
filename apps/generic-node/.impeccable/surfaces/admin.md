---
version: 1
slug: "admin"
primary_target: "admin"
related_targets: []
---

# Operator console (admin SPA)

Scope: whole operator console, mode Operate. Audience: node operators on phone PWA and desktop
equally. Job: know node health, clear what waits on them, watch reserves, configure connectors,
run custody rituals. Constraints: CSP self-only, system font stacks, drift-gate vocabulary,
tested labels/testids/pin-rail behaviour. Redesign depth: design system + shell + login/setup
funnel + Overview + Approve; other pages inherit through the system.

## Direction contract

THESIS: The category standard dark fintech console played straight at Mercury's craft. Refuses the
tile-wall dashboard where every number gets an equal card: one balance leads, what waits on the
operator is second, everything else is reference rows.

OWN-WORLD: Near-black neutral ground, surfaces separated by lightness steps and 1px hairlines,
large 14px radii on panels, 8px on controls. One teal accent for primary action, focus and the
active mark only; active nav is a raised neutral fill, never accent-washed. State colours
(green/amber/red) as small dots and soft chips. Big figures in regular weight with muted cents.

STORY: The operator sees whether the node is healthy, what it holds as verified by chain read,
and what needs them; acts on it in one click or tap; drills into rows for detail.

FIRST VIEWPORT: Sidebar left (brand, five sections, node status foot). Slim top bar: node host,
health dot, theme, inbox, operator. Main: page header with title and primary actions right;
a full-width balance panel (44px regular figure, muted cents, Receive/Send/Move buttons), then
the three-ops strip as one divided panel with a fourth halt-state cell (halt is a tested
custody control), then Needs attention and Wallet pool side by side, then the halt control
card and the activity ledger.

FORM: Canon (standing exit, user-chosen over two rolled hands), craft bar Mercury. Seed key a75393f6.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
