---
name: Zu Node
description: Operator console for a self-hosted custody node; the category-standard dark fintech console at Mercury's craft bar.
colors:
  ground: "#0f1013"
  ground-soft: "#131417"
  rail: "#0c0d10"
  surface: "#17181c"
  surface-raised: "#1e1f24"
  surface-high: "#27282e"
  hover-wash: "rgba(255, 255, 255, .035)"
  press-wash: "rgba(255, 255, 255, .06)"
  hairline: "rgba(255, 255, 255, .07)"
  hairline-strong: "rgba(255, 255, 255, .11)"
  ink: "#edeef0"
  ink-2: "#b0b2ba"
  ink-3: "#8a8d97"
  ink-4: "#62656f"
  signal-teal: "#3dd6c6"
  signal-teal-hover: "#5fe2d4"
  signal-teal-ink: "#03201c"
  signal-teal-text: "#5fe2d4"
  signal-teal-soft: "rgba(61, 214, 198, .12)"
  signal-teal-ring: "rgba(61, 214, 198, .34)"
  state-ok: "#4cc98e"
  state-ok-soft: "rgba(76, 201, 142, .12)"
  state-warn: "#e6b84f"
  state-warn-soft: "rgba(230, 184, 79, .12)"
  state-danger: "#f2767d"
  state-danger-soft: "rgba(242, 118, 125, .12)"
  state-info: "#86a9ff"
  state-info-soft: "rgba(134, 169, 255, .12)"
  overlay: "rgba(4, 5, 7, .66)"
  light-ground: "#f6f6f7"
  light-ground-soft: "#f1f1f3"
  light-rail: "#fbfbfc"
  light-surface: "#ffffff"
  light-surface-raised: "#f5f5f7"
  light-surface-high: "#ececef"
  light-hairline: "rgba(17, 18, 22, .08)"
  light-hairline-strong: "rgba(17, 18, 22, .13)"
  light-ink: "#121317"
  light-ink-2: "#464953"
  light-ink-3: "#686b75"
  light-ink-4: "#9a9ca5"
  light-signal-teal: "#0b7f74"
  light-signal-teal-hover: "#096c63"
  light-signal-teal-ink: "#ffffff"
  light-signal-teal-text: "#0a7268"
  light-state-ok: "#13804f"
  light-state-warn: "#9a6400"
  light-state-danger: "#c4282f"
  light-state-info: "#2556d0"
  light-overlay: "rgba(18, 19, 23, .38)"
typography:
  figure:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "44px"
    fontWeight: 450
    lineHeight: 1.05
    letterSpacing: "-.035em"
    fontFeature: "\"tnum\""
  stat-figure:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "30px"
    fontWeight: 450
    lineHeight: 1.1
    letterSpacing: "-.03em"
    fontFeature: "\"tnum\""
  headline:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "26px"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-.022em"
  title:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-.012em"
  body:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"cv11\", \"ss01\""
  row:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "13.5px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "12.5px"
    fontWeight: 550
    lineHeight: 1.4
  mono:
    fontFamily: "ui-monospace, \"SF Mono\", \"Cascadia Mono\", \"Segoe UI Mono\", Menlo, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 500
    lineHeight: 1.5
    fontFeature: "\"tnum\""
rounded:
  panel-lg: "16px"
  panel: "14px"
  inset: "10px"
  control: "8px"
  chip: "6px"
  full: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "24px"
  3xl: "32px"
components:
  button:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "34px"
  button-hover:
    backgroundColor: "{colors.surface-high}"
  button-primary:
    backgroundColor: "{colors.signal-teal}"
    textColor: "{colors.signal-teal-ink}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "34px"
  button-primary-hover:
    backgroundColor: "{colors.signal-teal-hover}"
  button-danger:
    backgroundColor: "{colors.state-danger-soft}"
    textColor: "{colors.state-danger}"
    rounded: "{rounded.control}"
    height: "34px"
  button-block:
    backgroundColor: "{colors.signal-teal}"
    textColor: "{colors.signal-teal-ink}"
    rounded: "{rounded.control}"
    height: "42px"
    width: "100%"
  quick-action:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.full}"
    padding: "0 16px"
    height: "38px"
  input:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "38px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "20px"
  nav-item:
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "0 11px"
    height: "38px"
  nav-item-active:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
  tag:
    backgroundColor: "{colors.surface-high}"
    textColor: "{colors.ink-2}"
    typography: "{typography.label}"
    rounded: "{rounded.chip}"
    padding: "0 8px"
    height: "22px"
  tag-ok:
    backgroundColor: "{colors.state-ok-soft}"
    textColor: "{colors.state-ok}"
  tag-warn:
    backgroundColor: "{colors.state-warn-soft}"
    textColor: "{colors.state-warn}"
  tag-danger:
    backgroundColor: "{colors.state-danger-soft}"
    textColor: "{colors.state-danger}"
  segmented-tab-on:
    backgroundColor: "{colors.surface-high}"
    textColor: "{colors.ink}"
    rounded: "7px"
    height: "30px"
---

# Design System: Zu Node

## Overview

**Creative North Star: "The Night Ledger"**

The category-standard dark fintech console, played straight at Mercury's craft bar. A near-black neutral ground carries a stack of surfaces that differ only by small lightness steps and 1px hairlines; nothing glows, nothing is textured, and the single teal accent is spent sparingly. The console reads like a well-kept ledger at 3am: one balance leads, what waits on the operator comes second, and everything else is quiet reference rows.

Density is moderate and even. Body copy sits at 14px, rows at 13.5px, labels at 12.5px, and the only large type is numerals: the balance figure and the three-ops counts, set in regular weight with muted fractional digits so the number reads as a measurement rather than a headline. State is spoken in small marks (8px dots with a soft halo, 22px tinted chips) rather than in colored panels. Light theme is a full peer, not an inversion: every role has its own tuned value under `[data-theme="light"]`.

The system is constrained by the node's CSP: system font stacks only, no remote assets, every icon an inline 24-unit stroke SVG.

**Key Characteristics:**
- Near-black neutral ground; depth by lightness steps and hairlines, not shadow.
- One teal accent for primary action, focus, and the active mark.
- Large panel radii (14px) against tighter control radii (8px).
- Big figures in regular weight (450) with muted fractions and tabular numerals.
- State colour as dots and soft chips, never as filled surfaces.
- Dark and light themes tokenised as equal peers.

## Colors

A neutral graphite ladder with one cool teal signal and four quiet state hues; every non-neutral appears at full strength only as a small mark or as text over its own 12% tint.

### Primary
- **Signal Teal** (`signal-teal`; light: `light-signal-teal`): primary buttons, the block sign-in button, the logo tile, the global focus ring, the text caret, form-control accents, and the icon of the active nav item. Its hover is one step lighter in dark and one step deeper in light. Text on it uses **Signal Teal Ink**, a near-black teal in dark and white in light.
- **Signal Teal Text** (`signal-teal-text`): accent used as foreground (active nav icon, balance mark glyph, modal title icon, active tab count) where the base teal would be too dim on dark surfaces.
- **Signal Teal Soft / Ring** (`signal-teal-soft`, `signal-teal-ring`): the 3px focus halo and border on inputs; the tint behind accent-text glyphs.

### Secondary
- **State Ok / Warn / Danger** (`state-ok`, `state-warn`, `state-danger`, each with a `-soft` 12% tint): health dots, tags, banners, attention-row icon tiles, nav badges. Ok is also inbound money (`.money.in`). Danger fills only the urgent nav count and the inbox badge.
- **State Info** (`state-info`, `state-info-soft`): informational banners (install, demo) and the internal-transfer type glyph; the cool blue reads as "neutral fact", never as success.

### Neutral
- **Ground** (`ground`): page background, top bar, footer, and the inside of inputs (inputs sit *below* the surface they live on).
- **Ground Soft** (`ground-soft`): the well behind segmented tabs and code blocks.
- **Rail** (`rail`): the sidebar, one step darker than ground.
- **Surface / Surface Raised / Surface High** (`surface`, `surface-raised`, `surface-high`): panels; then neutral buttons, banners, callouts and the active nav fill; then hovered buttons, neutral tags, avatar and orb fills, the selected tab.
- **Hairline / Hairline Strong** (`hairline`, `hairline-strong`): panel borders and row dividers; control borders and raised overlays.
- **Hover / Press Wash** (`hover-wash`, `press-wash`): translucent row and nav hover fills, so hover works on any surface step.
- **Ink 1 to 4** (`ink` to `ink-4`): primary text; secondary text and nav labels; muted descriptions, table headers, fractional digits; placeholders and disabled.
- **Overlay** (`overlay`): modal and TOTP scrim.

### Named Rules
**The One Signal Rule.** Teal is reserved for primary action, focus, and the active mark. Active navigation is a raised neutral fill with a hairline inset; only its icon turns teal. Never wash a row, nav item, or panel in accent.

**The Small State Rule.** State hues appear at full strength only as dots, chip text, or icon glyphs, always over their own soft tint. A whole panel never turns green, amber, or red; banners carry state as a tinted line of truth, not a coloured block.

**The Reading Ink Rule.** Ink 4 is for placeholders, disabled controls, and keyboard hints. Text an operator must read uses Ink 3 or stronger.

## Typography

**Display Font:** none; the system UI stack carries every role (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, …`).
**Body Font:** the same system UI stack, with `cv11` and `ss01` feature settings.
**Label/Mono Font:** `ui-monospace, "SF Mono", "Cascadia Mono", …` for identifiers, addresses, amounts in rows, and operation codes.

**Character:** a native, instrument-grade sans used at restrained weights (450 for figures, 550 for labels and controls, 600 for headings) with slightly negative tracking on everything above 14px. The stack is a CSP requirement and tested; it is not a fallback.

### Hierarchy
- **Figure** (450, 44px, 1.05, -.035em; 34px under 720px): the one lead balance. Fractional digits drop to Ink 3; the unit sits at 15px/550 in Ink 3.
- **Stat Figure** (450, 30px, 1.1, -.03em; 24px under 720px): the three-ops counts and halt state. The approve card's lead amount uses the same voice at 26px.
- **Headline** (600, 26px, 1.15, -.022em; 22px under 720px): the page title, one per page. Auth cards use 22px.
- **Title** (600, 15px, 1.25): panel and card headings, section titles, approve operation labels.
- **Body** (400, 14px, 1.5): default text; page descriptions cap at 72ch.
- **Row** (400, 13.5px): table cells, attention rows, banners, callouts.
- **Label** (550, 12.5–13px): field labels, table headers, buttons (13px), chips (11.5px), stat keys (13.5px).
- **Mono** (500, 12–12.5px, tabular): wallet addresses, operation codes, row amounts, `code`.

### Named Rules
**The Quiet Figure Rule.** Large numbers are set in regular weight (450) with tabular numerals and a muted fraction. Never bold a figure to make it important; size and position already do that.

**The Sentence Case Rule.** Labels, buttons, chips and headings are sentence case at normal tracking. Machine identifiers (operation codes, addresses) appear in mono as data, beneath their human label, never as a decorative line above a heading.

## Layout

A two-column app shell: a 64px icon rail (56px under 420px) that expands to 240px on hover, focus-within, or pin, and a main column of a 60px top bar, a scrolling body, and a slim status footer. Unpinned expansion overlays content with a rail shadow; under 720px pinning also overlays instead of reserving a column. Body content centres at a 1240px maximum with 32px padding (24/22px under 980px, 18/16px under 720px).

Pages are a vertical stack with a 20px gap (16px on phone). The page header aligns title-left and actions-right on a shared bottom edge and stacks under 720px. Panels sit in single full-width rows or two-up splits with a 16px gutter; splits collapse to one column at 980px. The three-ops strip is one divided panel of four cells, dropping to two-by-two at 1100px.

Spacing works on a 4px base with 8, 12, 16, 20, 24 and 32 as the working steps; panel interiors pad 18–24px, rows pad 11–13px vertically. Primary touch actions grow to 44px on phone, and approve-card actions become a sticky bottom bar that respects the safe-area inset. Everything reflows to 320px; wide tables scroll inside their own frame.

**The Lead and Reference Rule.** One element leads each page (on Overview, the full-width balance panel). What needs the operator sits next; everything else is rows inside panels, not a wall of equal tiles.

## Elevation & Depth

Flat by default. In dark, resting panels carry no shadow at all and are separated from the ground purely by a lightness step and a 1px hairline; in light, panels take a 1px hairline-weight shadow so white reads against off-white. Shadow appears only on things that float above the page: modals, the TOTP sheet, the auth card, and the expanded rail.

### Shadow Vocabulary
- **Card** (dark: `none`; light: `0 1px 2px rgba(17,18,22,.04)`): resting panels, tables, approve cards.
- **Pop** (dark: `0 1px 0 rgba(255,255,255,.04) inset, 0 24px 48px -12px rgba(0,0,0,.6)`; light: `0 24px 48px -16px rgba(17,18,22,.22), 0 0 0 1px rgba(17,18,22,.06)`): modals, TOTP card, auth card.
- **Rail** (dark: `12px 0 32px rgba(0,0,0,.45)`; light: `12px 0 32px rgba(17,18,22,.1)`): the sidebar while it overlays content.

### Named Rules
**The Lightness Ladder Rule.** Depth on the page is ground, then surface, then raised, then high. Reach for the next step before reaching for a shadow; shadows belong only to layers that float.

## Shapes

Generous, soft panels against tight controls. Panels, tables, stat strips and approve cards round at 14px; floating layers (modals, TOTP, auth card) at 16px; inset blocks (banners, callouts, evidence items, tab wells) at 10px; every control (button, input, nav item, icon button, chip-sized meta) at 8px; tags at 6px. Fully round shapes are kept for marks that are points or counts: status dots, count badges, avatars, wallet orbs, the user pill, and the balance panel's quick-action buttons. Borders are always 1px hairlines; there are no heavy rules, offset shadows, or clipped corners.

**The Two Radii Rule.** A container rounds at 14px, the control inside it at 8px. Do not shrink panels toward control radii or round controls toward panels.

## Components

### Buttons
One family in four weights, all 8px radius, 13px/550 labels, 15px inline icons, a 1px press nudge.
- **Shape:** gently rounded (8px); default height 34px, compact 30–32px, block 42px.
- **Neutral:** raised surface fill with a strong hairline; hover steps to surface-high.
- **Primary:** Signal Teal fill, Signal Teal Ink label, no border; hover lightens (dark) or deepens (light).
- **Danger:** danger text over its soft tint with a 28% danger border; for halt and destructive steps.
- **Filter / ghost:** transparent with Ink 2 text; the active filter takes the neutral raised fill.
- **Quick actions (balance panel only):** 38px pill-shaped neutral buttons with a leading arrow glyph; full-width stacked at 44px on phone.
- **Disabled:** 45% opacity, no pointer events.

### Chips and Status
- **Tag:** 22px, 6px radius, 11.5px/550, preceded by a 6px dot in `currentColor`; neutral, ok, warn, danger, info and muted variants each pair the hue with its soft tint.
- **Live dot:** 8px circle with a 3px soft halo in its state hue; used in the top bar, rail foot and collapsed readiness line.
- **Meta chip:** 32px outlined hairline chip in the top bar for node host and health.
- **Counts:** 20px round counts in the rail (warn tint by default, solid danger when urgent).

### Cards / Containers
- **Corner Style:** 14px (16px when floating).
- **Background:** surface, with a 1px hairline border.
- **Shadow Strategy:** Card token at rest; Pop only for floating layers.
- **Internal Padding:** 20px for cards, 22–26px for the balance panel and forms; panels with rows use a 16–18px header and full-bleed hairline-divided rows.
- **Banners:** 10px radius inset blocks; neutral on surface-raised, or state text on its soft tint with a matching translucent border.

### Inputs / Fields
- **Style:** 38px tall, 8px radius, ground fill (inset below its surface), strong hairline border, Ink 4 placeholder.
- **Focus:** border shifts to the teal ring colour plus a 3px teal-soft halo; no outline.
- **Error / Disabled:** invalid fields take a 60% danger border; disabled fields drop to 55% opacity.
- **Labels:** 13px/550 Ink 2 above the field, 6px gap, 16px between fields. TOTP entry uses 44x52px mono slots.

### Navigation
- **Rail items:** 38px, 8px radius, 14px/500 Ink 2 labels with 18px stroke icons; hover takes the hover wash.
- **Active:** surface-raised fill with a 1px hairline inset and Ink 1 text; only the icon turns Signal Teal Text.
- **Collapsed state:** labels fade and slide 4px; a 7px state dot on the icon stands in for the count.
- **Segmented tabs:** a ground-soft well with 30px tabs; the selected tab lifts to surface-high (white with hairline in light) and its count turns teal.

### Balance Panel (signature)
A full-width panel that leads Overview: a small teal-tinted mark and label, an outlined "Observed" pill at top right, the 44px quiet figure with muted fraction and unit, a one-line provenance note with an ok-coloured lead phrase, the quick-action pills, and a hairline-separated row of plain text links.

### Three-Ops Strip (signature)
One panel divided by vertical hairlines into four equal cells: Incoming, Internal transfer, Outgoing, and Halt. Each cell gives a 13.5px label, a mono operation code beneath it, a 30px quiet figure, and a 12.5px muted note.

### Attention Row
Full-bleed hairline-divided row: a 32px 8px-radius tile in the warn (or danger) tint holding a glyph or count, a 13.5px/550 title with a 12.5px muted detail, and an action at the end.

## Do's and Don'ts

### Do:
- **Do** separate surfaces with a lightness step and a 1px hairline before considering a shadow.
- **Do** spend Signal Teal only on primary action, focus, and the active nav icon.
- **Do** set figures at weight 450 with tabular numerals and a muted fraction.
- **Do** carry state as an 8px dot or a 22px tinted chip, in the state hue over its 12% tint.
- **Do** round containers at 14px and controls at 8px.
- **Do** define every new colour role for both `:root/[data-theme="dark"]` and `[data-theme="light"]`.
- **Do** keep primary phone actions at 44px and keep every surface reflowing to 320px.

### Don't:
- **Don't** wash active navigation, rows, or panels in accent; active is a raised neutral fill.
- **Don't** build a tile wall where every number gets an equal card; one figure leads.
- **Don't** fill a panel or banner with a solid state colour.
- **Don't** load a web font or remote asset; the system stacks are required by CSP and tests.
- **Don't** set reading text in Ink 4.
- **Don't** put uppercase eyebrows or kicker lines above headings.
