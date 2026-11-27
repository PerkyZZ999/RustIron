---
version: alpha
name: RustIron Console
description: Dark-first, matte charcoal operations console with restrained royal-blue accents, precise typography, calm hierarchy, and progressive disclosure.
colors:
  primary: "#4169E1"
  dark-canvas: "#101011"
  dark-subtle: "#151516"
  dark-surface: "#1B1B1D"
  dark-raised: "#242426"
  dark-shell: "rgba(27, 27, 29, 0.94)"
  dark-glass-edge: "rgba(255, 255, 255, 0.08)"
  dark-text: "#F0F0F1"
  dark-muted: "#A5A5AA"
  dark-border: "#303033"
  dark-border-strong: "#727278"
  dark-action: "#4169E1"
  dark-action-hover: "#3A60D4"
  dark-on-action: "#FFFFFF"
  dark-focus: "#8AA8FF"
  dark-hover: "#202022"
  dark-pressed: "#2B2B2E"
  dark-disabled-text: "#85858A"
  dark-success-surface: "#19271F"
  dark-error-surface: "#2D1C20"
  dark-scrim: "rgba(0, 0, 0, 0.64)"
  dark-selection: "#23252B"
  dark-glow: "rgba(65, 105, 225, 0.12)"
  dark-glow-ambient: "rgba(65, 105, 225, 0.00)"
  dark-success: "#63D397"
  dark-warning: "#F2BD58"
  dark-warning-surface: "#292317"
  dark-error: "#FF8F9A"
  dark-cpu: "#7B9CFF"
  dark-memory: "#B19BFF"
  dark-disk: "#63D397"
  light-canvas: "#F5F7FB"
  light-surface: "#FFFFFF"
  light-subtle: "#EEF2F8"
  light-shell: "rgba(245, 248, 255, 0.94)"
  light-glass-edge: "rgba(17, 24, 39, 0.08)"
  light-text: "#111827"
  light-muted: "#526178"
  light-border: "#DCE3EE"
  light-border-strong: "#7A889D"
  light-action: "#4169E1"
  light-action-hover: "#3155C7"
  light-on-action: "#FFFFFF"
  light-focus: "#3155C7"
  light-selection: "#E7EFFF"
  light-glow: "rgba(65, 105, 225, 0.10)"
  light-glow-ambient: "rgba(65, 105, 225, 0.00)"
  light-success: "#137A45"
  light-warning: "#8A5600"
  light-warning-surface: "#FFF7E8"
  light-error: "#B42336"
  light-cpu: "#3155C7"
  light-memory: "#7950C8"
  light-disk: "#137A45"
typography:
  headline:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 28px
    fontWeight: 600
    lineHeight: 36px
    letterSpacing: -0.02em
  section:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 18px
    fontWeight: 600
    lineHeight: 24px
    letterSpacing: -0.01em
  body:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 16px
    fontWeight: 400
    lineHeight: 24px
  compact:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 14px
    fontWeight: 400
    lineHeight: 20px
  label:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 14px
    fontWeight: 500
    lineHeight: 20px
  caption:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 12px
    fontWeight: 500
    lineHeight: 16px
    letterSpacing: 0.01em
  metric:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: 32px
    fontWeight: 600
    lineHeight: 40px
    letterSpacing: -0.02em
    fontFeature: '"tnum" 1, "lnum" 1'
  code:
    fontFamily: 'ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace'
    fontSize: 13px
    fontWeight: 400
    lineHeight: 20px
rounded:
  none: 0px
  control: 8px
  panel: 12px
  pill: 9999px
spacing:
  xs: 4px
  sm: 8px
  compact: 12px
  md: 16px
  lg: 24px
  xl: 32px
  section: 48px
motion:
  state-change:
    duration: 100ms
    delay: 0ms
    timingFunction: ease-out
  disclosure:
    duration: 160ms
    delay: 0ms
    timingFunction: ease-in-out
  surface-enter:
    duration: 200ms
    delay: 0ms
    timingFunction: cubic-bezier(0.2, 0, 0, 1)
  surface-exit:
    duration: 160ms
    delay: 0ms
    timingFunction: ease-in
components:
  button-primary-dark:
    backgroundColor: "{colors.dark-action}"
    textColor: "{colors.dark-on-action}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  button-primary-dark-hover:
    backgroundColor: "{colors.dark-action-hover}"
    textColor: "{colors.dark-on-action}"
  button-secondary-dark:
    backgroundColor: "{colors.dark-raised}"
    textColor: "{colors.dark-text}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  button-destructive-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-error}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  input-dark:
    backgroundColor: "{colors.dark-subtle}"
    textColor: "{colors.dark-text}"
    typography: "{typography.compact}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  navigation-selected-dark:
    backgroundColor: "{colors.dark-selection}"
    textColor: "{colors.dark-text}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
  glass-shell-dark:
    backgroundColor: "{colors.dark-shell}"
    textColor: "{colors.dark-text}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "{spacing.compact}"
  glass-summary-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-text}"
    typography: "{typography.metric}"
    rounded: "{rounded.panel}"
    padding: "{spacing.md}"
  popover-dark:
    backgroundColor: "{colors.dark-raised}"
    textColor: "{colors.dark-text}"
    typography: "{typography.compact}"
    rounded: "{rounded.panel}"
    padding: "{spacing.sm}"
  data-panel-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-text}"
    typography: "{typography.compact}"
    rounded: "{rounded.panel}"
    padding: "{spacing.md}"
  data-panel-dark-meta:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-muted}"
    typography: "{typography.caption}"
  attention-dark:
    backgroundColor: "{colors.dark-warning-surface}"
    textColor: "{colors.dark-warning}"
    typography: "{typography.compact}"
    rounded: "{rounded.control}"
    padding: "{spacing.md}"
  state-unknown-dark:
    backgroundColor: "{colors.dark-subtle}"
    textColor: "{colors.dark-muted}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  state-success-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-success}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  state-error-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-error}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  roadmap-label-dark:
    backgroundColor: "{colors.dark-selection}"
    textColor: "{colors.dark-focus}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  code-block-dark:
    backgroundColor: "{colors.dark-canvas}"
    textColor: "{colors.dark-text}"
    typography: "{typography.code}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
  metric-summary-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-text}"
    typography: "{typography.metric}"
    rounded: "{rounded.panel}"
    padding: "{spacing.lg}"
  table-header-dark:
    backgroundColor: "{colors.dark-subtle}"
    textColor: "{colors.dark-muted}"
    typography: "{typography.label}"
    height: 40px
  table-row-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-text}"
    typography: "{typography.compact}"
    height: 44px
  table-row-dark-hover:
    backgroundColor: "{colors.dark-hover}"
    textColor: "{colors.dark-text}"
  button-secondary-dark-hover:
    backgroundColor: "{colors.dark-pressed}"
    textColor: "{colors.dark-text}"
  button-disabled-dark:
    backgroundColor: "{colors.dark-subtle}"
    textColor: "{colors.dark-disabled-text}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    height: 40px
  state-warning-dark:
    backgroundColor: "{colors.dark-warning-surface}"
    textColor: "{colors.dark-warning}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  dialog-dark:
    backgroundColor: "{colors.dark-raised}"
    textColor: "{colors.dark-text}"
    typography: "{typography.body}"
    rounded: "{rounded.panel}"
    padding: "{spacing.lg}"
  button-primary-light:
    backgroundColor: "{colors.light-action}"
    textColor: "{colors.light-on-action}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  button-primary-light-hover:
    backgroundColor: "{colors.light-action-hover}"
    textColor: "{colors.light-on-action}"
  button-secondary-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-text}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  button-destructive-light:
    backgroundColor: "{colors.light-error}"
    textColor: "{colors.light-on-action}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  input-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-text}"
    typography: "{typography.compact}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
    height: 40px
  navigation-selected-light:
    backgroundColor: "{colors.light-selection}"
    textColor: "{colors.light-focus}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "{spacing.compact}"
  glass-shell-light:
    backgroundColor: "{colors.light-shell}"
    textColor: "{colors.light-text}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "{spacing.compact}"
  data-panel-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-text}"
    typography: "{typography.compact}"
    rounded: "{rounded.panel}"
    padding: "{spacing.md}"
  data-panel-light-meta:
    backgroundColor: "{colors.light-subtle}"
    textColor: "{colors.light-muted}"
    typography: "{typography.caption}"
  attention-light:
    backgroundColor: "{colors.light-warning-surface}"
    textColor: "{colors.light-warning}"
    typography: "{typography.compact}"
    rounded: "{rounded.control}"
    padding: "{spacing.md}"
  state-success-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-success}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
  state-error-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-error}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xs}"
---

# RustIron Console design system

## Overview

Updated 2026-11-25. RustIron Console is a dark-first operations workspace for
hosting and server administrators. Its visual identity is **Matte Charcoal /
Royal Blue**: near-black foundations, neutral graphite surfaces, quiet borders,
precise typography, and a single restrained brand accent. It should feel like a
premium professional instrument, not a gaming UI, a marketing landing page, or
a generic analytics dashboard.

The experience is calm, deliberate, and trustworthy. Operators should be able to
scan the health of a host in seconds, find the next meaningful action without
hunting, and inspect technical evidence without being overwhelmed by it.

**Design authority and scope.** The YAML tokens in this file are the target
visual contract; the prose defines their usage. Read the [design brief](DESIGN-BRIEF.md)
and [information architecture](INFORMATION-ARCHITECTURE.md) alongside it. The
refined mockup is the first implementation target, not permission to modify the
production Console. The production Console moved from Astryx to the Coss UI
stack in W642, as the owner directed on 2026-11-26. Light-theme compatibility is
not removed by this document. Resolve discrepancies with the project owner
before migrating production or changing product capabilities.

**Design principles**

1. **Charcoal first.** Nearly all permanent surfaces are achromatic. Use tonal
   depth and whitespace instead of color to organize the workspace.
2. **Blue is a signal, not decoration.** Royal blue identifies the most important
   action, current location, or keyboard focus. A view without a primary action
   may have no filled blue control at all.
3. **Matte by default.** Solid, readable surfaces are the norm. Frosted glass is
   optional for floating chrome only; no decorative gradients or ambient glow.
4. **Clarity before density.** Make the essential state and next action obvious;
   reveal details on demand. Never hide risk, uncertainty, impact, or approval.
5. **Operational truth.** Observation, intent, admission, execution, and verified
   outcome are distinct. Never imply success before verification.
6. **One privileged-change pattern.** Reuse plan review, approval handoff, and
   operation tracking across every feature area.

Preserve the functional composition of the existing [Host Overview mockup](mockup/screens/overview.html):
left navigation, compact utilities, four leading metrics, resource history,
conditional attention, and supporting summaries. Treat its styling as historical
reference, not as a requirement to reproduce the old visual treatment.

The default refined prototype is dark. Light remains a secondary compatibility
theme, with its existing palette retained except for restrained translucent and
glow roles. Do not prioritize light-theme design over the dark experience.

## Colors

**Dark foundation.** The surfaces form a deliberately near-achromatic ramp.
Small tonal steps are intentional; use meaningful spacing and borders to separate
regions rather than increasing saturation.

| Token | Hex | Role |
| --- | --- | --- |
| `dark-canvas` | #101011 | Near-black page and recessed log canvas |
| `dark-subtle` | #151516 | Inset controls, table headers and sidebar |
| `dark-surface` | #1B1B1D | Matte content panels and cards |
| `dark-raised` | #242426 | Floating menus, dialogs, secondary controls |
| `dark-hover` | #202022 | Quiet row and navigation hover |
| `dark-pressed` | #2B2B2E | Pressed neutral controls |
| `dark-border` | #303033 | Decorative separators and panel edges |
| `dark-border-strong` | #727278 | Meaningful control boundaries |
| `dark-text` | #F0F0F1 | Primary content |
| `dark-muted` | #A5A5AA | Secondary content and metadata |

Use near-black rather than absolute black for large surfaces. Do not use navy,
indigo, blue-gray, or purple as the base palette. The dark border is decorative;
where a boundary is needed to identify a control, use the strong border.

**Royal blue.** Keep the existing RustIron brand hue `primary` / `dark-action`
(#4169E1). Use white (`dark-on-action`) on filled primary controls, #3A60D4 on
hover, and the lighter #8AA8FF (`dark-focus`) for accessible links and focus
indicators. Selected navigation uses the nearly neutral `dark-selection`
(#23252B), normal text, and a narrow 2px accent marker. Active tabs use a thin
underline, not a filled pill. Prefer neutral secondary controls and monochrome
icons. The visual goal is roughly 90–95% neutral surfaces; this is a review
heuristic, not a measured quota or a reason to suppress accessibility indicators.

Blue is reserved for the view's primary action (when one exists), active location,
focus, links, and small preview identifiers. Never fill a large panel, sidebar,
chart background, or ordinary icon with brand blue. Use `dark-focus` rather than
raw brand blue for small text on charcoal. Semantic and chart colors are separate
from the brand accent and must not be repurposed for decoration.

**States.** States map to dedicated roles, always with a text label and an icon:

| State | Role | Examples |
| --- | --- | --- |
| Pass, succeeded, verified, installed | `success` text | Evidence field `pass`, operation `succeeded` |
| Warning, needs attention, expiring, stale | `warning` on `warning-surface` | Diagnosis `warn`, `needs_attention`, certificate `expires_soon` |
| Fail, refused, quarantined, digest mismatch | `error` text | Diagnosis `fail`, operation `failed`, quarantined site |
| Unknown, not run, not checked, not recorded | `muted` on `subtle` | Evidence field `not_run`, diagnosis `unknown` |
| Admitted, running, awaiting signature | `text` on `subtle` with an indeterminate mark | Operation `running` |

**Ownership.** Use text and border style, not new hues. Owned resources have a
solid `border-strong` outline. Observed, declared, and imported facts have a
dashed outline. Protected resources (the shipped OLS parent, mail records) add
a lock glyph. Ejected resources use the unknown treatment with their label.

**Charts.** CPU blue (`dark-cpu`), memory violet (`dark-memory`), disk green
(`dark-disk`) in both themes, with solid, dashed, and dotted lines, a labeled
legend, and a table equivalent. Gridlines use `dark-border`. Fills under lines
are at most 12% opacity. Missing samples are gaps, not zeros. The disk color
does not mean disk health. A further series uses `text` with a distinct line
style until a reviewed token exists.

**Light theme (secondary).** Retain the existing `light-*` compatibility palette.
Use equivalent semantic roles and the same restrictions on accent, hierarchy,
and translucency. Its preservation does not require a second design direction.

**Contrast.** Target WCAG 2.2 AA: at least 4.5:1 for normal text, 3:1 for large
text, and 3:1 for required non-text boundaries and focus indicators against
adjacent colors. Check all actual states and composited surfaces, not just token
pairs. The source document refers to `scripts/check_docs.py`; run it in the
repository alongside the DESIGN.md linter and browser accessibility checks.
Do not claim implementation accessibility based on token contrast alone.

## Typography

Use the system sans stack, with tabular figures for metrics and the monospace
stack only for identifiers, digests, signed bytes, commands, record values, and
log lines. No web font is loaded. A self-hosted font (for example a modern
grotesk) is an open owner choice; it needs a license and size review first.

| Role | Use |
| --- | --- |
| `headline` 28/36 semibold | Page title, one per page |
| `section` 18/24 semibold | Panel and drawer titles |
| `metric` 32/40 semibold, tabular | The four leading values and other headline numbers |
| `body` 16/24 | Explanations, plan review, help text |
| `compact` 14/20 | Tables, forms, details |
| `label` 14/20 medium | Buttons, chips, tabs, navigation |
| `caption` 12/16 medium | Sidebar group labels, units, timestamps, secondary metadata |
| `code` 13/20 mono | IDs, digests, commands, logs |

Tight negative tracking on large type and plain tracking on small type gives the
clean, modern look; do not add uppercase microtype as decoration. Captions never
carry a warning, a risk, or approval text. Keep long reading lines to approximately 60–75 characters.
Use sentence case, units, and locale-aware numbers. IDs and digests can shorten
visually with a copy button and an accessible full value.

## Layout

**Rhythm.** 4px base, 8px primary rhythm, and the spacing steps in the tokens.
The shell has a 224px sidebar and a 64px top bar; pages have 24px padding,
16px gaps between panels, and stop at 1600px. Plan review and other long
reading use one column of at most 760px.

**Shell.** The sidebar groups items under `caption` labels: Overview; Hosting;
Domains and mail; Safety; Host. Settings and Help sit at the bottom with the
operator and session label. A section is hidden until its roadmap item is
delivered. The top bar holds the breadcrumb, Search, Notifications, the theme
control, and host context (host label, executor enrollment, observation age).

**Disclosure levels.** Every screen uses the same three levels:

| Level | Where | Holds |
| --- | --- | --- |
| 1. Summary | The page itself | Identity, current state, key numbers, attention items, the primary action |
| 2. Details | Inline expansion or the right-side inspector drawer | Source, freshness, scope, limits, related records, the safe next step |
| 3. Evidence | Its own record page | Full redacted observation, history, signed bytes, IDs, export |

A row or card opens level 2 in place; a quick look never navigates away. The
inspector drawer is 420px wide on desktop, solid by default, optionally frosted only at its outer chrome, and
its state is in the URL (`?inspect=<id>`) so Back closes it. Every level-2 view
links to its level-3 page. Level 1 always shows blocking risk, uncertain
outcomes, global impact, and the need for approval.

**Resource pages.** Breadcrumbs, a resource header (name, state chip, ownership
badge, freshness, one Actions menu), a tab row, then the tab content. Host uses
the tab row without an Actions menu.

**Breakpoints.** 1280px, 900px, and 640px. Above 1280px: four metric summaries
in one row, one wide chart, the attention strip when warranted, four compact
summaries. From 900px to 1280px: two columns; the inspector overlays the
content. Below 900px: the sidebar becomes a labeled drawer. Below 640px: one
column; tabs become a labeled select; the inspector is a full-height sheet; plan
review is a full page. Never keep four columns by shrinking text. Check 320,
768, 1024, and 1440+ CSS pixels and zoom.

Most views have at most one primary action. Host Overview is inspection only.
Use an unboxed page header, restrained supporting description, and grouped
content instead of a card for every piece of information. Keep 24px page gutters
on desktop, 16px on narrow screens, and 24–32px between unrelated sections.
Prefer full-width tables and purposeful split views over grids of tiny cards.
Avoid repeating page titles, redundant badges, explanatory paragraphs on every
card, and oversized metric typography in dense detail views. A label, value,
and optional disclosure usually suffice. Preserve discoverability of secondary
actions with visible, labeled controls; do not rely on hover alone. Preserve
filters, time range, open disclosures, and scroll position across drilldown and
Back.

## Elevation & Depth

**Matte tonal elevation.** The flat near-black canvas and three charcoal surface
steps provide depth. Resting panels have a thin neutral border, no shadow, no
gradient, and no colored halo. Use whitespace and alignment before introducing a
new container. Do not nest cards simply to create hierarchy.

**Optional frosted chrome.** Solid surfaces are preferred for the sidebar, top
bar, Overview metric cards, attention strip, and all primary content. For floating
menus, search overlays, or an inspector's outer frame only, `dark-shell` may be
used at 94% opacity with `backdrop-filter: blur(12px) saturate(100%)` and a 1px
`dark-glass-edge` border. Text-heavy interiors remain solid. Never nest blur or
apply it to tables, logs, forms, charts, evidence, signed bytes, or plan text.
Use solid `dark-raised` when blur is unsupported, reduced transparency is
requested, or composited contrast is not verified. The `glass-summary-dark`
legacy token is retained for migration but resolves to a solid surface; use
`metric-summary-dark` for new work.

**Accent restraint.** No ambient radial gradients, neon, animated glow, or
mandatory glowing buttons. The default primary button is flat. `dark-glow` is
retained as an optional, low-opacity legacy brand effect and is not needed by
new components. Use a crisp 2px `dark-focus` ring with a 2px offset, not a glow,
for keyboard focus. Keep a visible indicator in forced-colors mode.

**Floating layers.** Use `0 16px 40px rgba(0, 0, 0, 0.45)` only for floating dark
surfaces; use `0 12px 32px rgba(15, 23, 42, 0.12)` in light. Modal scrims use
`dark-scrim`. Keep top bar 100, scrim 150, drawer 200, skip link 300; dialogs use
the native top layer or an equivalent accessible overlay system.

## Shapes

Controls, inputs, selected navigation, code blocks, and compact notices use
`rounded.control` (8px). Panels, cards, drawers, menus, and dialogs use
`rounded.panel` (12px). Viewport-aligned shell edges stay square. Full rounding
is only for state chips, roadmap labels, ownership badges, and toggles. Buttons
are never pills.

## Motion & Micro-interaction

Motion is quick, functional, and understated. Use the YAML `motion` tokens:
100ms for local state changes, 160ms for disclosures and exits, and 200ms for
entering floating surfaces. Use opacity and transform where appropriate; avoid
animating layout, unnecessary spring effects, or delayed interaction feedback.
Lucide animated icons are reserved for useful interaction feedback, not idle
navigation or decoration. Indeterminate activity indicators may animate while
work is actually pending; do not fabricate progress or animate verified status.
Honor `prefers-reduced-motion` by removing nonessential transitions and replacing
moving indicators with accessible static equivalents when appropriate. Never
announce each metric tick or shift focus merely because data refreshes.

## Voice & Content Strategy

**Voice:** precise, calm, concise. RustIron speaks like a professional operations
console. Use sentence case, direct verbs, and consistent domain terminology:
host, site, observation, plan, grant, operation, and evidence. Do not substitute
"deployment succeeded" for "admitted" or "healthy" for "not observed".

Use outcome-specific action labels ("Create plan", "Inspect evidence", "Revoke
session") rather than generic "Submit" or "OK". Explain consequences adjacent to
risky actions. Use one concise sentence for an empty or unavailable state and
provide the safe next step when one exists. Error messages state what failed,
what is known, and what the operator can do next; keep diagnostic codes available
without crowding the primary message. Distinguish simulated data in the prototype
from real observations. Show units with values, tabular numerals for metrics,
locale-aware dates and numbers, and an accessible exact timestamp alongside
relative freshness. Use exact identifiers and copy affordances where needed.

## Components

### Shell and icons

For the refined interactive mockup, use **Coss UI** as the component foundation,
React with TypeScript, TanStack Start as the preferred application framework, and
Tailwind CSS v4 for styling. Consult the [Coss UI documentation](https://coss.com/ui/llms.txt)
and the project owner's Coss UI skill. Map semantic tokens into the component
library and Tailwind theme; do not introduce a competing palette or copy default
library styling unchanged. Use the required frontend, iconography, and web design
Agent Skills from the redesign task. Evlog integration belongs in the prototype
implementation, not the visual token schema.

The production Console uses this stack since W642, and the
[technical stack](technical/TECH-STACK.md) records it. Do not silently rewrite
unrelated architecture or security requirements.

The wordmark is RustIron; a final logo is unselected. Use one provisional server
glyph. Use `lucide-react` for navigation and actions, with consistent 1.75–2px
stroke, 20px navigation icons, and 16px inline icons. Use `lucide-animated` only
for purposeful motion, consistent with the motion rules. Default icons are
`dark-muted`; active icons are `dark-text` with the accent marker carrying the
selection. DevIcons are only for real technologies (WordPress, PHP, MariaDB,
OpenLiteSpeed, and later Node.js, Bun, and PowerDNS). Pair icons with text where
meaning is not obvious; icon-only controls require an accessible name and a
tooltip where useful.

### Actions and inputs

Buttons are 40px tall; on touch layouts their hit area is at least 44px.
**Primary:** royal blue with white text, flat fill, at most one per view.
**Secondary:** `dark-raised` with a neutral outline (`border-strong` when required for identification). **Text button:**
`dark-focus` text, no fill. **Destructive:** in dark, `error` text on `surface`
with an `error` outline; in light, filled `light-error`. Every destructive
button has a consequence sentence next to it. Eject is not destructive; it is a
secondary button.

Show hover, pressed, focus, disabled, pending, selected, success, and failure.
Inputs sit on `dark-subtle` with a `border-strong` outline, which turns blue with
the focus ring. Labels sit above the field; errors sit under it and name the
fix. Never use placeholder text as the label, and never disable paste.

**Actions menu.** One labeled button per resource header lists the delivered
actions for that resource with a one-line effect ("Activate configuration ·
reloads every site"). An action that is not delivered is not listed.

**Bounded parameter form.** Typed fields only: selects for closed choices,
validated hostnames and names, numbers with units and limits. No path, command,
directive, or SQL field. The only submit is **Create plan**.

**Secret field.** Write-only and masked, with the reference name and last
rotation time. It never shows or copies a stored value.

### Plan review and approval handoff

Level 1 of plan review is the effects summary: affected resources, global reload
impact, downtime and data-loss exposure, expiry, compensation, and the budget
the plan consumes. Then preconditions, then steps (level 2), then the canonical
bytes (level 3).

The approval handoff follows the real signing procedure
([operator key](operator/05-OPERATOR-KEY.md)). The operator reviews the plan
with `rustiron-plan inspect` (and `rustiron-review` for the verbs it covers),
signs the exact `grant.json` bytes outside the browser with
`ssh-keygen -Y sign -n rustiron-plan-v1`, and submits `grant.json.sig`. The
handoff panel shows the plan digest, the grant's `plan_digest`, the expiry, a
code block with those commands, and the signature input. After submit it shows
the executor's result: admitted, or refused with its code (`INVALID_SIGNATURE`,
`STALE_PLAN`, `GRANT_EXPIRED`, `GRANT_REPLAY`, and others). The browser never
holds or creates a key. The sticky footer around this step is solid and separated by a neutral border.

The signed bytes panel shows the stored plan and grant bytes, digests recomputed
in the browser, and the SSHSIG result. A mismatch shows "Digest mismatch" in the
error state.

### Summaries, metrics, tables, and history

A metric summary shows value and unit, capacity where known, observation time,
and a Details disclosure. Use `metric-summary-dark` on Overview and solid panels elsewhere. A missing value shows "Not observed", never 0.

Tables sit on solid `surface` with a `subtle` header row, 44px rows, and
`border` dividers. Numbers align right. A row opens its details in the
inspector; the row name links to its record page. Stable row identity, bounded
pagination, and empty, no-match, and unavailable states are required. On small
screens keep a scrolling region with identity and state columns pinned.

The history chart has a labeled range control and documented aggregation. Do not
add a chart library before a real data need is known
([TECH-STACK](technical/TECH-STACK.md)).

### Findings, certificates, schedules, and jobs

A **diagnosis finding** shows its state (`fail`, `warn`, or `unknown`), the
check, the subject in monospace, and the owner (`rustiron` or `host`). Its
details show the fixed reason and action text. `ok` checks collapse into one
"Passed checks" disclosure.

A **certificate card** shows the single hostname, the not-after date, the end of
the renewal window (`renew_until`), who renews it (RustIron, or the operator
after an eject), and the last issuance or renewal result. `expires_soon` and
`renewal_failed` use warning; `expired` uses error.

A **scheduled capture card** shows the standing grant's named sites, capture
windows used and remaining, missed windows, the newest snapshot age, and the
expiry, as text. No progress rings.

The **WordPress jobs** panel shows the host timer's state and its last and next
trigger, and states the limits: jobs run in the site's own PHP pool without
network access, and ejected or adopted sites are not asked.

### Attention, operations, deployments, and recovery

The attention strip is a solid, compact notice that states the condition, scope,
age, and next inspection. Use a semantic accent only when warranted. Dismissing it does not clear a host condition.

Operation timelines show each step's intent, observation, and verification, and
the operation state (`admitted`, `running`, `succeeded`, `failed`,
`compensating`, `failed_compensated`, `needs_attention`, `rejected`, or
`untouched`). Unknown progress is indeterminate. No invented percentages, no
Retry all, no universal Undo. A `needs_attention` operation shows its blocked
resources and the documented recovery command and runbook. Imports, renewals,
and later app deployments reuse this timeline.

Recovery shows all seven evidence fields as separate chips, never one score, and
the receipt attestation (`self-attested, signed` or `self-attested, unsigned`).
A capture never implies a tested recovery.

### Logs and records

The log viewer is read-only, monospace on `dark-canvas`, time-bounded, redacted,
and states its source, range, and truncation. A live tail needs a pause control.
DNS record tables group records by ownership; protected mail records show the
lock glyph.

### Sign-in and security

Sign-in is a single solid panel centered on the matte canvas, with the host
label, the method, and the second-factor step. Errors never say which factor
failed. Session lists show device, start, last activity, and a revoke button.

### Disclosure, feedback, and accessibility

Inline disclosures use real buttons with `aria-expanded`. The inspector drawer
is nonmodal and does not trap focus; dialogs trap and restore it. Announce
significant state changes politely, not every metric tick. Charts have text and
data equivalents. Use localized skeletons on first load, keep valid data with a
stale label during refresh, and explain empty, unavailable, refused,
not-enrolled, and error states with a safe next step.

## Do's and Don'ts

- Do build on neutral charcoal; do not drift the surfaces toward navy or pure black.
- Do keep royal blue to primary action, location, focus, links, and preview identifiers; keep ordinary icons and large surfaces neutral. Preserve independent semantic and chart roles.
- Do use at most one flat primary button per view; do not add neon, pulsing, decorative glows, or background gradients.
- Do use solid matte surfaces by default; reserve optional frosted chrome for floating overlays. Never place dense content on glass or nest blur.
- Do show summary first, details in place, and evidence on its own page; do not hide risk, uncertainty, global impact, or approval behind a disclosure.
- Do pair every state with text, an icon, time, and scope; do not use color or a list of green jobs as proof.
- Do show owned, observed, and protected resources differently; do not make an imported resource look managed.
- Do send every privileged write through plan review and the real signing handoff; do not draw a Save button that applies an effect.
- Do label preview screens with their roadmap item; do not list undelivered actions or sections in the product.
- Do keep chart meanings across themes; do not swap memory and disk colors.
- Do not add a terminal, SQL console, generic command field, or caller-selected path anywhere.
- Do use whitespace, alignment, and concise copy before adding cards, labels, or badges.
- Do map Coss UI and Tailwind CSS v4 to the same tokens in the refined prototype; do not change the production stack without approval.
- Do use realistic simulated states in the prototype; never trigger real privileged changes or present simulated results as verified host evidence.
- Do test keyboard, screen reader, reflow, supported themes, and composited glass contrast in the implementation; do not claim those tests ran from this document.
