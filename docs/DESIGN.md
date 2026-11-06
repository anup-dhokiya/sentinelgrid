# SentinelGrid // Enterprise Design System Specification (DESIGN.md)
**Project:** SentinelGrid Autonomous WAAP & Threat Telemetry Platform  
**Design Classification:** High-Density Developer Tooling & Security Operations Console  
**Mode:** *Operate* (Precision, Scanability, Restraint, Zero Fluff)

---

## 1. Visual Philosophy: The "Anti-AI-Slop" Manifesto

Most modern AI-generated interfaces look identical because they recycle the same five visual tropes: generic card grids, gradient text, neon colored glows, cartoon emojis in buttons, and template spacing.

SentinelGrid is engineered with an entirely different aesthetic: **The Tactical Security Kernel & Archival Dossier**. It draws inspiration from high-density professional developer tools (**Linear, Cloudflare, Tailscale, Datadog, Raycast**) combined with the timeless craft of **archival typography and cryptographic ledger design**.

```
                  ┌───────────────────────────────────────────────┐
                  │          THE ANTI-AI-SLOP RULES               │
┌─────────────────┴───────────────────────────────────────────────┴─────────────────┐
│ 1. NO EMOJIS AS ICONS: All icons are authored, pixel-aligned 16px vector SVGs.   │
│ 2. NO GRADIENT HEADINGS: Hierarchy comes from weight, size, and letter-spacing.  │
│ 3. NO 3PX CARD TOP-STRIPES: No decorative colored borders standing in for data. │
│ 4. NO ZERO-OFFSET NEON GLOWS: Shadows carry realistic physical offset and blur.  │
│ 5. NO UNSTYLED BROWSER DEFAULTS: Custom scrollbars, selection, and focus rings. │
│ 6. TABULAR NUMBERS EVERYWHERE: Real-time telemetry figures never jump or jitter. │
│ 7. KEYBOARD-FIRST ACCESSIBILITY: Hotkeys for every primary operator interaction. │
│ 8. HIGH INFORMATION DENSITY: Generous horizontal span; zero artificial clamps.   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dual-World Color Architecture

SentinelGrid rejects both sterile `#FFFFFF` Bootstrap light modes and generic bluish `#1E293B` Tailwind slates. Instead, it defines two purposeful, high-contrast visual worlds:

### World 1: Archival Parchment & Ink (Light Mode)
*Inspired by high-grade financial ledgers, cryptographic whitepapers, and intelligence dossiers.*

| Token Variable | Hex Value | Role & Usage | Contrast Ratio |
| :--- | :--- | :--- | :--- |
| `--canvas-bg` | `#EFE9DF` | Primary application canvas (warm unbleached flax) | Base surface |
| `--card-white` | `#FAF6EE` | Card & panel surface (almond linen paper) | 1.15:1 to canvas |
| `--sand-warm` | `#E6DECE` | Recessed wells, table headers, and toolbars | Contrast well |
| `--sand-warm-hover` | `#DDD2BF` | Tactile vellum interactive hover state | Interactive |
| `--stone-border` | `#CFBFAB` | Hairline panel & card border (muted sandstone) | 2.2:1 to card |
| `--stone-border-light`| `#DFD3C2` | Internal subtle table row & list dividers | Subtle rim |
| `--text-charcoal` | `#1C1712` | Primary headlines & metrics (deep obsidian soot ink) | **14.8:1 (AAA)** |
| `--text-muted` | `#564B3E` | Secondary metadata & labels (weathered walnut ink) | **6.8:1 (AAA)** |
| `--text-subtle` | `#7A6C5B` | Tertiary timestamps & guides (antique seal ink) | **4.6:1 (AA)** |
| `--deep-indigo` | `#1B365D` | Primary brand accent (Oxford midnight sapphire) | **10.2:1 (AAA)** |
| `--terracotta` | `#9C2A1B` | Intercepted threat / Quarantined IP (sealing wax red)| **6.9:1 (AAA)** |
| `--sage-green` | `#1B633E` | Clean verified request / Allowed status (forest sage) | **7.1:1 (AAA)** |
| `--warm-ochre` | `#8C4A0E` | Suspicious probe / Challenge status (raw sienna amber) | **6.4:1 (AAA)** |

### World 2: Precision Obsidian & Carbon (Dark Mode)
*Inspired by Bloomberg terminals, kernel debuggers, and dark SOC consoles.*

| Token Variable | Hex Value | Role & Usage | Contrast Ratio |
| :--- | :--- | :--- | :--- |
| `--canvas-bg` | `#0B0E14` | Primary console background (deep void carbon) | Base surface |
| `--card-white` | `#12171F` | Panel & container surface (slate carbon) | 1.2:1 to canvas |
| `--sand-warm` | `#1A2230` | Recessed toolbars, wells & code block surfaces | Contrast well |
| `--sand-warm-hover` | `#222C3D` | Interactive hover highlight | Interactive |
| `--stone-border` | `rgba(255, 255, 255, 0.08)` | Delicate hairline border | Subtle rim |
| `--border-accent` | `rgba(56, 189, 248, 0.35)` | Focused element sapphire border | Interactive |
| `--text-charcoal` | `#F0F6FC` | Primary text & data (ice white) | **15.2:1 (AAA)** |
| `--text-muted` | `#94A3B8` | Secondary labels & metadata (cool slate) | **6.2:1 (AAA)** |
| `--text-subtle` | `#8B9BB4` | Timestamps & hints | **4.8:1 (AA)** |
| `--deep-indigo` | `#38BDF8` | Primary active accent (precision cyan-sapphire) | **9.8:1 (AAA)** |
| `--terracotta` | `#F85149` | Threat interception / Blocked request (crimson) | **5.8:1 (AA)** |
| `--sage-green` | `#3FB950` | Clean traffic allow (emerald) | **7.5:1 (AAA)** |
| `--warm-ochre` | `#F59E0B` | Challenge / Rate-limit alert (amber) | **8.1:1 (AAA)** |

---

## 3. Typographic Hierarchy & Typesetting Rules

### 3.1 Font Stack
```css
--font-ui: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
--font-mono: 'Space Mono', 'JetBrains Mono', SFMono-Regular, Menlo, Monaco, Consolas, monospace;
```

### 3.2 Type Scale
- **Display Numerals (`26px – 28px`, Weight: 800, `font-mono`):** Used strictly for high-priority KPI metrics. **Rule:** Must always include `font-variant-numeric: tabular-nums; letter-spacing: -0.5px;`.
- **Section Headers (`16px – 18px`, Weight: 800, `font-ui`):** Used for workspace headers. **Rule:** Always accompanied by a live status indicator dot or record count badge.
- **Table Data & Interactive Text (`12px – 13px`, Weight: 500 / 600, `font-ui`):** Body copy, select dropdowns, and button labels.
- **Telemetry & Technical Tags (`10px – 11px`, Weight: 700, `font-mono`):** IP addresses, HTTP methods (`GET`, `POST`), URIs, rule IDs, and relative timestamps. **Rule:** Monospace is never a decoration; it is reserved for verifiable technical strings.

---

## 4. Layout Architecture & Spatial Density

### 4.1 Layout Shell Structure
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ [APP-TOPBAR]: Brand Icon • Website Selector • Telemetry Latency • Clock • Theme  │
├───────────────┬─────────────────────────────────────────────────────────────────┤
│ [APP-SIDEBAR] │ [APP-MAIN]                                                      │
│ 68px or 250px │                                                                 │
│               │ ┌─────────────────────────────────────────────────────────────┐ │
│ 16px SVG Nav  │ │ KPI TELEMETRY GRID (4 Tiles: Routes, Shadow, Drops, Ledger) │ │
│ Dockable      │ └─────────────────────────────────────────────────────────────┘ │
│ Tooltips      │ ┌─────────────────────────────────────────────────────────────┐ │
│ Hotkey hints  │ │ REAL-TIME TELEMETRY STREAM TABLE (Full-Bleed or Standard)   │ │
│               │ └─────────────────────────────────────────────────────────────┘ │
└───────────────┴─────────────────────────────────────────────────────────────────┘
```

### 4.2 Breakpoints & Fluid Adaptation
- **Mobile (< 768px):**  
  - Sidebar automatically converts to an off-canvas drawer (`transform: translateX(-100%)`) with backdrop overlay.
  - Form controls and filter bars stack vertically (`flex-direction: column; align-items: stretch`).
  - Inputs enforce `font-size: 16px !important` to prevent iOS auto-zoom disruptions.
  - Tables maintain horizontal swipeability with `-webkit-overflow-scrolling: touch;`.
- **Tablet (768px – 1024px):**  
  - Sidebar docks to compact icon-only mode (`width: 68px`).
  - KPI tiles collapse from 4 columns to a balanced 2×2 grid.
- **Large Desktop (> 1440px / 1600px):**  
  - Standard mode centers at `max-width: 1720px`.
  - **Live Traffic Wide View:** When toggled, `.app-main` expands to **100% full-bleed**, the sidebar docks to 68px, and the live request inspection table occupies the entire monitor width.

---

## 5. Component Design Specifications

### 5.1 Sidebar Navigation
- **Dimensions:** Default `250px`, docked `68px`.
- **Iconography:** Authored 16px geometric SVGs with `stroke-width: 2px` and `stroke: currentColor`.
- **Active State:** Clean solid accent well (`--sand-warm`) with an inset left indicator bar (`width: 3px; height: 18px; border-radius: 9999px`).
- **Collapsed Mode:** Text labels hide with `display: none`; icons center cleanly with native browser tooltips (`title="..."`).

### 5.2 KPI Telemetry Blocks (No Card Stripes)
- **Container:** Rounded panel (`border-radius: 10px; border: 1px solid var(--stone-border); padding: 16px 18px;`).
- **Kicker Label:** Top row contains an 11px uppercase monospace title paired with a micro-category badge (e.g. `EDGE WAF`, `L7 AST`).
- **Value:** Large 26px bold tabular numeral.
- **Footer:** Subtitle indicating scope (e.g. `Across 3 active domains`, `0.0% false-positive rate`).
- **Banned:** No 3px colored top border lines; color is expressed through the metric number and status pill.

### 5.3 Live Traffic Stream Table
- **Header:** Sticky `position: sticky; top: 0;` with archival parchment or obsidian carbon background and subtle bottom border.
- **Row Architecture:**
  - Column 1: Monospace timestamp (`HH:MM:SS`) with relative time beneath (`(2s ago)`).
  - Column 2: Protected host badge.
  - Column 3: Client IP with telemetry hover inspector (`data-telemetry-id`).
  - Column 4: HTTP Method tag (`GET` / `POST` / `PUT`) and code-wrapped URI (`/api/v1/auth`).
  - Column 5: Risk score (`0–100`) color-graded into green (<50), amber (50–74), or red (75+).
  - Column 6: Verdict Pill (`ALLOW (200)`, `BLOCK (403)`, `CHALLENGE`, `RATELIMIT (429)`).
  - Column 7: Triggered Rule / Threat Category.
  - Column 8: Action button (`Inspect Forensics`).
- **Quarantined IP Re-attempt Treatment:**  
  When an IP previously banned in the firewall attempts access again:
  - Verdict pill turns into a high-visibility badge: `[BLOCKED IP RE-ATTEMPT]`.
  - Rule cell shows:  
    `QUARANTINED OFFENDER RE-ATTEMPT` with a circle-slash vector icon, and explanatory text: `Firewall active drop • Zero origin execution`.
- **Row Animation:** Prepend new rows with a smooth 0.25s slide-in (`animation: rowSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1)`).

### 5.4 Live Traffic Control Toolbar & Hotkeys
- **Toolbar:** Fluid wrapping flexbox with verdict filter dropdown, Wide View toggle, Pause/Resume toggle, and Buffer Clear.
- **Visual Hotkey Badges:** Controls display subtle `<kbd>` tags:
  - `[W]` — Toggle Wide View
  - `[Space]` — Pause / Resume live streaming
  - `[C]` — Clear view buffer
  - `[/]` — Focus quick search input

### 5.5 Forensic Side Drawer
- **Trigger:** Clicking any table row opens an off-canvas drawer from the right edge (`width: min(640px, 95vw)`).
- **Structure:**
  - Header: Incident ID, timestamp, verdict pill, and 36×36px accessible close button (`✕`).
  - Risk Matrix: 2-column breakdown of Adversarial Risk Score and Inspection Engine (AST Lexical + DFA).
  - Raw Wire Headers: Archival terminal block (`.forensic-code-block`) with syntax-highlighted request metadata.
  - Lexical Tokens: Parsed AST tokens identifying malicious injection fragments.
  - Cryptographic Origin Seal: RFC 8032 Ed25519 signature payload.

---

## 6. Accessibility & Sensory Engineering

1. **Focus Rings:** All interactive elements (`<button>`, `<a>`, `<input>`, `<select>`) declare:
   ```css
   :focus-visible {
     outline: 2px solid var(--deep-indigo);
     outline-offset: 2px;
   }
   ```
2. **Accessible Names:** Every icon button declares an explicit `aria-label` or `title` (e.g. `aria-label="Close modal dialog"`).
3. **Custom Scrollbars:** Themed directly from the palette:
   - Light Mode: `#DDD2BF` track, `#B8A995` thumb.
   - Dark Mode: `#0E131A` track, `rgba(255, 255, 255, 0.16)` thumb.
4. **Touch Targets:** All clickable actions maintain a minimum 40×40px tap bounding box on mobile devices.
5. **No Data Loss on Refresh:** Telemetry connects to a local IndexedDB store (`SentinelEventStore`). Refreshing the browser or switching between tabs does **not** wipe live requests. Data is cleared **only** upon explicit operator logout.

---

## 7. Design System Reference Comparison

| Aspect | Generic AI Slop | SentinelGrid Design System |
| :--- | :--- | :--- |
| **Color Base** | `#FFFFFF` with neon cyan `#00F0FF` | Warm Parchment `#EFE9DF` or Obsidian `#0B0E14` |
| **Borders** | Bright electric blue borders with blur | Delicate muted sandstone `#CFBFAB` hairline |
| **Iconography** | Operating system emojis (`⚡`, `🛡️`, `📊`) | Authored 16px vector SVGs (`stroke-width: 2`) |
| **Cards** | Repetitive equal-height cards with colored top lines | Asymmetric, high-density telemetry tables and tiles |
| **Typography** | Generic Inter with purple gradient titles | Plus Jakarta Sans + Space Mono tabular numerals |
| **Feel** | Disposable marketing landing page | Mission-critical security operations kernel |

---

## 8. Universal Display Responsiveness (320px to 5120px)

1. **Two-Tier Adaptive Ribbon:**
   - On viewports `<= 1024px`, `.app-topbar` wraps into a dual-tier operational command deck.
   - Tier 1 preserves brand identity, current breadcrumbs, and operator clearance HUD.
   - Tier 2 expands `#topbar-telemetry-strip` displaying real-time system clock and cloud core edge connectivity without truncation.
   - Secondary tools (sound toggle, timezone switcher, profile, shortcuts) scroll horizontally in `.topbar-actions` with touch momentum, completely eliminating destructive `display: none` DOM deletion.

2. **Ultrawide Split-Deck Mode (`21:9` to `32:9`):**
   - Under `@media (min-aspect-ratio: 21/9) and (min-width: 1800px)`, the layout dynamically shifts into a panoramic split-deck view.
   - Left deck (46% width) pins the real-time velocity graph engine, KPI tiles, and threat distribution charts.
   - Right deck (54% width) anchors the full-height live telemetry stream table with independent vertical scrolling.

3. **Lossless High-Density Tables:**
   - Forensic data tables feature hardware-pinned sticky columns: Column 1 (`Timestamp/Verdict`) is anchored to `left: 0`, and Column 8 (`Actions/Inspect`) is anchored to `right: 0`.
   - Headers and pinned cells use solid background fills (`var(--sand-warm)`) with 1px structural borders, guaranteeing 100% forensic visibility while swiping intermediate columns on 320px screens.

4. **Fluid Inputs & Tabular Numerals:**
   - Global filters (`#scope-website-select` and `#event-search-query`) scale fluidly via `width: clamp(180px, 25vw, 360px); flex: 1 1 200px;`.
   - Primary metric numerals (`.metric-val`) utilize `font-size: clamp(18px, 1.8vw + 10px, 28px); font-variant-numeric: tabular-nums;` to prevent layout reflows and text clipping.

---

## 9. Scroll Performance & GPU Acceleration

1. **Hardware Composite Layer Promotion:**
   - Structural elements that slide or translate during scrolling (`.app-sidebar`, `.app-topbar`, `.drawer-panel`, `.shortcuts-floating-pill`, `.threat-toast-alert`, and `.table-clean thead th`) are promoted to dedicated GPU composite layers:
     ```css
     will-change: transform, opacity;
     transform: translateZ(0);
     backface-visibility: hidden;
     ```
2. **Strict Property Confinement:**
   - Transitions and animations are strictly confined to `transform` and `opacity`. Properties that trigger browser reflow passes (`width`, `height`, `margin`, `padding`, `box-shadow`) are prohibited from scroll or hover transition loops.
3. **CSS Containment:**
   - Heavy data containers (`.table-responsive`, `.drawer-panel`, `.topology-card`, `#notificationPopover`) declare `contain: layout style paint;`, isolating their internal rendering tree from the main layout context.
4. **Solid Sticky Table Headers:**
   - Table headers maintain solid opaque background fills without blur filters or alpha-blended drop shadows, eliminating expensive real-time rasterization during scroll events.
5. **Throttled Passive Event Listeners:**
   - All scroll, touch, and resize handlers are registered with `{ passive: true }` and throttled via `window.requestAnimationFrame`, preventing main-thread scroll locking.

---

## 10. Micro-Interactions & State Transitions

1. **High-Precision Active Press States:**
   - All actionable elements (`.btn`, `.form-input`, `select.form-input`) respond with a physical tactile press state:
     ```css
     .btn:active, .form-input:active, select.form-input:active {
       transform: scale(0.98) !important;
     }
     ```
2. **Crisp 2px Hardware Focus Outlines:**
   - Keyboard navigation and interactive focus states declare high-contrast, offset cyan rings:
     ```css
     .form-input:focus,
     .btn:focus-visible,
     select.form-input:focus {
       outline: 2px solid var(--accent-cyan) !important;
       outline-offset: 2px !important;
       box-shadow: none !important;
       border-color: var(--accent-cyan) !important;
     }
     ```
3. **Dual-Square Badge Pulse:**
   - Active status badges (`.badge-online`) feature an inline square indicator pulsing on a discrete 1-second cadence matching UTC system clock ticks:
     ```css
     .badge-online::before {
       content: '';
       display: inline-block;
       width: 7px;
       height: 7px;
       border: 1px solid var(--sage-green);
       background: var(--sage-green);
       border-radius: 1px;
       animation: dualSquarePulse 1s steps(2, start) infinite;
     }
     ```
4. **Cascading Staggered Drawer Reveals:**
   - Opening the Threat Forensics side drawer triggers an accelerated 180ms panel slide combined with 25ms staggered entrance reveals across each internal payload and metadata container block.
5. **Tab Crossfade Animations:**
   - View switching executes a rapid 150ms opacity/translation crossfade (`transform: translateY(4px) -> translateY(0)`), ensuring responsive transitions between operational modules.
6. **Inline Copy Feedback:**
   - Clipboard operations (`copySessionToken()`, `copyPayloadToClipboard()`, `copyHeadersToClipboard()`) morph the triggering button text directly to `[COPIED ✓]` in `#2EA043` for exactly 1200ms before returning to their original label, completely eliminating disruptive toast popups.

---

## 11. Interactive Scrubbing & Telemetry Graph Dynamics

1. **SVG Hairline Cursor Tracking:**
   - Hovering across `#traffic-histogram-container` renders a vertical dashed hairline cursor (`#hist-hairline`) in `var(--accent-cyan)` tracking dynamically to each time slice center.
2. **Interactive Slice Dimming:**
   - During histogram inspection, non-hovered time slice groups dim to `opacity: 0.35`, providing high visual contrast to isolate attack spikes and traffic anomalies.
3. **Real-Time Dual-Series Velocity Oscilloscope:**
   - Renders clean traffic (`Passed` in `#2EA043`) against mitigated traffic (`Blocked` in `#F85149`) with vertical gradient fills.
   - Dual-ring reticle crosshair snapping reports exact `HH:MM:SS` slice timestamps, `PASSED r/s`, `BLOCKED r/s`, and `TOTAL r/s`.
   - Dynamic rolling buffer window selection supports instant toggling between `1m` (60s), `5m` (300s), `15m` (900s), and `1h` (3600s) time horizons.

---

*This specification serves as the permanent architectural standard for all SentinelGrid frontend interfaces.*