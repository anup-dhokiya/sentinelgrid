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

*This specification serves as the permanent architectural standard for all SentinelGrid frontend interfaces.*