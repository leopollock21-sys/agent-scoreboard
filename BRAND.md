<!-- GLOBAL-BRAND:START (Managed by leopollock21-sys/.github/BRAND.md — edit there, not here) -->
# BRAND.md — Chinlung Technologies Brand & UI Standard

Follow this brand guide for all UI, screens, icons, websites, printed receipts/vouchers, and user-facing text. If a repository adds project-specific branding notes below, follow both.

## 1. Company Identity & Logo Rules
- **Company Name:** **Chinlung Technologies**
- **Logo Structure:** Every product uses:
  1. The **Chinlung Technologies** company brand logo (e.g., About screen, footer, splash, or login header), and
  2. A distinct **app-specific logo** that adopts the Chinlung brand identity and **always retains the Great Hornbill (`Vapual`) emblem**.
- **Asset Handling in Cloud Repos:**
  - Always reuse the existing logo/icon assets already stored inside the repository (such as `assets/` or `public/`).
  - Never replace the Great Hornbill (`Vapual`) emblem with generic stock icons or auto-generated placeholders.
  - For NGO / humanitarian apps (such as `ngo-wms`), keep the primary interface neutral, respectful, and field-ready, and keep Chinlung attribution discreet (e.g., in the About modal or footer where already placed).

## 2. Official Color Palette
Use the Chinlung theme tokens consistently (avoid random uncoordinated colors):

| Role | Name | Hex | Typical Use |
| --- | --- | --- | --- |
| Primary Dark | Midnight Navy | `#0B1B3D` / `#0E1424` | Headers, dark surfaces, primary text, trust anchors |
| Primary Brand Accent | Hornbill Amber / Gold | `#F59E0B` / `#E5A93C` | Key brand accents, badges, highlights, emblem details |
| Interactive Accent | Vibrant Cyan | `#00D2FF` | Active states, focus rings, subtle tech highlights |
| Surfaces & Neutrals | Clean Apple-Style Neutrals | `#FFFFFF`, `#F8FAFC`, `#E2E8F0`, `#475569` | Cards, page backgrounds, subtle `1px` borders, secondary text |

- Keep high contrast (`>= 4.5:1` for normal text, `>= 3:1` for large text and UI controls) so screens remain crisp on both budget monitors and bright mobile screens.
- Reserve semantic status colors strictly for meaning: green (success), amber (warning), red (error/destructive).

## 3. Default UI Style (Minimalist Premium Apple-Style)
Minimalist, calm, professional Apple-style UI is the default for every app and web interface:
- **Layout & Spacing:** Generous whitespace, `8pt` spacing grid (`8 / 16 / 24 / 32px`), subtle `1px` borders, and soft elevation instead of heavy drop shadows or busy gradients.
- **Clarity:** **1 clear primary action button per screen/modal**; secondary actions stay understated.
- **Usability ("No Button, No Feature"):** 100% mouse and touch friendly — end users must never need terminal commands. Use comfortable touch targets (`44–48px` minimum height/width).
- **4 Mandatory UI States:** Every screen or panel that loads or displays data must cleanly handle:
  1. **Empty** (helpful plain-language guidance + clear next action)
  2. **Loading** (clean skeleton or subtle spinner — no frozen screen)
  3. **Error** (plain-language message + **Retry** button)
  4. **Populated** (clean hierarchy, aligned numbers, scannable rows)

## 4. Tone, Copy & Language Purity
- **Tone:** Short, direct, plain, and practical. Avoid decorative clutter, excessive emojis, buzzwords, or walls of text.
- **100% Language Purity:** Supported languages are **English (EN)**, **Myanmar / Burmese (MY)**, **Hakha Lai (LAI)**, and **Mizo (MIZ)**.
  - Never mix two languages on the same screen, button, dialog, error message, or printed receipt/voucher.
  - Never leak raw code identifiers, database keys, or enum names into user-visible text.
<!-- GLOBAL-BRAND:END -->
