# Utkal Vantage — BTL Execution + Monitoring + Conversion Platform

> **"Your advantage, on the ground."**  
> End-to-end BTL field marketing execution with GPS-verified proof-of-work and conversion tracking across Odisha.

---

## Live Pages

| Page | Description |
|---|---|
| [`index.html`](index.html) | Marketing landing page — hero, bento features, pricing, testimonials |
| [`dashboard.html`](dashboard.html) | Founder ops dashboard — live map, KPIs, promoter roster, leads pipeline, billing |
| [`client-portal.html`](client-portal.html) | Client-facing portal — read-only live proof gallery, lead funnel, audit log |
| [`brand-sheet.html`](brand-sheet.html) | Official Utkal Vantage Brand Sheet (v1.0) — sunrise dot grid, typography, swatches |

---

## Brand Identity

* **Name:** Utkal Vantage (`Utkal Vantage Technologies Pvt. Ltd.`)
* **Tagline:** *"Your advantage, on the ground."*
* **Primary Mark:** 13-by-7 dot-grid sunrise rising over a dotted horizon.
* **Palette:**
  * **Sunrise Coral:** `#D85A30` (Primary brand lead)
  * **Ember:** `#993C1D` (Text and rules on light)
  * **Dawn:** `#F5C4B3` (Soft fills and tints)
  * **Ink:** `#1F1D1B` (Text and grid)
  * **Paper / Canvas:** `#F6F3EE` (Warm paper background)
  * **Amber:** `#EF9F27` (Highlights & metrics)
* **Typography:**
  * **Display:** `Bricolage Grotesque`
  * **Body:** `IBM Plex Sans`
  * **Technical / Mono:** `IBM Plex Mono`

---

## Tech Stack

- **Pure HTML5 / CSS3 / Vanilla JS** — zero build step, instant Netlify edge deploy
- **Supabase** backend — auth, Postgres database, storage
- **Chart.js 4.4** for performance analytics
- **Phosphor Icons 2.1** for iconography
- **Pure SVG Vector Assets** (`assets/mark.svg`, `assets/wordmark.svg`)

---

## Supabase Setup

1. Go to your [Supabase Dashboard](https://supabase.com/dashboard)
2. Open **Settings → API**
3. Copy the `anon` public key
4. Paste it into `js/supabase.js` → `anonKey` field

---

## Deploy to Netlify

1. Push this repo to GitHub
2. Go to [Netlify](https://app.netlify.com) → **Add new site** → **Import from Git**
3. Select this repository: `seikhimranul-arch/groundx-btl-platform`
4. Publish directory: `.` (root)
5. Deploy!

---

## Project Structure

```
├── index.html           # Marketing landing page
├── dashboard.html       # Founder operations dashboard
├── client-portal.html   # Client-facing campaign portal
├── brand-sheet.html     # Official brand sheet specification
├── netlify.toml         # Netlify deploy config
├── assets/              # Vector sunrise marks and wordmarks
│   ├── mark.svg
│   ├── mark-white.svg
│   ├── wordmark.svg
│   └── wordmark-white.svg
├── styles/
│   └── main.css         # Global Utkal Vantage design system
└── js/
    └── supabase.js      # Supabase REST client (auth + DB + storage)
```

---

## License

Proprietary — Utkal Vantage Technologies Pvt. Ltd.
