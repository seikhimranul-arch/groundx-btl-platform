# GroundX — BTL Execution + Monitoring + Conversion Platform

> India's most transparent field marketing platform.  
> End-to-end BTL execution with GPS-verified proof-of-work and conversion tracking.

## Live Pages

| Page | Description |
|---|---|
| `index.html` | Marketing landing page — hero, features, pricing, testimonials |
| `dashboard.html` | Founder ops dashboard — live map, KPIs, leads, promoters, campaigns, billing |
| `client-portal.html` | Client-facing portal — proof-of-work gallery, lead funnel, audit log |

## Tech Stack

- **Pure HTML/CSS/JS** — zero build step, instant Netlify deploy
- **Supabase** backend — auth, Postgres database, file storage
- **Chart.js** for data visualizations
- **Phosphor Icons** for premium iconography
- **Satoshi** typeface via Fontshare

## Supabase Setup

1. Go to your [Supabase Dashboard](https://supabase.com/dashboard)
2. Open **Settings → API**
3. Copy the `anon` public key
4. Paste it into `js/supabase.js` → `anonKey` field

## Deploy to Netlify

1. Push this repo to GitHub
2. Go to [Netlify](https://app.netlify.com) → **Add new site** → **Import from Git**
3. Select this repository
4. Publish directory: `.` (root)
5. Deploy!

## Project Structure

```
├── index.html           # Marketing landing page
├── dashboard.html       # Founder operations dashboard
├── client-portal.html   # Client-facing campaign portal
├── netlify.toml         # Netlify deploy config
├── styles/
│   └── main.css         # Global design system
└── js/
    └── supabase.js      # Supabase REST client (auth + DB + storage)
```

## License

Proprietary — GroundX Technologies Pvt. Ltd.
