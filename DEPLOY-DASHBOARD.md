# Setting up the Dashboard

One UI (`/dashboard/`) to trigger and monitor bogart, OpenOSINT, Argo, and
security-analyst without needing GitHub's mobile Actions UI. It's a small
backend (holds a GitHub token server-side, deployed on Render) plus a
frontend page (deployed on GitHub Pages, same site as the hub).

## Why a backend is needed at all

Triggering a GitHub Actions workflow requires a GitHub token. That token can
never live in the browser-side code of a public page - anyone who opened
dev tools could steal it and use it as you. So instead:

- **Backend** (`dashboard/backend/`) holds the real GitHub token as a
  server-side secret and does the actual GitHub API calls.
- **Frontend** (`dashboard/frontend/`) talks to *your own backend* with a
  separate, less powerful "dashboard token" - not the GitHub token itself.

## Setup

### 1. Create a scoped GitHub token for the backend

Settings → Developer settings → **Fine-grained personal access tokens** →
Generate new token:
- Repository access: **Only select repositories** → `Myst-ops`
- Permissions: **Actions: Read and write**, **Contents: Read-only** (nothing
  broader than that - this token can trigger workflows and read run/artifact
  info, and that's it)

Copy the token - you'll paste it into Render next.

### 2. Deploy via the Render Blueprint (same one GHOST CRM uses)

If you haven't already, this repo's `render.yaml` now defines a third
service: `myst-ops-dashboard-backend`. Re-sync the Blueprint (Render
dashboard → the Blueprint → Manual Sync), and it'll show up as a new
service to deploy.

- **GH_TOKEN**: paste the fine-grained token from step 1
- **DASHBOARD_TOKEN**: Render auto-generates this - after deploy, copy it
  from the service's Environment tab

### 3. Enable Pages if you haven't (same as ThreatScanner)

Settings → Pages → Source → **GitHub Actions**. The
`deploy-pages.yml` workflow now also publishes `dashboard/frontend/` to
`/dashboard/` alongside the hub and ThreatScanner.

### 4. Connect the dashboard

Open `https://mystgraider.github.io/Myst-ops/dashboard/`, and on the
connect screen enter:
- **Backend URL**: the `myst-ops-dashboard-backend` service's `.onrender.com`
  URL (find it on that service's page in Render)
- **Dashboard Token**: the `DASHBOARD_TOKEN` value from step 2

These are saved in your browser's local storage so you only enter them
once per device.

## What it can do

- **Bogart**: fill in target domain + scope allowlist, hit Run Scan
- **OpenOSINT**: pick a tool from the dropdown + target, hit Run
- **Argo**: pick `mock` (free) or `headless` (real, costs tokens), hit Run
- **Security Analyst**: no inputs, just Run

Each panel shows the 5 most recent runs with status and a "view on GitHub"
link (for full logs and to download report artifacts - artifact download
isn't wired into this UI yet, use the GitHub run page for that part).

## Honest caveats

- Free-tier Render services spin down after 15 minutes idle - the first
  request after a break takes 30-60s while it wakes up.
- The dashboard token gates the *dashboard's own API*, not GitHub itself -
  if you ever suspect it's leaked, just delete the `DASHBOARD_TOKEN` env
  var on Render and set a new one; the frontend will need reconnecting.
- The fine-grained `GH_TOKEN` is scoped to this one repo with
  Actions:write + Contents:read only - even in the worst case where it
  leaked, it can't touch your other repos, can't read code content beyond
  workflow runs, and can't do anything destructive like delete the repo.
