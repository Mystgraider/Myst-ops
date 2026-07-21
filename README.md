# myst-ops

Personal security tooling, one repo: recon scanner, LLM-driven static
audit, and a full OSINT case-management CRM. Everything runs from the
GitHub Actions tab (mobile friendly, no PC needed) or deploys straight
to Render.

## What's here

### `bogart/` + `.github/workflows/bogart-scan.yml`
Recon + active vulnerability scanner. Actions tab → **Bogart Recon Scan** →
Run workflow → fill in target domain, scope allowlist, program name.
Downloads a markdown report + sqlite findings db as an artifact.

Installs 7 Go-based recon tools + builds massdns from source on every run,
so expect 5-10 minutes of setup before scanning starts.

### `.github/workflows/argo-audit.yml`
LLM-native static security audit (clones [Argo](https://github.com/gigioneggiando/argo)
from upstream at runtime). Actions tab → **Argo Static Security Audit** →
Run workflow → pick `repo_path` (`.` for this whole repo, `ghost` or
`bogart` for just one project) and `runner` (`mock` = free/fixtures,
`headless` = real audit, needs an `ANTHROPIC_API_KEY` repo secret and
costs real tokens).

Start with `mock` to confirm the pipeline runs clean before spending
anything on `headless`.

### `ghost/` + `.github/workflows/ghost-smoke-test.yml` + `render.yaml`
The full GHOST CRM app (frontend + backend + Postgres via docker-compose) —
case management for OSINT/bug-bounty findings. The smoke-test workflow
builds and boots the whole stack in CI whenever anything under `ghost/`
changes, verifying the frontend can actually reach the backend through
nginx before you trust a deploy.

To actually deploy it: see `DEPLOY-RENDER.md` — short version is sign up
for a free Neon or Supabase Postgres (Render's own free Postgres
auto-deletes after 30+14 days, not good for data you want to keep), then
Render → New → Blueprint → point at this repo, `render.yaml` handles the
rest.

To run it locally instead: `cd ghost && docker compose up --build`.

## Order of operations if you're doing this fresh

1. Try `argo-audit.yml` with `runner: mock` first — lowest commitment, free,
   proves the Actions setup itself works before touching anything heavier.
2. Run `bogart-scan.yml` against a real authorized target.
3. When ready to stand up the CRM, follow `DEPLOY-RENDER.md`.
