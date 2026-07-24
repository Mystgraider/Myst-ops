# myst-ops

Personal security tooling, one repo: recon scanner, LLM-driven static
audit, source code SAST, live browser-based recon, passive OSINT, and a
full case-management CRM. Everything runs from the GitHub Actions tab
(mobile friendly, no PC needed) or deploys straight to Render/Pages.

## Start here

**https://mystgraider.github.io/Myst-ops/** - a landing page (`hub/`) linking
to all 6 tools below, so you don't have to remember where each one lives.

For triggering bogart/OpenOSINT/Argo/security-analyst without fighting
GitHub's mobile Actions UI, use **`/dashboard/`** from that hub - one UI
with a form per tool. See `DEPLOY-DASHBOARD.md` for one-time setup.

## What's here

### `hub/` + `.github/workflows/deploy-pages.yml`
The landing page above. Just static links - no token, no logic, nothing
that can be misused if someone else finds the URL (Actions links open
GitHub's run dialog, which still requires your own write access to
actually trigger anything).

### `bogart/` + `.github/workflows/bogart-scan.yml`
Recon + active vulnerability scanner. Actions tab → **Bogart Recon Scan** →
Run workflow → fill in target domain, scope allowlist, program name.
Downloads a markdown report + sqlite findings db as an artifact.

Installs 7 Go-based recon tools + builds massdns from source on every run,
so expect 5-10 minutes of setup before scanning starts. The new
`bogart/security_intelligence_os/` package starts the longer-term Security
Intelligence OS foundation: normalized assets/findings/evidence, pipeline
stages, and plugin extension points documented in
`docs/SECURITY_INTELLIGENCE_OS.md`.

### `security-analyst/` + `.github/workflows/security-analyst-scan.yml`
Static source-code scanner (regex + AST layer) - hardcoded secrets, weak
crypto, injection patterns, insecure deserialization, and more. Runs
automatically whenever `security-analyst/` or `bogart/` changes (it scans
the whole repo, so it catches `bogart_v6.py` too), or trigger manually from
the Actions tab. Reports land as a `security-reports-...` artifact.

### `threatscanner/` + `.github/workflows/deploy-pages.yml`
Browser-based live scanner (headers, CORS, SQLi/XSS indicators, subdomain
enum, CSRF PoC, brute force, WebSocket fuzz, and a Code Scan tab running
the same rules as security-analyst, ported to JS). Deployed alongside the
hub at `/threatscanner/`, auto-updates whenever `threatscanner/` changes.

**One-time setup needed:** enable Pages on this repo — Settings → Pages →
Source → **GitHub Actions** (not "Deploy from a branch"). After that, the
workflow handles every future deploy.

### `.github/workflows/openosint.yml`
Passive OSINT aggregator (email/username/DNS/whois/IP intel) via the
`openosint` PyPI package. Actions tab → **OpenOSINT Investigation** → pick
a tool + target. `email`, `username`, `dns`, and `playbook-domain` work
with zero API keys; see the workflow file's comments for which repo
secrets unlock the rest (all free-tier, no card needed).

### `.github/workflows/argo-audit.yml`
LLM-native static security audit (clones [Argo](https://github.com/gigioneggiando/argo)
from upstream at runtime). Actions tab → **Argo Static Security Audit** →
Run workflow → pick `repo_path` (`.` for this whole repo, or a specific
subfolder) and `runner` (`mock` = free/fixtures, `headless` = real audit,
needs an `ANTHROPIC_API_KEY` repo secret and costs real tokens).

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
2. Enable GitHub Pages (Settings → Pages → Source → GitHub Actions) so
   ThreatScanner deploys.
3. Run `security-analyst-scan.yml` to see what it finds across the repo.
4. Run `bogart-scan.yml` against a real authorized target.
5. Try `openosint.yml` with the `dns` or `email` tool - no setup needed.
6. When ready to stand up the CRM, follow `DEPLOY-RENDER.md`.
