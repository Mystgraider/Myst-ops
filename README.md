# myst-ops

Personal security tooling setup — recon scanner, LLM-driven static audit, and
CRM deployment config, all runnable from the GitHub Actions tab (mobile
friendly, no PC needed).

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
Run workflow → pick `repo_path` (`.` for this whole repo, or point it at
any path) and `runner` (`mock` = free/fixtures, `headless` = real audit,
needs an `ANTHROPIC_API_KEY` repo secret and costs real tokens).

Start with `mock` to confirm the pipeline runs clean before spending
anything on `headless`.

### `ghost-crm-updates/`
**Not meant to run from here** — these are patch files for the separate
GHOST-osint-crm repo (nginx proxy fix, Render Blueprint, CI smoke test,
deploy guide). See `ghost-crm-updates/WHERE-THESE-GO.md` for exactly which
file goes where in that other repo. The `.github/workflows/smoke-test.yml`
inside this folder is inert here — GitHub only runs workflows sitting in
`.github/workflows/` at a repo's own root, so it needs to be moved to
GHOST-osint-crm's root when you apply these changes there, not left nested
inside this folder.

## Order of operations if you're doing this fresh

1. Try `argo-audit.yml` with `runner: mock` first — lowest commitment, free,
   proves the Actions setup itself works before touching anything heavier.
2. Run `bogart-scan.yml` against a real authorized target.
3. When ready, apply `ghost-crm-updates/` to the actual GHOST-osint-crm repo
   and follow `DEPLOY-RENDER.md`.
