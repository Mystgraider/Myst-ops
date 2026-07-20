# Where each file goes in your GHOST-osint-crm repo

This bundle only contains what changed - drop these into your existing repo
at these exact paths (overwriting where a file already exists):

| File in this bundle | Goes to |
|---|---|
| `nginx.conf.template` | `frontend/nginx.conf.template` (**delete the old `frontend/nginx.conf`** - it's replaced by this) |
| `frontend-Dockerfile` | `frontend/Dockerfile` (rename it to just `Dockerfile` when you place it) |
| `render.yaml` | repo root: `render.yaml` |
| `.github/workflows/smoke-test.yml` | same path: `.github/workflows/smoke-test.yml` |
| `DEPLOY-RENDER.md` | repo root: `DEPLOY-RENDER.md` |

Read `DEPLOY-RENDER.md` for the full walkthrough (including why the database
isn't part of the Render Blueprint) and the caveats before you rely on this
in production.
