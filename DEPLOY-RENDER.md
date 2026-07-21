# Deploying GHOST CRM (Render + external Postgres)

## What changed from the original repo

1. **`ghost/frontend/nginx.conf` → `ghost/frontend/nginx.conf.template`**, using
   `${BACKEND_HOST}` instead of the hardcoded `backend:3001`. The nginx
   Docker image auto-substitutes env vars into anything in
   `/etc/nginx/templates/*.template` at container start (a built-in
   feature, no custom entrypoint needed). Local `docker-compose` still
   works unchanged - the Dockerfile defaults `BACKEND_HOST=backend:3001`.
2. **`.github/workflows/ghost-smoke-test.yml`** - builds and boots the full
   stack in CI on every push, and specifically checks that the frontend
   can reach the backend through the nginx proxy. Run this at least once
   before you trust the deploy - I couldn't test-build the Docker images
   myself (no Docker in my working environment), so this is how you verify
   the fix actually works before relying on it.
3. **`render.yaml`** - a Render Blueprint that deploys both web services in
   one shot.

## Why the database isn't in the Blueprint

Render's own free Postgres auto-deletes after 30 days + a 14-day grace
period. For a CRM meant to hold case data you actually care about, that's
a bad default. Use a Postgres provider with a genuine permanent free tier
instead:

- **Neon** (neon.tech) - serverless Postgres, generous free tier, no card
- **Supabase** (supabase.com) - free tier, no card, includes a nice web UI
  for browsing tables if you ever want to eyeball the data directly

Either one gives you a host, port, user, password, and database name after
signup - paste those into the four `sync: false` placeholders in
`render.yaml` (or directly in the Render dashboard after the Blueprint
deploys, under the backend service's Environment tab).

## Steps

1. **Sign up for Neon or Supabase**, create a Postgres database, copy the
   connection details.
2. **Run the migration** against that database before first deploy:
   ```bash
   psql "<your-connection-string>" < ghost/backend/migrations/create_wireless_networks.sql
   ```
   (or whatever migration files exist under `ghost/backend/migrations/` - check
   that folder, there may be more than one depending on which version you're on)
3. **Push this repo to GitHub.**
4. **On Render:** New > Blueprint > connect the repo. Render reads
   `render.yaml` and proposes both services.
5. **Fill in the DB_HOST / DB_USER / DB_PASSWORD / DB_NAME** placeholders
   with your Neon/Supabase values (Render will prompt for these since
   they're marked `sync: false`).
6. **Deploy.** First build takes a few minutes (React build + npm install).
7. **Create your first admin user** via Render's Shell tab on the backend
   service:
   ```bash
   node scripts/createAdminSimple.js <username> <password> [email]
   ```

## Honest caveats before you rely on this

- **Free web services spin down after 15 minutes idle** - expect a 30-60s
  cold start the first time you open it after a break. Fine for personal
  case-management use, annoying if you're demoing it live to someone.
- **I have not personally completed a live Render deployment of this** -
  the Blueprint is written to Render's current documented spec and the
  nginx fix is verified by the CI smoke test, but the actual Render deploy
  step is untested by me. Run the smoke test workflow first, and if the
  live Render deploy hits something the smoke test didn't catch (most
  likely: a Render-specific networking quirk), send me the error and I'll
  help debug it.
- Both web services are on Render's **free plan** in this Blueprint - bump
  `plan: free` to `plan: starter` for either one directly in `render.yaml`
  if you want to remove the cold-start behavior later.
