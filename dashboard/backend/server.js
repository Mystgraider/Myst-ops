// myst-ops dashboard backend
// Holds the GitHub token server-side only. The browser never sees it -
// it talks to this backend with a separate DASHBOARD_TOKEN instead, and
// this backend does the actual authenticated GitHub API calls.
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const GH_TOKEN = process.env.GH_TOKEN;
const DASHBOARD_TOKEN = process.env.DASHBOARD_TOKEN;
const REPO_OWNER = process.env.REPO_OWNER || 'Mystgraider';
const REPO_NAME = process.env.REPO_NAME || 'Myst-ops';

if (!GH_TOKEN) {
  console.error('CRITICAL: GH_TOKEN is not set. GitHub API calls will fail.');
}
if (!DASHBOARD_TOKEN) {
  console.error('CRITICAL: DASHBOARD_TOKEN is not set. Every request will be rejected (fail-closed).');
}

// Fail-closed auth: every /api route requires the correct token.
// If DASHBOARD_TOKEN isn't configured at all, nothing works - by design.
app.use('/api', (req, res, next) => {
  if (!DASHBOARD_TOKEN) return res.status(404).json({ error: 'Not found' });
  const provided = req.headers['x-dashboard-token'];
  if (!provided || provided !== DASHBOARD_TOKEN) {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
});

const GH_API = 'https://api.github.com';
function ghHeaders() {
  return {
    'Authorization': `token ${GH_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

// Allowlist of workflow files this dashboard is permitted to trigger -
// prevents the trigger endpoint from being repurposed to dispatch some
// unrelated/unexpected workflow file via a crafted request.
const ALLOWED_WORKFLOWS = new Set([
  'bogart-scan.yml',
  'openosint.yml',
  'argo-audit.yml',
  'security-analyst-scan.yml',
  'ghost-smoke-test.yml',
]);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', repo: `${REPO_OWNER}/${REPO_NAME}` });
});

// Trigger a workflow_dispatch run
app.post('/api/trigger/:workflow', async (req, res) => {
  const { workflow } = req.params;
  if (!ALLOWED_WORKFLOWS.has(workflow)) {
    return res.status(400).json({ error: `Workflow not allowed: ${workflow}` });
  }
  const inputs = req.body?.inputs || {};

  try {
    const resp = await fetch(
      `${GH_API}/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${workflow}/dispatches`,
      {
        method: 'POST',
        headers: { ...ghHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ ref: 'main', inputs }),
      }
    );
    if (resp.status === 204) {
      return res.json({ message: 'Workflow triggered', workflow });
    }
    const errBody = await resp.text();
    return res.status(resp.status).json({ error: 'GitHub API error', detail: errBody });
  } catch (err) {
    console.error('Trigger error:', err);
    res.status(500).json({ error: 'Internal error triggering workflow' });
  }
});

// List recent runs for a workflow
app.get('/api/runs/:workflow', async (req, res) => {
  const { workflow } = req.params;
  if (!ALLOWED_WORKFLOWS.has(workflow)) {
    return res.status(400).json({ error: `Workflow not allowed: ${workflow}` });
  }
  try {
    const resp = await fetch(
      `${GH_API}/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${workflow}/runs?per_page=5`,
      { headers: ghHeaders() }
    );
    const data = await resp.json();
    if (!resp.ok) {
      return res.status(resp.status).json({ error: 'GitHub API error', detail: data });
    }
    const runs = (data.workflow_runs || []).map(r => ({
      id: r.id,
      status: r.status,
      conclusion: r.conclusion,
      created_at: r.created_at,
      updated_at: r.updated_at,
      html_url: r.html_url,
    }));
    res.json({ runs });
  } catch (err) {
    console.error('List runs error:', err);
    res.status(500).json({ error: 'Internal error listing runs' });
  }
});

// List artifacts for a specific run
app.get('/api/runs/:workflow/:runId/artifacts', async (req, res) => {
  const { runId } = req.params;
  try {
    const resp = await fetch(
      `${GH_API}/repos/${REPO_OWNER}/${REPO_NAME}/actions/runs/${runId}/artifacts`,
      { headers: ghHeaders() }
    );
    const data = await resp.json();
    if (!resp.ok) {
      return res.status(resp.status).json({ error: 'GitHub API error', detail: data });
    }
    const artifacts = (data.artifacts || []).map(a => ({
      id: a.id,
      name: a.name,
      size_in_bytes: a.size_in_bytes,
      expired: a.expired,
    }));
    res.json({ artifacts });
  } catch (err) {
    console.error('List artifacts error:', err);
    res.status(500).json({ error: 'Internal error listing artifacts' });
  }
});

// Proxy artifact download (browsers can't include our GH_TOKEN themselves)
app.get('/api/artifacts/:artifactId/download', async (req, res) => {
  const { artifactId } = req.params;
  try {
    const resp = await fetch(
      `${GH_API}/repos/${REPO_OWNER}/${REPO_NAME}/actions/artifacts/${artifactId}/zip`,
      { headers: ghHeaders(), redirect: 'follow' }
    );
    if (!resp.ok) {
      return res.status(resp.status).json({ error: 'Could not fetch artifact' });
    }
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="artifact-${artifactId}.zip"`);
    const buffer = Buffer.from(await resp.arrayBuffer());
    res.send(buffer);
  } catch (err) {
    console.error('Download artifact error:', err);
    res.status(500).json({ error: 'Internal error downloading artifact' });
  }
});

app.listen(PORT, () => {
  console.log(`Dashboard backend running on port ${PORT}`);
});
