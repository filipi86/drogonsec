# Branch Monitoring

DrogonSec can watch a specific branch on GitHub or GitLab and automatically
scan it whenever new code is pushed. This page explains how it works, the
security decisions behind the design, and how to set it up step by step.

---

## How it works

Two monitoring modes are available:

| Mode | Trigger | Best for |
|------|---------|----------|
| **webhook** | Push event received in real time | Production / CI pipelines |
| **poll** | DrogonSec queries the API on a fixed interval | Air-gapped hosts, quick setup |

In both modes the flow is the same:

```
Push to branch
      │
      ▼
DrogonSec detects change
      │
      ▼
Shallow clone (depth=1) → temp dir
      │
      ▼
SAST + SCA + Leak scan
      │
      ▼
Report written (0600 perms)
      │
      ▼
Temp dir removed
```

---

## Security design

### Pillars covered

| Pillar | Implementation |
|--------|---------------|
| **Authentication** | Tokens from env vars only — never CLI flags, never logs |
| **Integrity** | GitHub webhooks: HMAC-SHA256 (`X-Hub-Signature-256`). GitLab: constant-time token comparison |
| **Confidentiality** | Clone URL with embedded token never printed. Report files created with `0o600`. Temp dir auto-cleaned. |
| **Availability** | Rate limiter (60 req/min on webhook endpoint). Tight HTTP timeouts. Redirect blocking. |
| **SSRF prevention** | API base URLs hardcoded. Branch names and repo slugs validated with strict regex before use in URLs. |
| **Injection prevention** | Branch name validated: `^[a-zA-Z0-9._/\-]+$`, no `..`, max 255 chars. Repo slug: `owner/repo` only. |
| **Timing attack prevention** | `crypto/subtle.ConstantTimeCompare` for all secret comparisons. Fixed 100 ms delay on auth failure. |

### Token scopes (least privilege)

**GitHub** — create a fine-grained token with only:
- `Contents: Read-only`

**GitLab** — create a project access token with only:
- `read_repository`

Never use a token with write access — DrogonSec only reads.

### Webhook secret

The HMAC secret should be a random 32-byte hex string. Generate one:

```bash
openssl rand -hex 32
```

Store it in `WEBHOOK_SECRET` and configure the **exact same value** in your
repo's webhook settings. DrogonSec will reject any request whose signature
does not match.

---

## Prerequisites

- DrogonSec installed (`drogonsec version` works)
- A GitHub or GitLab personal access token with the scope above
- Network access from the repo host to your DrogonSec host (webhook mode only)
- For TLS: a valid certificate and private key in PEM format

---

## Step-by-step setup

### 1 — Install DrogonSec

```bash
go install github.com/filipi86/drogonsec/cmd/drogonsec@latest
```

Or download the binary from the [Releases](https://github.com/filipi86/drogonsec/releases) page.

---

### 2 — Create a least-privilege token

#### GitHub (fine-grained token)

1. Go to **Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Set a short expiry (30–90 days)
4. Under **Repository permissions** select `Contents → Read-only`
5. Click **Generate token** and copy the value

#### GitLab (project access token)

1. Open your project → **Settings → Access Tokens**
2. Click **Add new token**
3. Select role **Reporter** and scope **read\_repository**
4. Click **Create project access token** and copy the value

---

### 3 — Export credentials as environment variables

```bash
# GitHub
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# GitLab
export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx

# Webhook mode only
export WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "Save this secret — you will paste it into the repo webhook settings:"
echo $WEBHOOK_SECRET
```

> **Do not** pass tokens as `--flags`. They would appear in shell history,
> `ps aux`, and CI logs.

---

### 4 — Polling mode (simplest setup)

No webhook configuration needed. DrogonSec queries the API every N minutes
and scans when it detects a new commit.

```bash
# GitHub — poll main every 5 minutes, SARIF output
drogonsec monitor \
  --platform github \
  --repo owner/repo \
  --branch main \
  --mode poll \
  --interval 5m \
  --format sarif \
  --output /reports/scan.sarif

# GitLab — poll develop every 10 minutes, JSON output, HIGH+ only
drogonsec monitor \
  --platform gitlab \
  --repo group/project \
  --branch develop \
  --mode poll \
  --interval 10m \
  --format json \
  --output /reports/scan.json \
  --severity HIGH
```

DrogonSec runs an immediate check on startup, then waits for the interval.
It prints a status line on every tick:

```
  · [09:15:00] No changes on main (a1b2c3d4)
  → New commit: a1b2c3d4 → e5f6a7b8

  ◆ [09:20:01] Scanning branch main
  ✓ Report written: /reports/scan_main_20260421-092001.sarif
```

Press `Ctrl+C` to stop cleanly.

---

### 5 — Webhook mode

#### 5a — Start the webhook server

```bash
# Plain HTTP (development only — not for production)
drogonsec monitor \
  --platform github \
  --repo owner/repo \
  --branch main \
  --mode webhook \
  --listen :8080

# HTTPS (production — required when the token is in the webhook URL)
drogonsec monitor \
  --platform github \
  --repo owner/repo \
  --branch main \
  --mode webhook \
  --listen :8443 \
  --tls-cert /etc/ssl/drogonsec/cert.pem \
  --tls-key  /etc/ssl/drogonsec/key.pem \
  --format sarif \
  --output /reports/scan.sarif
```

The server exposes two endpoints:

| Path | Purpose |
|------|---------|
| `POST /webhook` | Receives push events from GitHub / GitLab |
| `GET  /health`  | Health check (`{"status":"ok"}`) |

#### 5b — Configure the webhook on GitHub

1. Go to your repo → **Settings → Webhooks → Add webhook**
2. **Payload URL**: `https://<your-host>:8443/webhook`
3. **Content type**: `application/json`
4. **Secret**: paste the value of `$WEBHOOK_SECRET`
5. **Which events?**: select **Just the push event**
6. Click **Add webhook**

GitHub will send a ping — you should see `204 No Content` in the delivery log
(ping events are silently acknowledged).

#### 5c — Configure the webhook on GitLab

1. Go to your project → **Settings → Webhooks → Add new webhook**
2. **URL**: `https://<your-host>:8443/webhook`
3. **Secret token**: paste the value of `$WEBHOOK_SECRET`
4. Check **Push events** only
5. Click **Add webhook**

---

### 6 — Run as a systemd service (Linux production)

Create `/etc/systemd/system/drogonsec-monitor.service`:

```ini
[Unit]
Description=DrogonSec Branch Monitor
After=network.target

[Service]
Type=simple
User=drogonsec
Group=drogonsec
EnvironmentFile=/etc/drogonsec/monitor.env
ExecStart=/usr/local/bin/drogonsec monitor \
  --platform github \
  --repo owner/repo \
  --branch main \
  --mode webhook \
  --listen :8443 \
  --tls-cert /etc/ssl/drogonsec/cert.pem \
  --tls-key  /etc/ssl/drogonsec/key.pem \
  --format sarif \
  --output /var/reports/scan.sarif
Restart=on-failure
RestartSec=10s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/reports

[Install]
WantedBy=multi-user.target
```

`/etc/drogonsec/monitor.env` (mode `0600`, owned by root):

```
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
WEBHOOK_SECRET=<your-32-byte-hex-secret>
```

```bash
systemctl daemon-reload
systemctl enable --now drogonsec-monitor
journalctl -u drogonsec-monitor -f
```

---

### 7 — Docker

```dockerfile
FROM ghcr.io/filipi86/drogonsec:latest

ENTRYPOINT ["drogonsec", "monitor"]
```

```bash
docker run --rm \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e WEBHOOK_SECRET="$WEBHOOK_SECRET" \
  -p 8443:8443 \
  -v /etc/ssl/drogonsec:/certs:ro \
  -v /var/reports:/reports \
  ghcr.io/filipi86/drogonsec:latest monitor \
    --platform github \
    --repo owner/repo \
    --branch main \
    --mode webhook \
    --listen :8443 \
    --tls-cert /certs/cert.pem \
    --tls-key  /certs/key.pem \
    --format sarif \
    --output /reports/scan.sarif
```

---

### 8 — GitHub Actions integration (alternative)

If you prefer not to run a persistent server, add DrogonSec as a step in your
existing workflow. This is the workaround described before the `monitor`
command existed and still works well for most teams.

```yaml
# .github/workflows/drogonsec.yml
name: DrogonSec Branch Scan

on:
  push:
    branches: [main, develop, "release/**"]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Install DrogonSec
        run: go install github.com/filipi86/drogonsec/cmd/drogonsec@latest

      - name: Scan
        run: |
          drogonsec scan . \
            --format sarif \
            --output results.sarif \
            --git-history \
            --severity HIGH

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Reference

### `monitor` flag reference

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | `github` | `github` or `gitlab` |
| `--repo` | — **(required)** | Repository in `owner/repo` format |
| `--branch` | `main` | Branch to monitor |
| `--mode` | `poll` | `webhook` or `poll` |
| `--listen` | `:8080` | Webhook listen address |
| `--tls-cert` | — | PEM certificate for HTTPS |
| `--tls-key` | — | PEM private key for HTTPS |
| `--interval` | `5m` | Poll interval (min `30s`) |
| `--format` | `text` | `text`, `json`, `sarif`, `html`, `cyclonedx` |
| `--output` | stdout | Base path for report files |
| `--severity` | `LOW` | Minimum severity to report |
| `--workers` | `4` | Parallel scan workers |
| `--no-sast` | false | Disable SAST engine |
| `--no-sca` | false | Disable SCA engine |
| `--no-leaks` | false | Disable leak detection |

### Environment variables

| Variable | Required for | Description |
|----------|-------------|-------------|
| `GITHUB_TOKEN` | GitHub | PAT with `contents:read` scope |
| `GITLAB_TOKEN` | GitLab | PAT with `read_repository` scope |
| `WEBHOOK_SECRET` | Webhook mode | HMAC key (GitHub) / shared token (GitLab) |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `missing GITHUB_TOKEN environment variable` | Token not exported | `export GITHUB_TOKEN=ghp_...` |
| `GitHub token rejected (401)` | Wrong scope or expired token | Regenerate with `contents:read` |
| `branch "X" not found (404)` | Typo in `--branch` or wrong repo | Verify branch exists in the web UI |
| `webhook signature mismatch` | Secret in env ≠ secret in repo settings | Re-copy `$WEBHOOK_SECRET` to webhook config |
| `rate limit exceeded` | More than 60 webhooks/minute | Check for misconfigured webhook loops |
| `git clone failed` | Network, firewall, or bad token | Check egress rules; verify token can read the repo |
| `cannot create report file` | Output directory missing or not writable | `mkdir -p /reports && chmod 700 /reports` |
