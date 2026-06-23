# Usage Examples

---

## Basic Commands

```bash
# Scan the current directory
drogonsec scan .

# Scan a specific directory
drogonsec scan ./myproject

# Show help
drogonsec --help

# Show version
drogonsec --version
```

---

## Shell Completion

Drogonsec supports rich tab-completion for bash, zsh, fish, and PowerShell.
Completion covers subcommands, enum flag values (`--severity`, `--format`,
`--ai-provider`, `--ai-model`, `--languages`) with inline descriptions, and
directory-only completion for positional paths.

### Quick install (interactive)

```bash
# Detect your shell, show a preview, ask for confirmation, then wire it up.
drogonsec completion install

# Preview only — no files modified:
drogonsec completion install --dry-run

# Automation:
drogonsec completion install --yes
```

The installer writes the completion script to `~/.drogonsec/completion.<shell>`
(mode `0600`) and appends a single `source` line to your shell profile.

### Manual install

```bash
# Bash (add to ~/.bashrc)
source <(drogonsec completion bash)

# Zsh (add to ~/.zshrc)
source <(drogonsec completion zsh)

# Fish
drogonsec completion fish | source

# PowerShell
drogonsec completion powershell | Out-String | Invoke-Expression
```

### Context-aware model suggestions

When you press `<TAB>` after `--ai-model`, the suggestions depend on the
`--ai-provider` already on the command line. For example:

```bash
drogonsec scan . --ai-provider ollama --ai-model <TAB>
#   deepseek-coder    default, 6.7B code model
#   codellama         Meta code model
#   llama3            general-purpose
#   ...

drogonsec scan . --ai-provider anthropic --ai-model <TAB>
#   claude-sonnet-4-6    balanced cost/quality (default)
#   claude-opus-4-7      highest quality
#   claude-haiku-4-5     fastest / cheapest
```

### Security note

`--ai-key` deliberately has **no** completion — neither filesystem nor any
predefined list. This prevents secrets from being captured by shell
history-completion caches (zsh `_history_complete_word`, fish history, etc.).
Always pass your API key via `AI_API_KEY` environment variable.

---

## Output Formats

Drogonsec supports five output formats, suited for different workflows:

| Format | Flag | Use Case |
|---|---|---|
| Text (default) | — | Human-readable terminal output |
| JSON | `--format json` | SIEM, automation, further processing |
| HTML | `--format html` | Shareable reports, management presentations |
| SARIF | `--format sarif` | GitHub Security tab, Azure DevOps |
| CycloneDX | `--format cyclonedx` | SBOM for Grype, Trivy, Dependency-Track |

```bash
# JSON report
drogonsec scan ./myproject --format json --output report.json

# HTML report (open in browser)
drogonsec scan . --format html --output report.html

# SARIF for GitHub Security integration
drogonsec scan . --format sarif --output results.sarif

# CycloneDX SBOM (Software Bill of Materials)
drogonsec scan . --format cyclonedx --output sbom.json
```

> **Tip:** for machine formats (`json`, `sarif`, `cyclonedx`) always pass
> `--output`, so the scan's progress output stays on the terminal and the file
> receives only the clean document.

### CycloneDX SBOM

The `cyclonedx` format exports a [CycloneDX](https://cyclonedx.org) 1.5 JSON
Software Bill of Materials of the dependencies discovered by the SCA engine. Each
dependency becomes a component with a Package URL (purl), so the output is
directly consumable by Grype, Trivy, and Dependency-Track.

Supported ecosystems and their purl types: npm, pypi, golang, maven, gem
(rubygems), composer (packagist), pub.

```bash
drogonsec scan . --format cyclonedx --output sbom.json
```

Example output (truncated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:cadae14d-aa47-44...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-23T12:00:00Z",
    "tools": { "components": [ { "type": "application", "name": "DrogonSec Security Scanner", "version": "0.1.0" } ] },
    "component": { "type": "application", "name": "myproject" }
  },
  "components": [
    { "type": "library", "bom-ref": "pkg:npm/lodash@4.17.15", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15" }
  ]
}
```

> **Scope:** the SBOM is a flat component inventory. The SCA engine resolves
> manifests rather than full lockfiles, so the transitive dependency graph is
> not yet expressed. Transitive resolution and SPDX output are planned for a
> later release. The SBOM is derived from the SCA engine, so do not combine it
> with `--no-sca`.

---

## Controlling Severity

```bash
# Only report HIGH and CRITICAL findings
drogonsec scan . --severity HIGH

# Report everything including LOW
drogonsec scan . --severity LOW

# Report MEDIUM and above
drogonsec scan . --severity MEDIUM
```

---

## Enabling and Disabling Engines

```bash
# Disable SCA (dependency scanning)
drogonsec scan . --no-sca

# Disable secret detection
drogonsec scan . --no-leaks

# Disable SAST (code analysis)
drogonsec scan . --no-sast

# Run only the Leaks engine
drogonsec scan . --no-sast --no-sca

# Run only SAST
drogonsec scan . --no-sca --no-leaks
```

---

## Git History Scanning

```bash
# Scan the full git commit history for secrets
drogonsec scan . --git-history
```

This is essential when onboarding a new repository or auditing code that may have had secrets committed and later deleted. Deleted secrets remain in git history and are fully recoverable by an attacker.

---

## AI-Powered Remediation

DrogonSec provides AI-powered remediation for security findings. **Ollama + DeepSeek Coder** is the recommended open-source option — free, local, and private.

### Local AI (Ollama) — Recommended

```bash
# 1. Install Ollama (https://ollama.com)
# macOS: brew install ollama

# 2. Pull the recommended model
ollama pull deepseek-coder

# 3. Scan with AI (auto-detects local Ollama)
drogonsec scan . --enable-ai

# Use a different local model
drogonsec scan . --enable-ai --ai-provider ollama --ai-model codellama

# Custom timeout for large codebases
drogonsec scan . --enable-ai --ai-timeout 180
```

### Cloud AI (API Key Required)

```bash
# Anthropic
AI_API_KEY="sk-ant-..." drogonsec scan . --enable-ai --ai-provider anthropic

# OpenAI-compatible
AI_API_KEY="sk-..." drogonsec scan . --enable-ai \
  --ai-provider openai \
  --ai-model gpt-4o

# Custom endpoint
AI_API_KEY="..." drogonsec scan . --enable-ai \
  --ai-provider custom \
  --ai-endpoint https://your-endpoint/v1/messages
```

### Progress Counter

When AI remediation is active, Drogonsec displays a per-finding progress counter (e.g., `[3/12] Analyzing finding...`) so you can track the analysis status in real time.

### Response Cache

AI responses are cached in `~/.drogonsec/ai-cache/` with a 7-day TTL. The first scan queries the AI provider for each finding, but subsequent scans with the same findings return cached results instantly, making repeated scans significantly faster.

### AI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-ai` | `false` | Enable AI-powered remediation |
| `--ai-provider` | `anthropic` | Provider: `ollama`, `anthropic`, `openai`, `azure`, `custom` |
| `--ai-model` | *(auto)* | Model override (default: `deepseek-coder` for ollama) |
| `--ai-endpoint` | *(auto)* | Custom API endpoint URL |
| `--ai-key` | *(none)* | API key (or use `AI_API_KEY` env var; not needed for ollama) |
| `--ai-timeout` | `0` | Timeout in seconds (0 = auto: 30s cloud, 120s ollama) |

---

## GitHub Actions Integration

Integrate Drogonsec into your CI/CD pipeline to automatically scan every pull request and push:

```yaml
name: Drogonsec Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Drogonsec
        run: |
          git clone https://github.com/filipi86/drogonsec
          cd drogonsec && make install
          sudo mv ./bin/drogonsec /usr/local/bin/

      - name: Run Security Scan
        run: drogonsec scan . --format sarif --output results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

---

## Configuration File

Create `.drogonsec.yaml` in your project root to avoid repeating flags on every run:

```yaml
scan:
  min_severity: LOW
  workers: 4
  git_history: false
  ignore_paths:
    - node_modules
    - vendor
    - dist
    - .git
    - coverage

engines:
  sast:
    enabled: true
  sca:
    enabled: true
  leaks:
    enabled: true
    min_entropy: 3.5

ai:
  enabled: false
  high_severity_only: true

fail_on:
  critical: true
  high: true
```

With `fail_on.critical: true`, Drogonsec exits with a non-zero code when critical findings are detected, automatically failing your CI/CD pipeline.

---

## Output Examples

### Text Output (default)

```
🛡 Drogonsec Security Scanner
═══════════════════════════════════════════
  Target : /path/to/project
  SAST   : enabled
  SCA    : enabled
  Leaks  : enabled
═══════════════════════════════════════════

═══ SAST FINDINGS ══════════════════════
  #1 [HIGH] SQL Injection via string formatting
  File     : src/users.py:42
  Rule     : PY-001
  OWASP    : A05:2025 - Injection
  CWE      : CWE-89  CVSS: 9.8
  Fix      : Use parameterized queries instead of string formatting

═══ LEAK FINDINGS ═══════════════════════
  #1 [CRITICAL] AWS Access Key found
  File     : config/deploy.sh:14
  Pattern  : AWS_ACCESS_KEY_ID
  Entropy  : 4.2
  Fix      : Remove, rotate in AWS IAM, use environment variables

═══ SCA FINDINGS ════════════════════════
  #1 [HIGH] CVE-2023-44487 in golang.org/x/net v0.8.0
  Fixed in : v0.17.0
  CVSS     : 7.5

═══════════════════════════════════════════
  Total: 3 findings  |  Critical: 1  |  High: 2
═══════════════════════════════════════════
```

### JSON Output

```json
{
  "version": "0.1.0",
  "target": "./myproject",
  "stats": {
    "total_findings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "sast_findings": [
    {
      "id": "PY-001",
      "severity": "HIGH",
      "title": "SQL Injection via string formatting",
      "file": "src/users.py",
      "line": 42,
      "owasp": "A05:2025",
      "cwe": "CWE-89",
      "cvss": 9.8,
      "fix": "Use parameterized queries"
    }
  ],
  "leak_findings": [],
  "sca_findings": []
}
```

---

## Practical Security Workflows

### Onboarding a New Repository

When auditing a repository for the first time, run a full scan including git history:

```bash
git clone https://github.com/org/repo
cd repo
drogonsec scan . --git-history --severity LOW --format html --output audit-report.html
```

### Pre-commit Hook

Block commits that introduce secrets:

```bash
#!/bin/sh
# .git/hooks/pre-commit
drogonsec scan . --no-sast --no-sca --severity HIGH
if [ $? -ne 0 ]; then
  echo "Drogonsec: secrets detected. Commit blocked."
  exit 1
fi
```

### Scheduled Nightly Scan

```bash
# crontab -e
0 2 * * * cd /path/to/project && drogonsec scan . --format json --output /reports/nightly-$(date +\%Y\%m\%d).json
```

### Integration with jq for Filtering

```bash
# Count critical findings
drogonsec scan . --format json | jq '.stats.critical'

# List all HIGH and CRITICAL files
drogonsec scan . --format json | jq '[.sast_findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | .file] | unique'
```

---

## Tips for Security Professionals

- Always run Drogonsec inside an **isolated VM** when analyzing potentially malicious code
- Use `--git-history` on every new repository to audit past commits for leaked secrets
- Combine with **YARA**, **Semgrep**, or **TheHive** for a complete analysis workflow
- Use `fail_on.critical: true` in CI/CD to block deployments with critical vulnerabilities
- Set `min_entropy: 4.0` for fewer false positives in large codebases with many random strings
- Use `--format html` for management-friendly reports that require no technical interpretation
