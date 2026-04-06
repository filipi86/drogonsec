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

## Output Formats

Drogonsec supports four output formats, suited for different workflows:

| Format | Flag | Use Case |
|---|---|---|
| Text (default) | — | Human-readable terminal output |
| JSON | `--format json` | SIEM, automation, further processing |
| HTML | `--format html` | Shareable reports, management presentations |
| SARIF | `--format sarif` | GitHub Security tab, Azure DevOps |

```bash
# JSON report
drogonsec scan ./myproject --format json --output report.json

# HTML report (open in browser)
drogonsec scan . --format html --output report.html

# SARIF for GitHub Security integration
drogonsec scan . --format sarif --output results.sarif
```

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

## AI-Powered Remediation *(Coming soon)*

```bash
# Set your AI provider API key
export AI_API_KEY="your-api-key-here"

# Enable AI remediation suggestions
drogonsec scan . --enable-ai

# Use a custom AI provider and model
drogonsec scan . --enable-ai \
  --ai-provider openai \
  --ai-model gpt-4o \
  --ai-endpoint https://your-endpoint/v1/messages
```

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
          go-version: '1.22'

      - name: Install Drogonsec
        run: |
          git clone https://github.com/filipi86/drogonsec
          cd drogonsec && make install
          sudo mv ./bin/drogonsec /usr/local/bin/

      - name: Run Security Scan
        run: drogonsec scan . --format sarif --output results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
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
