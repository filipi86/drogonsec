<div align="center">

# 🛡️ DragonSec Security Scanner

[![CI/CD](https://github.com/filipi86/drogonsec/actions/workflows/ci.yml/badge.svg)](https://github.com/filipi86/drogonsec/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![OWASP Top 10 2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-orange.svg)](https://owasp.org/Top10/2025/)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://golang.org)

</div>

<img width="1099" height="404" alt="image" src="https://github.com/user-attachments/assets/500be7b6-98ca-43b1-a580-fba6bf32adde" />

> An open-source, comprehensive security scanner combining SAST, SCA, and secret detection aligned with OWASP Top 10:2025 — created for intelligent remediation.

---

## Features

| Engine | Description |
|--------|-------------|
| **SAST** | Static Application Security Testing for 20+ languages |
| **SCA**  | Software Composition Analysis — scan dependencies for CVEs |
| **Leaks** | Secret detection — 50+ patterns (AWS, GCP, GitHub, JWT, SSH keys...) |
| **IaC**  | Infrastructure as Code misconfigurations (Terraform, Kubernetes) |
| **AI**   | AI-powered remediation suggestions (Coming soon) |

### Security Frameworks
- **OWASP Top 10:2025** — All 10 categories covered (including 2 new: Supply Chain & Mishandling Exceptions)
- **CWE** — Common Weakness Enumeration mapping
- **CVSS 3.1** — Severity scoring
- **SARIF 2.1** — GitHub/Azure DevOps integration

### Supported Languages
`Python` `Java` `JavaScript` `TypeScript` `Go` `Kotlin` `C#` `PHP` `Ruby` `Swift` `Dart` `Elixir` `Erlang` `Shell` `C/C++` `HTML` `Terraform` `Kubernetes` `Nginx`

---

## Quick Start

### Installation

**From source (requires Go 1.22+):**
```bash
git clone https://github.com/drogonsec/drogonsec
cd drogonsec
make install
```

**Docker:**
```bash
docker run --rm -v $(pwd):/scan ghcr.io/drogonsec/drogonsec scan /scan
```

### Basic Usage

```bash
# Scan current directory
drogonsec scan .

# Scan with JSON output
drogonsec scan ./myproject --format json --output report.json

# Scan with HTML report
drogonsec scan . --format html --output report.html

# Scan with AI remediation (Coming soon) (requires AI_API_KEY)
export AI_API_KEY="..."
drogonsec scan . --enable-ai

# Scan git history for secrets
drogonsec scan . --git-history

# Only report HIGH and CRITICAL
drogonsec scan . --severity HIGH

# Disable specific engines
drogonsec scan . --no-sca
drogonsec scan . --no-leaks
drogonsec scan . --no-sast
```

---

## Output Formats

### Text (default)
```
🛡 DragonSec Security Scanner
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
  Fix      : Use parameterized queries...
```

### JSON
```json
{
  "version": "0.1.0",
  "stats": { "total_findings": 5, "critical": 1, "high": 3 },
  "sast_findings": [ ... ],
  "sca_findings": [ ... ],
  "leak_findings": [ ... ]
}
```

### SARIF (GitHub Security Integration)
```yaml
# .github/workflows/security.yml
- name: DragonSec Scan
  run: drogonsec scan . --format sarif --output results.sarif
  
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Configuration

Create `.drogonsec.yaml` in your project root:

```yaml
scan:
  min_severity: LOW
  workers: 4
  git_history: false
  ignore_paths:
    - node_modules
    - vendor
    - dist

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

---

## AI Integration (Coming soon)

DrogonSec includes AI-powered remediation (Coming soon), providing intelligent, context-aware fixes for detected vulnerabilities:

```bash
# Set your AI provider API key
export AI_API_KEY="..."

# Enable AI remediation
drogonsec scan . --enable-ai

# Coming soon: use your own AI provider
drogonsec scan . --enable-ai \
  --ai-provider openai \
  --ai-model gpt-4o \
  --ai-endpoint https://your-endpoint/v1/messages

# Example output:
# 🤖 AI Remediation:
# The SQL injection in line 42 allows attackers to manipulate your query...
# Corrected code:
#   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

## OWASP Top 10:2025 Coverage

| # | Category | Status |
|---|----------|--------|
| A01 | Broken Access Control | ✅ 23 rules |
| A02 | Security Misconfiguration | ✅ 31 rules |
| A03 | Software Supply Chain Failures 🆕 | ✅ SCA Engine |
| A04 | Cryptographic Failures | ✅ 18 rules |
| A05 | Injection | ✅ 45 rules |
| A06 | Insecure Design | ✅ 15 rules |
| A07 | Authentication Failures | ✅ 20 rules |
| A08 | Software or Data Integrity Failures | ✅ 9 rules |
| A09 | Security Logging & Alerting Failures | ✅ 11 rules |
| A10 | Mishandling of Exceptional Conditions 🆕 | ✅ 8 rules |

---

## Secret Detection Patterns

DragonSec detects 50+ secret patterns including:

- **Cloud:** AWS Access Keys, GCP API Keys, Azure Storage Keys
- **SCM:** GitHub tokens (classic, fine-grained, OAuth, App)
- **Payment:** Stripe Secret/Restricted Keys
- **Communication:** Slack Bot/App tokens, Webhook URLs
- **Email:** SendGrid API Keys
- **Crypto:** RSA/EC/SSH/PGP private keys, JWT tokens
- **DB:** Connection strings (PostgreSQL, MySQL, MongoDB, Redis)
- **Generic:** Hardcoded passwords, API keys, secrets

---

## Architecture

```
drogonsec/
├── cmd/drogonsec/          # CLI entrypoint
├── internal/
│   ├── analyzer/       # Main orchestrator
│   ├── engine/         # SAST rules engine (20+ languages)
│   ├── leaks/          # Secret detection engine
│   ├── sca/            # Dependency analysis engine
│   ├── reporter/       # Text/JSON/SARIF/HTML reporters
│   ├── ai/             # AI remediation engine (Coming soon)
│   └── config/         # Types and configuration
└── rules/              # YAML rule definitions (community-extensible)
```

---

## Contributing

Contributions are welcome! Areas to contribute:
- New security rules for any language
- Additional secret patterns  
- Parser improvements
- Documentation
- Bug fixes

See [CONTRIBUTING](CONTRIBUTING.md) for guidelines.

---

## License

Apache License 2.0 — See [LICENSE](LICENSE)

---

## Credits

Inspired by Horusec. DragonSec is its modern, actively maintained, and updated with enhanced capabilities.

Built with: Go, Cobra, Viper, go-git.

---

## Maintained by

This open-source project is maintained and supported by **[CROSS-INTEL](https://cross-intel.com)**.
