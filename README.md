<div align="center">

# 🛡️ Drogonsec Security Scanner

[![CI/CD](https://github.com/filipi86/drogonsec/actions/workflows/ci.yml/badge.svg)](https://github.com/filipi86/drogonsec/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![OWASP Top 10 2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-orange.svg)](https://owasp.org/Top10/2025/)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://golang.org)
[![GitHub Release](https://img.shields.io/github/v/release/filipi86/drogonsec)](https://github.com/filipi86/drogonsec/releases)
[![GitHub Issues](https://img.shields.io/github/issues/filipi86/drogonsec)](https://github.com/filipi86/drogonsec/issues)

</div>

<img width="1099" height="398" alt="image" src="https://github.com/user-attachments/assets/d6b8efb1-7fe4-4c25-9f20-1a430d4a769c" />


> An open-source, comprehensive security scanner combining SAST, SCA, and secret detection aligned with OWASP Top 10:2025 — created for intelligent remediation.

---

## Documentation

📖 **Full Documentation:** -->  [Drogonsec Doc](https://cross-intel.com/opensource/drogonsec)

---

## Features

| Engine | Description |
|--------|-------------|
| **SAST** | Static Application Security Testing for 20+ languages |
| **SCA**  | Software Composition Analysis — scan dependencies for CVEs |
| **Leaks** | Secret detection — 50+ patterns (AWS, GCP, GitHub, JWT, SSH keys...) |
| **IaC**  | Infrastructure as Code misconfigurations (Terraform, Kubernetes) |
| **AI**   | AI-powered remediation — Ollama (local/free) or cloud providers |

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

**Go Install (requires Go 1.25+):**
```bash
go install github.com/filipi86/drogonsec/cmd/drogonsec@latest
```

**From source:**
```bash
git clone https://github.com/filipi86/drogonsec
cd drogonsec
make install
```

**Docker:**
```bash
docker run --rm -v $(pwd):/scan ghcr.io/filipi86/drogonsec scan /scan
```

### Basic Usage

```bash
# Scan current directory
drogonsec scan .

# Scan with JSON output
drogonsec scan ./myproject --format json --output report.json

# Scan with HTML report
drogonsec scan . --format html --output report.html

# Scan with AI remediation (local Ollama — free, no API key needed)
drogonsec scan . --enable-ai

# Scan with AI remediation (cloud provider — requires API key)
AI_API_KEY="..." drogonsec scan . --enable-ai --ai-provider anthropic

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
Drogonsec Security Scanner
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
- name: DrogonSec Scan
  run: drogonsec scan . --format sarif --output results.sarif
  
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v4
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

## AI-Powered Remediation

DrogonSec includes AI-powered remediation, providing intelligent, context-aware fixes for detected vulnerabilities. **Ollama + DeepSeek Coder** is the recommended open-source option — **Ollama is open-source (MIT license)** and runs 100% locally with no data leaving your machine.

### Local AI (Ollama) — Recommended for OSS

```bash
# 1. Install Ollama (https://ollama.com)
# macOS: brew install ollama

# 2. Pull the recommended model
ollama pull deepseek-coder

# 3. Scan with AI (auto-detects local Ollama)
drogonsec scan . --enable-ai

# Use a different model
drogonsec scan . --enable-ai --ai-provider ollama --ai-model codellama
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

# Example output:
# 🤖 AI Remediation:
# The SQL injection in line 42 allows attackers to manipulate your query...
# Corrected code:
#   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Bring Your Own AI

Any OpenAI-compatible endpoint works as a custom provider:

```bash
AI_API_KEY="your-key" drogonsec scan . --enable-ai \
  --ai-provider custom \
  --ai-endpoint https://your-api/v1/messages
```

### Security Hardening

The AI client includes several defensive controls, documented in [docs/security.md](docs/security.md):

- **No HTTP redirects** — refuses 3xx responses to prevent `x-api-key` leaking to a third-party host via `302 Location: …`
- **HTTPS enforcement** — non-loopback HTTP endpoints are rejected; only `https://` or `http://127.0.0.1`/`http://localhost` are accepted
- **HMAC-SHA256 cache integrity** — every cached response is tagged with a per-user key under `~/.drogonsec/ai-cache/cache.key` (`0600`); tampered entries are discarded on read
- **Ollama shape validation** — auto-detection requires a valid `{"models":[...]}` response from `/api/tags`, not just HTTP 200 on port 11434
- **Cache + output perms** — cache dir is `0700`, every cached file and every `--output` report is `0600` (reports embed code snippets and secrets)

---

## Shell Completion

Drogonsec supports rich tab-completion for bash, zsh, fish, and PowerShell — with inline descriptions for enum flags, context-aware model suggestions, and directory-only completion for scan paths. See the [Usage docs](docs/usage.md#shell-completion) for details.

```bash
# Interactive install (detects shell, previews, asks for confirmation)
drogonsec completion install

# Preview only — no files modified
drogonsec completion install --dry-run

# Manual (bash / zsh)
source <(drogonsec completion bash)
source <(drogonsec completion zsh)
```

> **Security note:** `--ai-key` is deliberately excluded from completion so API keys are never captured by shell history-completion caches. Always pass keys via `AI_API_KEY`.

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

Drogonsec detects 50+ secret patterns including:

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
│   ├── ai/             # AI remediation engine (Ollama + Cloud)
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

Inspired by Horusec. DrogonSec is its modern, actively maintained, and updated with enhanced capabilities.

Built with: Go, Cobra, Viper, go-git.

---

## Maintained by

This open-source project is maintained and supported by **[CROSS-INTEL](https://cross-intel.com)**.

---

## Links

📖 **Documentation:** [cross-intel.com/opensource/drogonsec](https://cross-intel.com/opensource/drogonsec)
