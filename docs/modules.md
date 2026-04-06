# Modules & Engines

Drogonsec is composed of specialized scanning engines, each targeting a different attack surface. All engines run in parallel by default and can be individually enabled or disabled via CLI flags or the configuration file.

---

## Engine Overview

| Engine | CLI Flag to Disable | Description |
|--------|---------------------|-------------|
| **SAST** | `--no-sast` | Static code analysis for 20+ languages |
| **SCA** | `--no-sca` | Dependency and supply chain vulnerability scanning |
| **Leaks** | `--no-leaks` | Secret and credential detection (50+ patterns) |
| **IaC** | built-in with SAST | Infrastructure as Code misconfiguration detection |
| **AI Remediation** | `--enable-ai` to activate | Intelligent fix suggestions *(coming soon)* |

---

## SAST Engine — Static Application Security Testing

The SAST engine analyzes source code for security vulnerabilities without executing it. It applies pattern-matching rules across 20+ programming languages and maps every finding to OWASP, CWE, and CVSS standards.

### Supported Languages

`Python` `Java` `JavaScript` `TypeScript` `Go` `Kotlin` `C#` `PHP` `Ruby` `Swift` `Dart` `Elixir` `Erlang` `Shell` `C/C++` `HTML` `Terraform` `Kubernetes` `Nginx`

### What the SAST Engine Detects

| Vulnerability | Example | OWASP |
|---|---|---|
| SQL Injection | String formatting in queries | A05:2025 |
| Command Injection | `os.system()` with user input | A05:2025 |
| Cross-Site Scripting (XSS) | Unescaped output in templates | A05:2025 |
| Hardcoded credentials | API keys in source files | A07:2025 |
| Insecure cryptography | MD5, DES, weak key sizes | A04:2025 |
| Broken authentication | Missing token validation | A07:2025 |
| Insecure deserialization | `pickle.loads()` on user input | A08:2025 |
| Path traversal | Unvalidated file paths | A01:2025 |
| SSRF | Unvalidated URL fetch | A05:2025 |
| XXE | Unsafe XML parsers | A05:2025 |
| Missing exception handling | Bare `except:` blocks | A10:2025 |
| Security logging failures | No audit trail on sensitive ops | A09:2025 |

### Example SAST Finding

```
#1 [HIGH] SQL Injection via string formatting
File     : src/users.py:42
Rule     : PY-001
OWASP    : A05:2025 - Injection
CWE      : CWE-89
CVSS     : 9.8
Fix      : Use parameterized queries instead of string formatting
```

### SAST Rules

Rules are defined as YAML files in the `rules/` directory and are fully community-extensible:

```yaml
id: PY-001
name: SQL Injection via string formatting
severity: HIGH
language: python
pattern: "cursor.execute(.*%.*)"
owasp: A05:2025
cwe: CWE-89
cvss: 9.8
message: "Avoid building SQL queries with string formatting or concatenation."
fix: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
```

---

## SCA Engine — Software Composition Analysis

The SCA engine scans your project's dependency manifest files for known CVEs, outdated packages, and supply chain risks. It maps directly to **A03:2025 — Software Supply Chain Failures**, one of the two new categories in OWASP Top 10:2025.

### Supported Manifest Files

| Ecosystem | Files |
|---|---|
| **Node.js** | `package.json`, `package-lock.json`, `yarn.lock` |
| **Python** | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml` |
| **Go** | `go.mod`, `go.sum` |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| **Ruby** | `Gemfile`, `Gemfile.lock` |
| **PHP** | `composer.json`, `composer.lock` |
| **Rust** | `Cargo.toml`, `Cargo.lock` |
| **.NET** | `*.csproj`, `packages.config` |

### What the SCA Engine Reports

- CVE identifier and description
- Affected package name and version
- Fixed version (if available)
- CVSS severity score
- Direct vs transitive dependency flag

### Example SCA Finding

```
#1 [CRITICAL] CVE-2023-44487 — HTTP/2 Rapid Reset Attack
Package  : golang.org/x/net v0.8.0
Fixed in : v0.17.0
CVSS     : 7.5
OWASP    : A03:2025 - Software Supply Chain Failures
```

---

## Leaks Engine — Secret Detection

The Leaks engine scans source code, configuration files, and git commit history for hardcoded secrets, API keys, tokens, and credentials. It uses entropy analysis combined with pattern matching for high accuracy.

### Detection Categories (50+ patterns)

| Category | Patterns Detected |
|---|---|
| **Cloud — AWS** | Access Key ID, Secret Access Key, Session Token |
| **Cloud — GCP** | API Keys, Service Account JSON, OAuth tokens |
| **Cloud — Azure** | Storage Account Keys, Connection Strings, SAS tokens |
| **Source Control** | GitHub tokens (classic, fine-grained, OAuth, GitHub App) |
| **Payment** | Stripe Secret Keys, Restricted Keys, Webhook secrets |
| **Communication** | Slack Bot tokens, App tokens, Webhook URLs |
| **Email** | SendGrid API Keys, Mailgun API Keys |
| **Cryptographic** | RSA private keys, EC private keys, SSH private keys, PGP keys |
| **Authentication** | JWT tokens, Bearer tokens, Basic auth credentials |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| **Generic** | Hardcoded passwords, generic API keys and secrets |

### Entropy Analysis

The engine uses Shannon entropy to flag high-randomness strings that are likely to be secrets, even when they don't match known patterns:

```yaml
engines:
  leaks:
    enabled: true
    min_entropy: 3.5    # adjust sensitivity (default: 3.5)
```

### Git History Scanning

```bash
drogonsec scan . --git-history
```

This scans every commit in the repository history, not just the current state of the working directory. This is critical for catching secrets that were added and later deleted — they still exist in git history and are fully recoverable.

### Example Leak Finding

```
#1 [CRITICAL] AWS Access Key found
File     : config/deploy.sh:14
Pattern  : AWS_ACCESS_KEY_ID
Value    : AKIA****************EXAMPLE
Entropy  : 4.2
OWASP    : A07:2025 - Authentication Failures
CWE      : CWE-312
Fix      : Remove the key, rotate it immediately in AWS IAM, and use environment variables or a secrets manager
```

---

## IaC Engine — Infrastructure as Code

The IaC engine detects security misconfigurations in infrastructure definition files. It runs as part of the SAST engine and applies IaC-specific rule sets.

### Supported Formats

| Format | Coverage |
|---|---|
| **Terraform** | AWS, GCP, Azure resources |
| **Kubernetes** | Pod security, RBAC, network policies, resource limits |
| **Dockerfile** | Image best practices, privilege escalation risks |
| **Nginx** | TLS configuration, security headers |

### Common Detections

- Public S3 buckets with no access control
- Overly permissive IAM roles (`*` actions or resources)
- Missing encryption at rest on storage resources
- Containers running as root (`runAsRoot: true`)
- Exposed sensitive ports (22, 3306, 5432) to the internet
- Missing Kubernetes resource limits (CPU, memory)
- Insecure TLS versions or cipher suites in Nginx
- Docker images using `latest` tag (supply chain risk)

### Example IaC Finding

```
#1 [HIGH] S3 bucket is publicly accessible
File     : infra/storage.tf:12
Rule     : TF-AWS-S3-001
OWASP    : A02:2025 - Security Misconfiguration
CWE      : CWE-732
Fix      : Set `acl = "private"` and enable `block_public_acls = true`
```

---

## AI Remediation Engine *(Coming soon)*

The AI engine provides intelligent, context-aware fix suggestions for detected vulnerabilities. It understands the code context around each finding and generates corrected code snippets.

### Planned Capabilities

- Context-aware code fixes tailored to the specific vulnerability
- Support for multiple AI providers (OpenAI, Anthropic, custom endpoints)
- High-severity-only mode to reduce noise in large codebases
- Inline corrected code snippets alongside each finding
- Batch remediation reports exportable as patch files

### Usage Preview

```bash
# Set your AI provider API key
export AI_API_KEY="your-api-key-here"

# Enable AI remediation
drogonsec scan . --enable-ai

# Use a custom AI provider
drogonsec scan . --enable-ai \
  --ai-provider openai \
  --ai-model gpt-4o \
  --ai-endpoint https://your-endpoint/v1/messages
```

### Example AI Output Preview

```
🤖 AI Remediation for Finding #1:

The SQL injection on line 42 of src/users.py allows an attacker to
manipulate the database query by injecting malicious SQL through
the `user_id` parameter.

Vulnerable code:
  cursor.execute("SELECT * FROM users WHERE id = " + user_id)

Corrected code:
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

Explanation:
  Parameterized queries ensure that user input is always treated as
  data, never as part of the SQL statement, preventing injection attacks.
```

---

## OWASP Top 10:2025 Full Coverage

| # | Category | Engine(s) | Rules |
|---|----------|-----------|-------|
| A01 | Broken Access Control | SAST | ✅ 23 rules |
| A02 | Security Misconfiguration | SAST + IaC | ✅ 31 rules |
| A03 | Software Supply Chain Failures 🆕 | SCA | ✅ Full engine |
| A04 | Cryptographic Failures | SAST + Leaks | ✅ 18 rules |
| A05 | Injection | SAST | ✅ 45 rules |
| A06 | Insecure Design | SAST | ✅ 15 rules |
| A07 | Authentication Failures | SAST + Leaks | ✅ 20 rules |
| A08 | Software or Data Integrity Failures | SCA + SAST | ✅ 9 rules |
| A09 | Security Logging & Alerting Failures | SAST | ✅ 11 rules |
| A10 | Mishandling of Exceptional Conditions 🆕 | SAST | ✅ 8 rules |

---

## Writing Custom Rules

All SAST rules are YAML files in the `rules/` directory, making them easy to contribute to the community:

```yaml
id: CUSTOM-001
name: Dangerous use of eval() with user input
severity: HIGH
language: python
pattern: "eval(.*request.*)"
owasp: A05:2025
cwe: CWE-95
cvss: 8.8
message: "Avoid using eval() with any user-supplied or external input."
fix: "Use ast.literal_eval() for safe evaluation of literals, or refactor to avoid dynamic evaluation entirely."
```

To add the rule, place it in `rules/custom/my-rule.yaml` and rebuild:

```bash
make install
```
