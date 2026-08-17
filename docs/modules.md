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
| **AI Remediation** | `--enable-ai` to activate | AI-powered fix suggestions (Ollama OSS or Cloud) |

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

The SCA engine works out which third-party packages your project actually
installs, and checks each one against known advisories. It maps directly to
**A03:2025 — Software Supply Chain Failures**, one of the two new categories in
OWASP Top 10:2025.

"Actually installs" is the whole job. A manifest names a handful of packages at
version *ranges*; a lockfile names every package that will be installed, at the
version it will be installed at. The second group is nearly all the code that
ships and holds nearly all the advisories, so the engine reads lockfiles and
installed trees wherever they exist and falls back to the manifest only when
they do not.

### Where dependencies are read from

| Ecosystem | Files | Depth |
|---|---|---|
| **Node.js** | `package-lock.json`, `yarn.lock`, `node_modules/`, `package.json` | Full tree |
| **Python** | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `.venv/`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt` | Full tree |
| **Go** | `go.mod` | Declared, including `// indirect` entries |
| **Java** | `pom.xml` | Declared only |
| **Ruby** | `Gemfile.lock` | Full tree |
| **PHP** | `composer.lock`, `vendor/composer/installed.json`, `composer.json` | Full tree |
| **Rust** | `Cargo.lock`, `Cargo.toml` | Full tree |
| **Dart** | `pubspec.yaml`, `pubspec.yml` | Declared only |

**Depth is the column that matters.** A manifest states what a project asked
for: a handful of names, at version *ranges*. A lockfile states what was
actually installed: an exact version for every package in the tree, including
the ones nobody named. Vulnerabilities overwhelmingly live in that second
group, so an ecosystem marked "declared only" is reporting on a fraction of the
code that ships.

### A range is not a version

A dependency read from a manifest is matched against advisories **only when the
requirement names a single release**. `lodash: "4.17.15"` is answerable;
`lodash: "^4.17.15"` is not, and is reported as inventory without a finding.

The reason is that the two are not close. `^4.17.15` installs 4.17.21, and
matching the number left after the caret is stripped reports advisories that no
longer apply to the code that ships — with a version number beside them the
project may never have installed. The scan says how many packages this affects
rather than passing over them in silence:

```
Found 41 dependencies across 3 manifest files
12 declared at version ranges, not checked against advisories — commit a lockfile to cover them
```

Resolving a range would take a registry and a network call, which is the one
thing the SCA engine does not do. Committing a lockfile is the fix, and it is
also the better answer: it covers the transitive tree at the same time.

What counts as a pin is the ecosystem's own rule. `1.2.3` names one release in
npm, Composer, pip and pub — but **in Cargo it is shorthand for `^1.2.3`**, so
there only `=1.2.3` pins. pip's pin is `==`, and a second specifier undoes it:
`torch==2.0.*,!=2.0.1` is a span. Lockfile entries are resolved by definition
and are always matched.

Where both exist for the same project, the lockfile wins and the manifest is
ignored — otherwise every declared dependency would be counted twice, the
second time at a range that matches no advisory. A project carrying both npm
and yarn lockfiles, as happens when a migration leaves the old one behind, is
read from `package-lock.json`.

`yarn.lock` is understood in both of its formats: the bespoke text of Yarn 1 and
the YAML of Yarn 2 and later. Neither records which packages the project itself
declared, so the sibling `package.json` supplies that; without one every package
is still reported and only the direct/transitive split is lost.

For npm, PHP and Python the engine falls back through three sources, in this order:

1. **A lockfile** — `package-lock.json`, then `yarn.lock`; `composer.lock` for
   PHP; `poetry.lock`, `uv.lock` or `Pipfile.lock` for Python. What *will* be
   installed, reproducibly.
2. **The installed tree on disk** — what *is* installed. Read only when no
   lockfile covers the project, which makes a repository that does not commit
   one scannable in full: a CI job that runs `npm ci` or `composer install`
   before the scan, or any working copy after an install. For npm that means
   `node_modules/`, where each package carries its own manifest and the
   directory layout is the resolution; for PHP it means
   `vendor/composer/installed.json`, in which Composer records the whole
   resolved graph in one file, in either the Composer 1 or the Composer 2 shape;
   for Python it means the project's virtualenv.
3. **The manifest** — `package.json`, `composer.json`, `pyproject.toml` or
   `requirements.txt`, the declared dependencies at ranges. The last resort,
   and the only one that leaves the transitive tree unseen.

None of the three touches the network. Resolving ranges against a registry would
answer a different question — what would be installed today — and would put a
scan that currently runs air-gapped on the far side of the internet.

Composer resolves one version of a package for the whole project, so a
`composer.lock` gives the full tree with no ambiguity to resolve. What it does
not record is which packages the project itself asked for; the sibling
`composer.json` supplies that, and without one every package is still reported
and only the direct/transitive split is lost. Platform requirements — `php`,
`ext-json`, `composer-runtime-api` — are not packages and are never reported.

Rust has the two ends and no middle: `Cargo.lock`, then `Cargo.toml`. There is
no installed-tree tier because Cargo keeps no equivalent record of one.
`Cargo.lock` is the only lockfile that names the root project itself — a
workspace member or path dependency is written with no `source`, because it was
never fetched — so the direct dependencies are read from the lockfile alone.
Two versions of one crate in the same tree are normal in Rust and are reported
separately, each with its own route: `time 0.1.45` pulled in by `chrono` is a
different finding from a declared `time 0.3.9`.

Python installs one version of a distribution per environment, so `poetry.lock`
gives the full tree by name alone. The catch is that a name is written several
ways — jinja2 requires `MarkupSafe`, and the package satisfying it is locked as
`markupsafe` — so edges are matched in the normal form PEP 503 defines: lower
case, with every run of `-`, `_` and `.` collapsed to a single `-`. The direct
set comes from the sibling `pyproject.toml`, read in both layouts a modern
project can use: the standard `[project]` table and Poetry's own
`[tool.poetry.dependencies]` with its per-group tables. Development groups
count — they are installed by a plain `poetry install`.

Python's three lockfiles are read, and they do not all say the same amount.
`poetry.lock` and `uv.lock` record the dependency edges, so a finding comes with
the route that introduced it. **`Pipfile.lock` records none** — it is a flat map
of name to resolved version — so that tier buys the transitive set at exact
versions, which is what decides whether an advisory matches, and reports
transitive findings with no route rather than inventing one. Where the direct
set comes from also differs: `uv.lock` names the project itself, the way
`Cargo.lock` does, while `poetry.lock` needs `pyproject.toml` and
`Pipfile.lock` needs the `Pipfile`.

Python's installed tier is the virtualenv: `.venv/` or `venv/`, where every
installed distribution carries a `*.dist-info/METADATA` naming itself, its
version and its `Requires-Dist`. Together those are the whole graph, so this
tier gives routes where `Pipfile.lock` cannot. A requirement gated behind an
extra — `argon2-cffi ; extra == 'argon2'` — is not an edge, because it is not
installed unless the extra was asked for. What the virtualenv brought in itself,
`pip` and `setuptools`, is reported with no route: installed code that can carry
advisories, reachable from nothing the project declared. Only a project-local
virtualenv is read; a shared or system environment answers a different question.

Not yet parsed, so a project relying on one of these is **not** covered by the
ecosystem's row above: `pnpm-lock.yaml`, `go.sum`, Gradle builds, and the .NET
ecosystem entirely.

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

### SBOM Export (CycloneDX)

The dependency inventory the SCA engine builds can be exported as a
[CycloneDX](https://cyclonedx.org) 1.5 Software Bill of Materials, so it can be
consumed by Grype, Trivy, and Dependency-Track:

```bash
drogonsec scan . --format cyclonedx --output sbom.json
```

Each dependency becomes a CycloneDX component with a Package URL (purl). The v1
SBOM is a flat component list; the transitive dependency graph and SPDX output
are planned for a later release. See [Usage → Output Formats](usage.md#output-formats)
for details.

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

## AI Remediation Engine

The AI engine provides intelligent, context-aware fix suggestions for detected vulnerabilities. It understands the code context around each finding and generates corrected code snippets.

### Capabilities

- Context-aware code fixes tailored to the specific vulnerability
- **Ollama + DeepSeek Coder** — free, local, private (recommended for OSS)
- Cloud providers: Anthropic, OpenAI, Azure, custom endpoints
- Auto-detection of local Ollama when no API key is provided
- High-severity-only enrichment (CRITICAL and HIGH findings)
- Inline corrected code snippets alongside each finding
- Leak remediation guidance (secret rotation, CI/CD prevention)

### Architecture

```
CLI (--enable-ai)
    |
    v
ai.Client (internal/ai/claude.go)
    |
    +-- isOllama? --> callOllama() --> POST http://127.0.0.1:11434/api/generate
    |                                  (no auth, 120s timeout)
    |
    +-- cloud? ----> callCloud()  --> POST https://api.anthropic.com/v1/messages
                                     (API key auth, 30s timeout)
```

### Providers

| Provider | API Key | Default Model | Local |
|----------|---------|---------------|-------|
| `ollama` | Not required | `deepseek-coder` | Yes |
| `anthropic` | Required | `claude-sonnet-4-6` | No |
| `openai` | Required | *(user-specified)* | No |
| `azure` | Required | *(user-specified)* | No |
| `custom` | Required | *(user-specified)* | No |

### Usage

```bash
# Local AI — auto-detects Ollama
drogonsec scan . --enable-ai

# Explicit Ollama with custom model
drogonsec scan . --enable-ai --ai-provider ollama --ai-model codellama

# Cloud AI
AI_API_KEY="..." drogonsec scan . --enable-ai --ai-provider anthropic
```

### Response Cache

AI responses are cached locally in `~/.drogonsec/ai-cache/` with a 7-day TTL. This means:

- The first scan analyzes each finding via the AI provider
- Subsequent scans with the same findings return cached responses instantly
- Cache entries expire automatically after 7 days
- Delete `~/.drogonsec/ai-cache/` to clear the cache manually

### Bring Your Own AI

Any OpenAI-compatible endpoint works as a custom provider. This includes self-hosted models, corporate proxies, or alternative AI services:

```bash
AI_API_KEY="your-key" drogonsec scan . --enable-ai \
  --ai-provider custom \
  --ai-endpoint https://your-api/v1/messages
```

Set `--ai-model` to specify which model the endpoint should use. The only requirement is that the endpoint accepts the standard chat completions format.

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
