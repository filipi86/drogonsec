# Contributing to DrogonSec

Thank you for your interest in contributing to **DrogonSec**! This project is a community-driven security scanner, and every contribution matters — from new detection rules to bug fixes, documentation, and performance improvements.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Adding Security Rules](#adding-security-rules)
  - [Adding Secret Patterns](#adding-secret-patterns)
  - [Improving Parsers or Engines](#improving-parsers-or-engines)
  - [Documentation](#documentation)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

This project follows a **Contributor Covenant** approach. Be respectful, inclusive, and constructive. Harassment, discrimination, or bad-faith contributions will not be tolerated.

---

## Getting Started

### Prerequisites

| Tool | Version |
|------|---------|
| Go | 1.22+ |
| Git | any recent |
| golangci-lint | latest (optional, for linting) |
| Docker | optional |

### Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/drogonsec.git
cd drogonsec
go mod download
```

### Build & Run

```bash
make build          # Build binary to ./bin/drogonsec
make run            # Build and scan the current directory
make test           # Run all tests
make lint           # Run linters
```

---

## Project Structure

```
drogonsec/
├── cmd/drogonsec/          # CLI entrypoint (Cobra)
├── internal/
│   ├── analyzer/           # Main orchestrator — coordinates all engines
│   ├── engine/             # SAST rules engine (20+ languages)
│   ├── leaks/              # Secret detection engine
│   ├── sca/                # Software Composition Analysis
│   ├── reporter/           # Output formatters (text, JSON, SARIF, HTML)
│   ├── ai/                 # AI remediation engine (Coming soon)
│   ├── cli/                # Banner, scan header, summary UI
│   └── config/             # Types and configuration structs
└── rules/                  # YAML rule definitions (community-extensible)
    ├── golang/
    ├── java/
    ├── javascript/
    ├── python/
    └── leaks/
```

---

## How to Contribute

### Reporting Bugs

1. Check if the issue [already exists](https://github.com/filipi86/drogonsec/issues).
2. Open a new issue using the **Bug Report** template.
3. Include:
   - DrogonSec version (`drogonsec --version`)
   - OS and Go version
   - Minimal reproduction case (sanitized code snippet)
   - Full command and output

### Suggesting Features

Open a **Feature Request** issue describing:
- The problem you're trying to solve
- Your proposed solution
- Alternatives considered

### Adding Security Rules

Rules live in `rules/<language>/*.yaml` and are the easiest way to contribute.

**Rule structure:**

```yaml
id: PY-001
name: SQL Injection via string formatting
description: Detects SQL queries built with string formatting or concatenation.
language: python
severity: HIGH
owasp: A05:2025
cwe: CWE-89
cvss: 9.8
patterns:
  - 'execute\s*\(\s*["\'].*%[s|d].*["\']'
  - 'execute\s*\(\s*f["\'].*\{.*\}'
fix: Use parameterized queries instead of string formatting.
references:
  - https://owasp.org/Top10/A05_2021-Injection/
  - https://cwe.mitre.org/data/definitions/89.html
```

**Rule checklist:**

- [ ] ID follows the convention: `<LANG>-<3-digit-number>` (e.g., `GO-012`, `JS-034`)
- [ ] Regex patterns are tested against real vulnerable code
- [ ] `severity` is one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- [ ] `owasp` references OWASP Top 10:2025 categories
- [ ] `cwe` includes a valid CWE identifier
- [ ] `fix` provides actionable remediation guidance
- [ ] False-positive rate is acceptable

**Supported languages:** `python`, `java`, `javascript`, `golang`, `kotlin`, `csharp`, `php`, `ruby`, `swift`, `dart`, `elixir`, `erlang`, `shell`, `c`, `html`, `terraform`, `kubernetes`, `nginx`

### Adding Secret Patterns

Secret patterns live in `rules/leaks/`. Each pattern should detect credentials or sensitive tokens with low false-positive rates.

```yaml
id: LEAK-051
name: GitHub Fine-Grained Personal Access Token
pattern: 'github_pat_[A-Za-z0-9_]{82}'
entropy: 4.5
severity: CRITICAL
fix: Revoke the token immediately at https://github.com/settings/tokens
```

**Pattern checklist:**

- [ ] Pattern is specific enough to avoid broad false positives
- [ ] Entropy threshold set where applicable (for high-randomness secrets)
- [ ] Tested against real and fake token formats
- [ ] `fix` provides a direct link or action for remediation

### Improving Parsers or Engines

If you're modifying `internal/engine/`, `internal/leaks/`, or `internal/sca/`:

- Keep engine changes backward-compatible with existing rules
- Add unit tests covering the new behavior
- Benchmark critical paths if performance is affected (`go test -bench=.`)
- Document exported functions with Go doc comments

### Documentation

- Fix typos or improve clarity in `README.md` or `CONTRIBUTING.md`
- Add examples for new rules or features
- Improve inline Go doc comments

---

## Development Setup

```bash
# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Format code
make fmt

# Run linter
make lint

# Run tests with coverage
make test-coverage
# Opens coverage.html

# Run tests with race detector
make test-race

# Scan DrogonSec's own source code
make scan-self
```

---

## Testing

Every new rule or engine change **must** include tests.

```bash
# Run all tests
make test

# Run tests for a specific package
go test ./internal/engine/... -v

# Run a specific test
go test ./internal/leaks/... -run TestDetectGitHubToken -v
```

**Test expectations:**

- Each rule should have at least one **true positive** test case (code that should trigger the rule)
- Each rule should have at least one **true negative** test case (safe code that should NOT trigger)
- Engine integration tests live in `internal/analyzer/`

---

## Code Style

This project follows standard Go conventions:

- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch common mistakes
- Exported symbols must have Go doc comments
- Error handling must be explicit — do not silently ignore errors
- Prefer table-driven tests

**Commit message format:**

```
<type>(<scope>): <short description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
```
feat(rules): add Go SSRF detection rule GO-021
fix(engine): correct regex for PHP RCE pattern
docs(readme): update installation instructions
```

---

## Pull Request Process

1. **Branch** from `main`:
   ```bash
   git checkout -b feat/add-go-ssrf-rule
   ```

2. **Implement** your change with tests.

3. **Verify** everything passes:
   ```bash
   make fmt && make lint && make test
   ```

4. **Push** and open a PR against `main`:
   ```bash
   git push origin feat/add-go-ssrf-rule
   ```

5. Fill in the **PR template** with:
   - What changed and why
   - How it was tested
   - Related issues (`Closes #123`)

6. A maintainer will review and may request changes. Once approved, your PR will be merged.

---

## Questions?

Open a [Discussion](https://github.com/filipi86/drogonsec/discussions) or reach out via Issues. We're happy to help guide new contributors.

**Happy hunting! 🐉**
