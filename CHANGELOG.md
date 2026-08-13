# Changelog

All notable changes to **DrogonSec** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-13

Precision release. The SAST engine went through an empirically-audited pass
against real open-source projects to cut false positives without trading them
for false negatives, six languages gained rule coverage, and the supply chain
of the build itself was hardened.

### Added

- **CycloneDX SBOM export** (`--format cyclonedx`): emits a CycloneDX 1.5 JSON
  Software Bill of Materials of the dependencies discovered by the SCA engine,
  with Package URLs (purls) per ecosystem (npm, pypi, golang, maven, gem,
  composer, pub). Flat component inventory, deduplicated and consumable by
  Grype, Trivy, and Dependency-Track. Transitive graph and SPDX output are
  planned for a later release. ([#31](https://github.com/filipi86/drogonsec/issues/31))
- **SAST coverage for 6 new languages**: Elixir (`EX-*`), C/C++ (`C-*`),
  Swift (`SW-*`), Dart (`DART-*`), Erlang (`ERL-*`), and Nginx (`NGINX-*`),
  plus `TF-006` for IAM wildcard policies in Terraform. 124 rules total.
- **File-scoped rules** (`FileScoped` + `RequiredPattern`): a rule mechanism for
  whole-file "security control is absent" checks, which line-scoped patterns
  cannot express.
- **Multi-platform Docker images**: `linux/amd64` and `linux/arm64`
  ([#42](https://github.com/filipi86/drogonsec/pull/42)).

### Changed

- **False-positive reduction**, validated against a true-positive corpus and
  real projects (okhttp, express, cartography, redis, caddy, vapor, flutter,
  cowboy, phoenix): `KT-003` now matches real trust-all idioms instead of bare
  API names (-757 false positives on okhttp); `JS-011`, `JS-016` and `HTML-002`
  were rebuilt as file-scoped missing-control checks at LOW; `PY-003`, `PY-010`,
  `PY-011`, `PY-019`, `PHP-006`, `JS-004`, `GEN-001`, `CS-004` and `GO-007`
  gained context-aware patterns and placeholder suppression.
- **False-negative recovery**: `PY-011` catches secret logging via `+`
  concatenation; `JS-004` and `PHP-006` no longer suppress real secrets and weak
  default credentials; `PY-021`, `PY-022` and `GO-009` surface cross-line weak
  RNG and variable URL SSRF at LOW instead of dropping them.
- **Test-aware severity demotion**: hardcoded secrets under test paths report as
  LOW and control checks as INFO — demoted, never silently dropped. Findings are
  only dropped when a pattern is provably non-vulnerable.
- **Reproducible CI toolchain**: all GitHub Actions pinned to commit SHAs and
  `golangci-lint` pinned to v2.12.2.

### Removed

- **Rule `GEN-002`**: it flagged public X.509 certificates as private keys, a
  false positive with no true-positive case to justify it.

### Fixed

- CLA workflow: signatures are stored on a dedicated unprotected branch, rechecks
  can re-run, the `reopened` trigger is handled, and the skip is keyed on the PR
  author rather than the event actor.
- The dogfooding security scan now exits cleanly instead of failing the pipeline
  on its own report.
- The staging pipeline has the `packages:write` permission needed to push to GHCR
  ([#39](https://github.com/filipi86/drogonsec/pull/39)).

### Security

- **Go 1.26.5**, patching `GO-2026-5856` in `crypto/tls`.
- Staging Docker publishing is gated to branch pushes: on `pull_request` it
  published `:staging` images to GHCR before any review.

## [0.1.0] - 2026-06-23

First public release of DrogonSec, a high-performance open-source security
scanner combining SAST, SCA, secret detection, and IaC analysis in a single
binary, built for developers and CI/CD pipelines.

### Added

- **SAST engine**: static analysis with language-specific rule sets for 20+
  languages, aligned with the OWASP Top 10:2025.
- **SCA engine**: dependency vulnerability scanning against the OSV database,
  with manifest parsers for npm, pip, Go, Maven, Ruby, Composer, and Dart.
- **Secret detection**: regex and Shannon-entropy based leak detection over the
  working tree and full git history, with per-rule confidence levels and
  match redaction.
- **IaC analysis**: misconfiguration checks for infrastructure-as-code.
- **AI-powered remediation**: optional remediation suggestions via local Ollama
  (no API key) or cloud providers (Anthropic, OpenAI-compatible, custom
  endpoints), enabled with `--enable-ai`.
- **Output formats**: human-readable text, JSON, native SARIF for GitHub Code
  Scanning, and a standalone HTML report.
- **Branch monitoring**: webhook server for scanning repositories on push.
- **CLI**: `scan` command with per-engine toggles, severity filtering, and
  shell completion for bash and zsh.
- **CI/CD**: GitHub Actions pipeline with build, test, lint, govulncheck, and a
  self-scan security gate.

[Unreleased]: https://github.com/filipi86/drogonsec/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/filipi86/drogonsec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/filipi86/drogonsec/releases/tag/v0.1.0
