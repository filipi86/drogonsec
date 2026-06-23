# Changelog

All notable changes to **DrogonSec** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CycloneDX SBOM export** (`--format cyclonedx`): emits a CycloneDX 1.5 JSON
  Software Bill of Materials of the dependencies discovered by the SCA engine,
  with Package URLs (purls) per ecosystem (npm, pypi, golang, maven, gem,
  composer, pub). Flat component inventory, deduplicated and consumable by
  Grype, Trivy, and Dependency-Track. Transitive graph and SPDX output are
  planned for a later release. ([#31](https://github.com/filipi86/drogonsec/issues/31))

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

[Unreleased]: https://github.com/filipi86/drogonsec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/filipi86/drogonsec/releases/tag/v0.1.0
