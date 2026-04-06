# 🛡️ Drogonsec — Security Scanner

[![CI/CD](https://github.com/filipi86/drogonsec/actions/workflows/ci.yml/badge.svg)](https://github.com/filipi86/drogonsec/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![OWASP Top 10 2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-orange.svg)](https://owasp.org/Top10/2025/)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://golang.org)

> An open-source, comprehensive security scanner combining **SAST**, **SCA**, and **secret detection** — aligned with OWASP Top 10:2025 and built for intelligent remediation.

---

## What is Drogonsec?

**Drogonsec** is an open-source modular security framework written in Go, created by **Filipi Pires** and maintained by **[CROSS-INTEL](https://cross-intel.com)**.

It was built to give security professionals a single, unified tool to detect vulnerabilities across code, dependencies, secrets, and infrastructure — with AI-powered remediation on the roadmap.

Inspired by Horusec, Drogonsec is its modern, actively maintained successor with enhanced capabilities and alignment to the latest OWASP standards.

---

## Why Drogonsec?

| Problem | Drogonsec Solution |
|---|---|
| Multiple tools for different scan types | Single binary — SAST + SCA + Leaks + IaC |
| OWASP Top 10:2021 is outdated | Full alignment with OWASP Top 10:2025 |
| No context-aware fix suggestions | AI remediation engine *(coming soon)* |
| Complex CI/CD integration | Native SARIF output for GitHub/Azure DevOps |
| Hard to extend with custom rules | Community YAML rules in `rules/` directory |

---

## Scanning Engines

| Engine | Description | Status |
|--------|-------------|--------|
| **SAST** | Static Application Security Testing for 20+ languages | ✅ Stable |
| **SCA** | Software Composition Analysis — scan dependencies for CVEs | ✅ Stable |
| **Leaks** | Secret detection — 50+ patterns (AWS, GCP, GitHub, JWT, SSH...) | ✅ Stable |
| **IaC** | Infrastructure as Code misconfigurations (Terraform, Kubernetes) | ✅ Stable |
| **AI** | AI-powered remediation suggestions | 🔜 Coming soon |

---

## Security Frameworks

- **OWASP Top 10:2025** — All 10 categories covered, including the 2 new ones: Supply Chain Failures and Mishandling of Exceptional Conditions
- **CWE** — Common Weakness Enumeration mapping on every finding
- **CVSS 3.1** — Severity scoring for accurate risk prioritization
- **SARIF 2.1** — Native integration with GitHub Security and Azure DevOps

---

## Supported Languages

`Python` `Java` `JavaScript` `TypeScript` `Go` `Kotlin` `C#` `PHP` `Ruby` `Swift` `Dart` `Elixir` `Erlang` `Shell` `C/C++` `HTML` `Terraform` `Kubernetes` `Nginx`

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

## Project Architecture

```
drogonsec/
├── cmd/drogonsec/          # CLI entrypoint
├── internal/
│   ├── analyzer/           # Main orchestrator
│   ├── engine/             # SAST rules engine (20+ languages)
│   ├── leaks/              # Secret detection engine
│   ├── sca/                # Dependency analysis engine
│   ├── reporter/           # Text / JSON / SARIF / HTML reporters
│   ├── ai/                 # AI remediation engine (coming soon)
│   └── config/             # Types and configuration
└── rules/                  # YAML rule definitions (community-extensible)
```

---

## Credits & Acknowledgements

- **Created by:** [Filipi Pires](https://github.com/filipi86) — Head of Identity Threat Labs, Global Threat Researcher, Cybersecurity Advocate, Instructor, Speaker and Writer about Malware Hunting
- **Maintained by:** [CROSS-INTEL](https://cross-intel.com)
- **Inspired by:** [Horusec](https://github.com/ZupIT/horusec)
- **Built with:** Go, Cobra, Viper, go-git
- **License:** Apache License 2.0
