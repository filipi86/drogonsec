# Drogonsec

> **Modular Security Intelligence Framework** — Built for threat analysts, red teamers, and security researchers.

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/filipi86/drogonsec)
[![Language](https://img.shields.io/badge/language-Go-00ADD8)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/filipi86/drogonsec/blob/main/LICENSE)
[![Author](https://img.shields.io/badge/author-filipi86-orange)](https://github.com/filipi86)

---

## What is Drogonsec?

**Drogonsec** is an open-source, modular security framework written in Go, designed to assist security professionals in threat detection, intelligence gathering, and vulnerability analysis. The project follows a systematic module naming convention (`DRG-0x` format), allowing each component to operate independently or as part of a unified pipeline.

Built with extensibility in mind, Drogonsec is suitable for:

- Security Operations Centers (SOC)
- Red team and penetration testing workflows
- Threat intelligence and malware hunting
- Automated security scanning pipelines

---

## Architecture Overview

\`\`\`
┌─────────────────────────────────────────────┐
│                  DROGONSEC                  │
│           Modular Security Framework        │
├─────────────┬───────────────────────────────┤
│  DRG-0x1    │  Core Engine                  │
│  DRG-0x2    │  Neural Threat Scanner        │
│  DRG-0x3    │  (future modules)             │
└─────────────┴───────────────────────────────┘
\`\`\`

Each module is self-contained and communicates through a shared interface, making it easy to add, remove, or extend functionality without breaking the core system.

---

## Key Features

- **Modular Design** — Plug-and-play security modules using the `DRG-0x` naming convention
- **Go-based** — Fast, cross-platform binary with minimal dependencies
- **Neural Threat Scanner** — AI-assisted threat analysis via the DRG-0x2 module
- **CLI Interface** — Simple and scriptable command-line interface
- **Extensible** — Easy to add custom modules following the DRG-0x standard
- **Open Source** — MIT licensed, community contributions welcome

---

## Quick Links

| Section | Description |
|---|---|
| [Installation](./installation.md) | How to install and build Drogonsec |
| [Modules](./modules.md) | Reference for all DRG-0x modules |
| [Usage Examples](./usage.md) | Practical use cases and examples |
| [FAQ & Troubleshooting](./faq.md) | Common issues and solutions |

---

## Author

**Filipi Pires** — Head of Identity Threat Labs & Global Threat Researcher  
Cybersecurity Advocate, Instructor, Speaker and Writer about Malware Hunting

- GitHub: [@filipi86](https://github.com/filipi86)
- Project: [github.com/filipi86/drogonsec](https://github.com/filipi86/drogonsec)
