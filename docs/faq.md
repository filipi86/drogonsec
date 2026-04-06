# FAQ & Troubleshooting

## General

**What is Drogonsec?**  
An open-source modular security framework in Go for threat detection, intelligence analysis, and security research.

**Who is it for?**  
Security researchers, red teamers, SOC analysts, malware hunters, and anyone building automated security tooling.

**Is it free?**  
Yes. MIT licensed — free to use, modify, and distribute.

**What OS is supported?**  
Linux (primary), macOS, and Windows via cross-compilation.

**What does DRG-0x mean?**  
Internal module naming convention using hexadecimal identifiers (DRG-0x1, DRG-0x2...) for easy reference and extension.

---

## Troubleshooting

### Build: `cannot find package "." in ./cmd/drogonsec/main.go`

Nested directory issue:

\`\`\`bash
find ~ -name "main.go" 2>/dev/null
cd ~/drogonsec
make install
\`\`\`

### Build: `go: command not found`

\`\`\`bash
sudo apt update && sudo apt install golang-go
\`\`\`

### Runtime: Binary not found after build

\`\`\`bash
ls -la ./bin/
make install
\`\`\`

### Runtime: Permission denied

\`\`\`bash
chmod +x ./bin/drogonsec
\`\`\`

---

## Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feat/my-module`
3. Commit: `git commit -m "Add DRG-0x3 module"`
4. Open a Pull Request on GitHub

Follow the `DRG-0x` naming convention for new modules.
