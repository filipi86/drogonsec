# FAQ & Troubleshooting

---

## General Questions

### What is Drogonsec?

Drogonsec is an open-source modular security framework written in Go, created by **Filipi Pires** and maintained by **[CROSS-INTEL](https://cross-intel.com)**. It combines SAST, SCA, secret detection, and IaC analysis into a single binary, aligned with OWASP Top 10:2025.

### Who created Drogonsec?

Drogonsec was created by **Filipi Pires** — Head of Technical Advocay, Global Threat Researcher, Cybersecurity Advocate, Instructor, Speaker, and Writer about Malware Hunting. The project is maintained by [CROSS-INTEL](https://cross-intel.com/opensource/drogonsec).

### Who is Drogonsec for?

- Security researchers and malware hunters
- Red teamers and penetration testers
- SOC analysts and threat intelligence professionals
- DevSecOps engineers integrating security into CI/CD pipelines
- Developers who want to audit their own code before shipping

### Is Drogonsec free?

Yes. Drogonsec is released under the **Apache License 2.0**. It is free to use, modify, and distribute.

### What is the difference between Drogonsec and Horusec?

Drogonsec is inspired by Horusec but is its modern, actively maintained successor with enhanced capabilities. Key differences:

| Feature | Drogonsec | Horusec |
|---|---|---|
| OWASP alignment | Top 10:2025 | Top 10:2021 |
| Active development | ✅ Yes | ❌ Inactive |
| AI remediation | 🔜 Coming soon | ❌ No |
| New OWASP A03 (Supply Chain) | ✅ Full SCA engine | ❌ No |
| New OWASP A10 (Exceptions) | ✅ Yes | ❌ No |
| Community YAML rules | ✅ Yes | Limited |

### What operating systems are supported?

Drogonsec is written in Go and compiles to a single native binary. Supported platforms:

| OS | Support |
|---|---|
| Linux | ✅ Primary platform |
| macOS | ✅ Supported |
| Windows | ✅ Via cross-compilation or Docker |

### What does `DRG-0x` mean?

`DRG-0x` is Drogonsec's internal module naming convention, using hexadecimal identifiers (DRG-0x1, DRG-0x2, etc.) to reference specific components. For example, DRG-0x1 is the Core Engine and DRG-0x2 is the Neural Threat Scanner.

---

## Installation Issues

### `cannot find package "." in ./cmd/drogonsec/main.go`

**Cause:** You cloned the repository inside a folder that is already named `drogonsec`, resulting in a nested path like `~/drogonsec/drogonsec/`.

**Fix:**

```bash
# Find where main.go actually lives
find ~ -name "main.go" 2>/dev/null

# Navigate to the correct root
cd ~/drogonsec    # NOT ~/drogonsec/drogonsec
make install
```

### `go: command not found`

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install golang-go

# Verify
go version
```

### `make: command not found`

```bash
sudo apt install make
```

### Binary not found after build

```bash
ls -la ./bin/
# If empty, re-run:
make install
```

### `git push` says `Everything up-to-date` but nothing was sent

Files were never staged:

```bash
git status
git add docs/
git commit -m "add documentation"
git push origin main
```

---

## Runtime Issues

### Permission denied when running the binary

```bash
chmod +x ./bin/drogonsec
./bin/drogonsec --version
```

### Scan returns no findings

Check the following:

- Confirm the target path is correct and contains source files
- Make sure you are not excluding the path in `.drogonsec.yaml` under `ignore_paths`
- Try lowering the minimum severity: `--severity LOW`
- Verify no engines are disabled accidentally

```bash
# Run with maximum visibility
drogonsec scan . --severity LOW --no-sca
```

### Too many false positives in secret detection

Increase the entropy threshold in `.drogonsec.yaml`:

```yaml
engines:
  leaks:
    min_entropy: 4.0
```

### Scan is slow on large repositories

Increase the number of parallel workers:

```yaml
scan:
  workers: 8
```

Or exclude directories that don't need scanning:

```yaml
scan:
  ignore_paths:
    - node_modules
    - vendor
    - .git
    - dist
    - coverage
```

---

## CI/CD Integration

### How do I fail the pipeline on critical vulnerabilities?

Add to `.drogonsec.yaml`:

```yaml
fail_on:
  critical: true
  high: true
```

Drogonsec will exit with a non-zero code when findings at or above the specified severity are detected, which CI systems interpret as a pipeline failure.

### How do I integrate with the GitHub Security tab?

```yaml
- name: Run Drogonsec
  run: drogonsec scan . --format sarif --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### The GitHub raw URL returns 403 when used from the documentation site

The repository must be **public** for raw GitHub URLs to be accessible without authentication. Go to your repository Settings → General → Danger Zone → Change visibility → Make public.

---

## Contributing

### How do I contribute?

1. Fork the repository: [github.com/filipi86/drogonsec](https://github.com/filipi86/drogonsec)
2. Create a branch: `git checkout -b feat/my-contribution`
3. Make your changes
4. Commit: `git commit -m "Add: description"`
5. Push and open a Pull Request

### What can I contribute?

- New SAST rules for any supported language (YAML files in `rules/`)
- Additional secret detection patterns for the Leaks engine
- New language parsers for the SAST engine
- Bug fixes and performance improvements
- Documentation improvements and translations

### Where are the SAST rules defined?

Rules are YAML files in the `rules/` directory. See the [Modules](./modules.md) page for the full rule schema and an example of writing a custom rule.

---

## Getting Help

- Open an issue: [github.com/filipi86/drogonsec/issues](https://github.com/filipi86/drogonsec/issues)
- When reporting a bug, always include:
  - Your OS and architecture (`uname -a`)
  - Your Go version (`go version`)
  - The exact command you ran
  - The full error output
- Check existing issues before opening a new one to avoid duplicates
