# Security Hardening

---

## Overview

Drogonsec implements several internal security controls to protect users and their data when running scans and generating reports.

---

## XSS Prevention in HTML Reports

All user-controlled data written to HTML reports is escaped using Go's standard `html.EscapeString()` before insertion into the template.

Affected fields across SAST, Leaks, and SCA findings:

| Engine | Escaped fields |
|--------|---------------|
| SAST | Title, File, RuleID, OWASP, CWE, Description, Remediation, AI Remediation |
| Leaks | Type, File, RuleID, Match, Description, AI Remediation |
| SCA | PackageName, PackageVersion, CVE, ManifestFile, FixedVersion, Ecosystem, Description, Advisory |

### URL scheme allow-list for advisory links

`html.EscapeString` neutralises quote/angle-bracket injection but does **not** block dangerous URL schemes like `javascript:`, `data:`, or `vbscript:`. For advisory links rendered as `<a href="…">`, DrogonSec additionally validates the scheme through a `safeURL` helper that only passes `http` and `https` through; anything else (including relative/protocol-relative URLs) is rewritten to `#`. Every advisory link also carries `rel="noopener noreferrer nofollow"` and `target="_blank"` to prevent tab-nabbing and referrer leaks.

---

## HTTPS Enforcement for AI Endpoints

When a custom AI endpoint is configured (e.g. a self-hosted model or proxy), Drogonsec enforces HTTPS to prevent API key exfiltration over unencrypted connections.

**Allowed endpoints:**

```
https://         — any HTTPS endpoint
http://localhost — local development only
http://127.0.0.1 — local development only
```

Any other `http://` endpoint is silently replaced with the default Anthropic endpoint. This prevents accidental misconfiguration from sending API keys in plaintext over the network.

Configuration example (`.drogonsec.yaml`):

```yaml
ai:
  enabled: true
  endpoint: "https://your-proxy.internal/v1"  # must be HTTPS
  api_key: "sk-..."
```

---

## ReDoS Protection in Leak Detection

The secret detection engine applies a 10,000-byte line length limit before running regex patterns against source code lines.

```
if len(line) > 10,000 bytes → skip line
```

This prevents **ReDoS (Regular Expression Denial of Service)** — a class of attack where crafted input causes catastrophic backtracking in complex regex patterns, leading to CPU exhaustion and scanner hangs.

Both file scanning and Git history scanning are protected:

- `ScanFile()` — per-line guard before pattern matching
- `ScanGitHistory()` — per-line guard before pattern matching

The 10,000-byte limit is well above any realistic source code line and has no impact on normal scans.

---

## Supply Chain Security in CI

Drogonsec's own CI pipeline applies two layers of supply chain protection on every build:

### go mod verify

Validates that all downloaded modules match the checksums in `go.sum`. Detects if a dependency was tampered with or substituted after the lockfile was committed.

### govulncheck

Scans direct and transitive dependencies against the [Go Vulnerability Database](https://vuln.go.dev). Only reports vulnerabilities that are reachable in the actual call graph — eliminating noise from unused code paths.

Both checks run before compilation and block the build if they detect an issue.

See [CI/CD Pipelines](ci-cd.md) for the full pipeline details.

---

## AI Client Hardening

The AI remediation client ([AI Remediation](ai-remediation.md)) adds several defensive controls on top of HTTPS enforcement:

### No HTTP redirects

Go's default `http.Client` preserves the `x-api-key` header when following a redirect — a hostile endpoint responding with `302 Location: …` could exfiltrate your API key to a third-party host. DrogonSec installs a `CheckRedirect` hook that refuses any redirect and surfaces an explicit error. Legitimate AI providers do not redirect POSTs to their inference endpoints, so this is safe by construction.

### Cache integrity (HMAC-SHA256)

Cached AI responses live under `~/.drogonsec/ai-cache/` with mode `0600`. Every entry is additionally tagged with an HMAC-SHA256 over the response body, using a per-user 32-byte random key stored in `~/.drogonsec/ai-cache/cache.key` (`0600`). On read, a tag mismatch causes the entry to be discarded — protecting you against cache-poisoning on shared or CI filesystems where an attacker might gain write access without read.

### Ollama shape validation

Auto-detecting a local Ollama requires more than `HTTP 200` on port `11434` — DrogonSec also requires the response to decode as the `/api/tags` JSON shape (a `{"models": [...]}` object). Any other service incidentally listening on that port is rejected, so prompts are never forwarded to an unrelated daemon.

---

## Report Output Permissions

When `--output <file>` is used for `text`, `json`, `sarif`, `html`, or `cyclonedx` reports, the file is created with mode `0600` (user-only). Reports embed vulnerable code snippets, matched secrets, and AI remediation text; on shared CI runners or workstations they should not be world-readable by default. If you need the report to be readable by other accounts, adjust the permissions after generation.

---

## Manifest Size Limits (SCA)

The SCA engine parses `package.json`, `composer.json`, `pubspec.yaml`, `Gemfile.lock`, `requirements.txt`, `go.mod`, and `pom.xml`. JSON/YAML parsers load the full file before validating structure, so DrogonSec enforces a `10 MiB` size cap per manifest before parsing. Custom YAML rule files (loaded via `--rules-dir`) are capped at `5 MiB`. This prevents a malicious or accidentally oversized manifest from OOM-killing the scanner in CI.

OSV API responses are additionally capped at `32 MiB` via `io.LimitReader` so a compromised or misbehaving OSV proxy cannot exhaust scanner memory by streaming gigabytes of data.

---

## `.gitignore` Awareness (Leaks)

When `.gitignore` at the repo root matches a file, any secret finding on that file is **downgraded to INFO severity** with a marker in the description. The finding is kept visible because a historical accidental commit remains a real risk (check with `--git-history`), but it no longer generates HIGH/CRITICAL noise for files the developer explicitly excluded from version control. See [Issue #17](https://github.com/filipi86/drogonsec/issues/17).

---

## Rules Directory Path Resolution

Custom YAML rules loaded via `--rules-dir` have their root canonicalised with `filepath.EvalSymlinks` before walking, and any symlink entries encountered inside the tree are skipped. This prevents a committed symlink from silently redirecting rule loading to a path outside the intended directory (e.g., `rules/evil -> /etc`).

---

## Git History Commit Cap

`--git-history` walks up to `10 000` commits. On repositories with millions of commits (monorepos, mirrors), the previous unbounded walk would consume hours of CPU; the cap keeps scan time predictable. For deeper history audits, use a dedicated tool like `trufflehog --max-depth`.
