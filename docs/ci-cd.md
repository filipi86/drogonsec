# CI/CD Pipelines

---

## Overview

Drogonsec uses three separate CI/CD pipelines — one per environment — each triggered by pushes or pull requests to the corresponding branch.

| Pipeline | File | Triggered by | Environment branding |
|----------|------|-------------|----------------------|
| **Production** | `ci.yml` | `main` | Blue frame, gold title |
| **Staging** | `staging.yml` | `staging` | Yellow frame, white title + `[STAGING]` |
| **Development** | `development.yml` | `development` | Green frame, cyan title + `[DEV]` |

---

## Security Gates

Every pipeline runs a sequence of mandatory checks before any merge is allowed:

```
push / pull_request
        │
        ▼
┌──────────────────────────────────┐
│  1. go mod verify                │  checksum validation vs go.sum
│  2. govulncheck                  │  CVE scan — Go Vulnerability Database
│  3. go build                     │  compilation check
│  4. go test -race                │  tests with race detector
│  5. golangci-lint (gofmt + more) │  code quality
│  6. drogonsec scan (SAST + SCA)  │  self-scan — report only, non-blocking
└──────────────────────────────────┘
        │  all pass?
        ▼
     merge allowed
```

### go mod verify

Validates that all downloaded modules match the checksums recorded in `go.sum`. Detects tampered or substituted packages before they can be compiled.

```bash
go mod verify
```

### govulncheck

Scans all direct and transitive dependencies against the [Go Vulnerability Database](https://vuln.go.dev). Unlike SCA tools that flag all known CVEs in go.sum, `govulncheck` only reports vulnerabilities that are **reachable** in your actual call graph — eliminating false positives.

```bash
govulncheck ./...
```

If a confirmed CVE is reachable in the code path, the build fails and the PR cannot be merged.

### Self-scan (Dogfooding)

The production pipeline builds Drogonsec and runs it on its own source code:

```bash
./bin/drogonsec scan . --format sarif --output drogonsec.sarif --severity MEDIUM --no-ai
```

The SARIF report is uploaded to GitHub Security → Code scanning alerts. This step is set to `continue-on-error: true` — findings are reported but do not block the merge.

---

## Production Pipeline (`ci.yml`)

Jobs:

| Job | Description |
|-----|-------------|
| `build-test` | go mod verify → govulncheck → go vet → tests → build |
| `lint` | golangci-lint (includes gofmt) |
| `security-scan` | build + drogonsec self-scan + SARIF upload |
| `release` | Cross-platform binaries — only on `release` events |
| `docker` | Build + push `ghcr.io/filipi86/drogonsec:latest` — only on `main` push or release |

The binary is built with production branding injected at compile time:

```bash
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=production" \
  -o bin/drogonsec \
  ./cmd/drogonsec/main.go
```

---

## Staging Pipeline (`staging.yml`)

Jobs: `build-test`, `lint`, `docker` (pushes `ghcr.io/filipi86/drogonsec:staging`).

Binary built with staging branding:

```bash
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=staging" \
  -o bin/drogonsec-staging \
  ./cmd/drogonsec
```

---

## Development Pipeline (`development.yml`)

Jobs: `build-test`, `lint`. No Docker push.

Binary built with development branding:

```bash
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=development" \
  -o bin/drogonsec-dev \
  ./cmd/drogonsec
```

---

## Branch Protection

All three branches (`main`, `staging`, `development`) are protected by a GitHub Ruleset:

- Direct pushes are blocked — all changes must go through a Pull Request
- Required status checks must pass before merge (`Build & Test`, `Lint`)
- Force pushes and branch deletion are blocked

Repository admins can bypass these rules for emergency hotfixes.

---

## Automated Dependency Updates (Dependabot)

Dependabot runs every Monday at 09:00 (America/Sao_Paulo) and opens PRs for:

- **Go modules** (`go.mod`) — grouped into a single PR
- **GitHub Actions** — one PR per action

### Merge policy

| Update type | Behaviour |
|-------------|-----------|
| `patch` (x.y.**Z**) | CI runs → maintainer merges once all gates are green |
| `minor` (x.**Y**.0) | CI runs → reviewed for breaking changes |
| `major` (**X**.0.0) | CI runs → reviewed for breaking changes |
| GitHub Actions | CI runs → reviewed and re-pinned to a commit SHA |

No dependency update merges itself. GitHub auto-merge is disabled on this
repository and the `main` ruleset requires one approving review, so every
Dependabot PR lands through a human decision — an update that passes CI is
still an unreviewed change to the supply chain.

---

## Multi-Environment Branding

The `Environment` variable is injected at build time via `-ldflags`. This controls the banner colors and label shown when Drogonsec runs.

| Value | Frame color | Title color | Header label |
|-------|------------|-------------|--------------|
| *(empty / default)* | Blue | Gold | *(none)* |
| `staging` | Yellow | White | `[STAGING]` |
| `development` | Green | Cyan | `[DEV]` |

Build locally with a specific environment:

```bash
# Development
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=development" \
  -o ./bin/drogonsec ./cmd/drogonsec

# Staging
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=staging" \
  -o ./bin/drogonsec ./cmd/drogonsec

# Production (default — ldflags optional)
make build
```

With Docker:

```bash
docker build --build-arg ENVIRONMENT=staging -t drogonsec:staging .
```
