# Installation

---

## Prerequisites

Before installing Drogonsec, make sure you have the following on your system:

| Requirement | Minimum Version | Notes |
|---|---|---|
| **Go** | 1.26.6+ | [Download Go](https://golang.org/dl/) |
| **Git** | any | For cloning the repository |
| **Make** | any | For using the build system |
| **Docker** | any | Optional — for container-based usage |

Verify your Go installation:

```bash
go version
```

Expected output:

```
go version go1.26.6 linux/amd64
```

---

## Method 1 — From Source (Recommended)

```bash
git clone https://github.com/filipi86/drogonsec
cd drogonsec
make install
```

> **Important:** Run `make install` from inside the `drogonsec/` directory created by `git clone`. Do not run it from a parent folder with the same name, or the build will fail.

After a successful build, verify the binary:

```bash
./bin/drogonsec --version
```

---

## Method 2 — Go Install (Requires Go 1.26.6+)

Install directly from the module without cloning the repository:

```bash
go install github.com/filipi86/drogonsec/cmd/drogonsec@latest
```

The binary will be placed in your `$GOPATH/bin` (usually `~/go/bin`). Make sure it is in your `$PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Verify the installation:

```bash
drogonsec --version
```

To run without installing permanently:

```bash
go run github.com/filipi86/drogonsec/cmd/drogonsec@latest scan .
```

---

## Method 3 — Docker

No local Go installation required. Mount your project directory and run:

```bash
docker run --rm -v $(pwd):/scan ghcr.io/filipi86/drogonsec scan /scan
```

To scan with JSON output:

```bash
docker run --rm -v $(pwd):/scan ghcr.io/filipi86/drogonsec scan /scan --format json --output /scan/report.json
```

---

## Method 4 — Manual Build

If you prefer not to use `make`, build with full ldflags:

```bash
git clone https://github.com/filipi86/drogonsec
cd drogonsec
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=production" \
  -o ./bin/drogonsec \
  ./cmd/drogonsec
```

For a development build with green branding and `[DEV]` label:

```bash
go build \
  -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=development" \
  -o ./bin/drogonsec \
  ./cmd/drogonsec
```

---

## Directory Structure After Build

```
drogonsec/
├── bin/
│   └── drogonsec       # compiled binary
├── cmd/
├── internal/
├── rules/
├── Makefile
└── go.mod
```

---

## Configuration File (Optional)

Create a `.drogonsec.yaml` file in your project root to persist scan settings:

```yaml
scan:
  min_severity: LOW
  workers: 4
  git_history: false
  ignore_paths:
    - node_modules
    - vendor
    - dist
    - .git

engines:
  sast:
    enabled: true
  sca:
    enabled: true
  leaks:
    enabled: true
    min_entropy: 3.5

ai:
  enabled: false
  high_severity_only: true

fail_on:
  critical: true
  high: true
```

---

## Updating Drogonsec

To update to the latest version:

```bash
cd drogonsec
git pull origin main
make install
```

---

## Uninstalling

```bash
# Remove the binary only
rm ./bin/drogonsec

# Remove the entire project
cd ~
rm -rf drogonsec
```

---

## Troubleshooting

### Error: `cannot find package "." in ./cmd/drogonsec/main.go`

**Cause:** You cloned the repository inside a folder that is already named `drogonsec`, resulting in a path like `~/drogonsec/drogonsec/`.

**Fix:**

```bash
# Find where main.go actually lives
find ~ -name "main.go" 2>/dev/null

# Navigate to the correct root directory
cd ~/drogonsec    # NOT ~/drogonsec/drogonsec
make install
```

### Error: `go: command not found`

Go is not installed or not in your `$PATH`.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install golang-go

# Verify
go version
```

### Error: `make: command not found`

```bash
# Ubuntu / Debian
sudo apt install make

# CentOS / RHEL
sudo yum install make
```

### Error: Permission denied on binary

```bash
chmod +x ./bin/drogonsec
./bin/drogonsec --version
```

### `git push` says `Everything up-to-date` but files are missing

The files were not staged before committing:

```bash
git status
git add docs/
git commit -m "add documentation"
git push origin main
```
