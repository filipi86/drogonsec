# Installation

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Go** | 1.20+ | [Download Go](https://golang.org/dl/) |
| **Git** | any | For cloning the repository |
| **Make** | any | For running the build system |

---

## Installation

### Clone and Build

\`\`\`bash
git clone https://github.com/filipi86/drogonsec.git
cd drogonsec
make install
\`\`\`

> ⚠️ Run `make install` from inside the `drogonsec/` directory created by git clone, not from a parent folder with the same name.

### Manual Build

\`\`\`bash
git clone https://github.com/filipi86/drogonsec.git
cd drogonsec
go build -o ./bin/drogonsec ./cmd/drogonsec/main.go
\`\`\`

---

## Verifying the Installation

\`\`\`bash
./bin/drogonsec --version
\`\`\`

---

## Troubleshooting

### `cannot find package "." in ./cmd/drogonsec/main.go`

Nested directory issue. Fix:

\`\`\`bash
find ~ -name "main.go" 2>/dev/null
cd ~/drogonsec   # NOT ~/drogonsec/drogonsec
make install
\`\`\`

### `go: command not found`

\`\`\`bash
sudo apt update && sudo apt install golang-go
\`\`\`

### `make: command not found`

\`\`\`bash
sudo apt install make
\`\`\`
