#!/bin/bash
# DragonSec Security Scanner - Setup Script
# Run: chmod +x scripts/setup.sh && ./scripts/setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ____                            _____          "
  echo " |  _ \ _ __ ___   __ _  ___  _ _|_   _|__  ___ "
  echo " | | | | '__/ _ \ / _' |/ _ \| '_ \| |/ _ \/ __|"
  echo " | |_| | | | (_) | (_| | (_) | | | | |  __/ (__ "
  echo " |____/|_|  \___/ \__, |\___/|_| |_|_|\___|\___| "
  echo "                  |___/                           "
  echo ""
  echo "  DragonSec Security Scanner - Setup"
  echo -e "${NC}"
}

ok() { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
err() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${CYAN}→${NC} $1"; }

banner

# Check Go installation
info "Checking prerequisites..."

if ! command -v go &>/dev/null; then
  err "Go is not installed!"
  echo ""
  echo "  Please install Go 1.22+ from: https://golang.org/dl/"
  echo ""
  echo "  Quick install (Linux/macOS):"
  echo "    wget https://golang.org/dl/go1.22.0.linux-amd64.tar.gz"
  echo "    sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz"
  echo "    export PATH=\$PATH:/usr/local/go/bin"
  exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.22"

ok "Go found: $(go version)"

# Check minimum version
if ! echo "$GO_VERSION $REQUIRED_VERSION" | awk '{if ($1 < $2) exit 1}'; then
  err "Go $REQUIRED_VERSION+ is required, found $GO_VERSION"
  exit 1
fi

# Check git
if ! command -v git &>/dev/null; then
  warn "git not found - git history scanning will not work"
else
  ok "Git found: $(git version)"
fi

echo ""
info "Setting up dependencies..."
go mod download
ok "Dependencies downloaded"

info "Running tests..."
if go test ./... -count=1 -timeout 60s 2>&1; then
  ok "All tests passed"
else
  warn "Some tests failed - this may be expected on first setup"
fi

echo ""
info "Building DragonSec..."
mkdir -p bin
go build -o bin/drogonsec ./cmd/drogonsec/main.go
ok "Binary built: ./bin/drogonsec"

echo ""
echo -e "${BOLD}  Installation complete!${NC}"
echo ""
echo "  Run your first scan:"
echo -e "  ${CYAN}./bin/drogonsec scan .${NC}"
echo ""
echo "  Scan with AI remediation:"
echo -e "  ${CYAN}export ANTHROPIC_API_KEY='sk-ant-...'${NC}"
echo -e "  ${CYAN}./bin/drogonsec scan . --enable-ai${NC}"
echo ""
echo "  Generate HTML report:"
echo -e "  ${CYAN}./bin/drogonsec scan . --format html --output report.html${NC}"
echo ""
echo "  Install system-wide:"
echo -e "  ${CYAN}sudo cp bin/drogonsec /usr/local/bin/drogonsec${NC}"
echo ""

# Optional: add to PATH hint
if [[ ":$PATH:" != *":$(pwd)/bin:"* ]]; then
  warn "Add to PATH: export PATH=\"\$PATH:$(pwd)/bin\""
fi

echo -e "  ${GREEN}✓ Ready to scan!${NC}"
