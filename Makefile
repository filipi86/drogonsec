# DrogonSec Security Scanner - Makefile
# https://github.com/filipi86/drogonsec

BINARY_NAME    := drogonsec
# Derived from the last tag so there is no version literal to bump by hand.
# Override explicitly when the tag is not reachable, e.g. a shallow CI clone:
#   make release VERSION=1.2.3
VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
BUILD_TIME     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION_PKG    := github.com/filipi86/drogonsec/internal/version
LDFLAGS        := -ldflags "-X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).BuildTime=$(BUILD_TIME) -X $(VERSION_PKG).GitCommit=$(GIT_COMMIT) $(EXTRA_LDFLAGS)"
GO             := go
GOFLAGS        :=
BUILD_DIR      := ./bin
MAIN           := ./cmd/drogonsec/main.go
DOCKER_IMAGE   := drogonsec-scanner
DOCKER_PLATFORMS := linux/amd64,linux/arm64
DOCKER_OUTPUT  := type=oci,dest=$(BUILD_DIR)/$(BINARY_NAME)-docker-$(VERSION).tar

.PHONY: all build clean test lint install release help demo

##@ General
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[36mDrogonSec Security Scanner\033[0m - Build System\n\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Development
all: lint test build ## Run lint, test, and build

build: ## Build for current OS/arch
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN)
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: ## Build for Linux (amd64 + arm64)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN)
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN)
	@echo "✓ Built Linux binaries"

build-darwin: ## Build for macOS (Intel + Apple Silicon)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN)
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN)
	@echo "✓ Built macOS binaries"

build-windows: ## Build for Windows amd64
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN)
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe"

release: build-linux build-darwin build-windows ## Build for all platforms
	@echo "✓ Release builds complete"
	@ls -la $(BUILD_DIR)/

install: build ## Install drogonsec to /usr/local/bin
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Installed. Run: drogonsec --help"

run: build ## Build and run a scan on current directory
	./$(BUILD_DIR)/$(BINARY_NAME) scan .

demo: build ## Regenerate the README banner (docs/assets/banner.gif) with vhs
	@command -v vhs >/dev/null 2>&1 || { \
		echo "vhs not found. Install it with: brew install vhs"; \
		echo "See https://github.com/charmbracelet/vhs"; \
		exit 1; \
	}
	@echo "Recording docs/assets/banner.gif at $(VERSION)..."
	@vhs docs/assets/banner.tape
	@echo "✓ Recorded: docs/assets/banner.gif"

##@ Testing
test: ## Run all tests
	$(GO) test ./... -v -count=1

test-coverage: ## Run tests with coverage report
	$(GO) test ./... -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

test-race: ## Run tests with race detector
	$(GO) test ./... -race -count=1

##@ Code Quality
lint: ## Run linters (requires golangci-lint)
	@which golangci-lint > /dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...
	@echo "✓ Code formatted"

vet: ## Run go vet
	$(GO) vet ./...
	@echo "✓ Vet passed"

##@ Dependencies
deps: ## Download dependencies
	$(GO) mod download
	$(GO) mod tidy
	@echo "✓ Dependencies updated"

deps-update: ## Update all dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

##@ Scan
scan-self: build ## Scan DrogonSec's own source code
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format text

scan-report: build ## Scan and generate HTML report
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format html --output drogonsec-report.html
	@echo "✓ Report: drogonsec-report.html"

scan-sarif: build ## Scan and generate SARIF report (for GitHub)
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format sarif --output drogonsec.sarif
	@echo "✓ SARIF: drogonsec.sarif"

##@ Docker
docker-build: ## Build Docker image for linux/amd64 and linux/arm64
	@mkdir -p $(BUILD_DIR)
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(DOCKER_IMAGE):$(VERSION) --output $(DOCKER_OUTPUT) .
	@echo "✓ Docker image built"

docker-push: ## Build and push multi-arch Docker image (set DOCKER_IMAGE)
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(DOCKER_IMAGE):$(VERSION) --push .
	@echo "✓ Docker image pushed"

docker-run: ## Run DrogonSec in Docker
	docker run --rm -v $(PWD):/scan $(DOCKER_IMAGE):$(VERSION) scan /scan

##@ Cleanup
clean: ## Remove build artifacts
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "✓ Cleaned"
