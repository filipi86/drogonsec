# DragonSec Security Scanner - Makefile
# https://github.com/filipi86/drogonsec

BINARY_NAME    := drogonsec
VERSION        := 0.1.0
BUILD_TIME     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS        := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"
GO             := go
GOFLAGS        :=
BUILD_DIR      := ./bin
MAIN           := ./cmd/drogonsec/main.go

.PHONY: all build clean test lint install release help

##@ General
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[36mDragonSec Security Scanner\033[0m - Build System\n\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Development
all: lint test build ## Run lint, test, and build

build: ## Build for current OS/arch
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN)
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: ## Build for Linux amd64
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN)
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

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
scan-self: build ## Scan DragonSec's own source code
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format text

scan-report: build ## Scan and generate HTML report
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format html --output drogonsec-report.html
	@echo "✓ Report: drogonsec-report.html"

scan-sarif: build ## Scan and generate SARIF report (for GitHub)
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --format sarif --output drogonsec.sarif
	@echo "✓ SARIF: drogonsec.sarif"

##@ Docker
docker-build: ## Build Docker image
	docker build -t drogonsec-scanner:$(VERSION) .
	@echo "✓ Docker image built"

docker-run: ## Run DragonSec in Docker
	docker run --rm -v $(PWD):/scan drogonsec-scanner:$(VERSION) scan /scan

##@ Cleanup
clean: ## Remove build artifacts
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "✓ Cleaned"
