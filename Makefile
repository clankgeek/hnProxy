# Variables
BINARY_NAME=hnproxy
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=${VERSION} -s -w"
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

.PHONY: all build clean test test-unit test-integration test-bench deps help run example cross-compile

# Default target
all: build

# Build the project
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	@echo "✅ Dependencies installed"

# Initialize Go module if not exists
init:
	@if [ ! -f go.mod ]; then \
		echo "🎯 Initializing Go module..."; \
		$(GOMOD) init hnproxy; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	rm -rf certs/
	rm -f coverage.out coverage.html
	rm -f test-report.html benchmark_results.txt
	rm -f *.prof
	@echo "✅ Clean complete"

# Run tests
test: test-unit

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "📊 Test coverage:"
	$(GOCMD) tool cover -func=coverage.out

# Run integration tests (requires -tags integration)
test-integration:
	@echo "🔧 Running integration tests..."
	$(GOTEST) -v -race -tags=integration ./...

# Run all tests (unit + integration)
test-all: test-unit test-integration

# Run benchmarks
test-bench:
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -v -bench=. -benchmem ./...

# Generate test coverage report
coverage: test-unit
	@echo "📊 Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

# Run comprehensive test suite
test-suite:
	@chmod +x test.sh
	@./test.sh all

# Run CI test pipeline
test-ci:
	@chmod +x test.sh
	@./test.sh ci

# Run security tests
test-security:
	@chmod +x test.sh
	@./test.sh security

# Run lint checks
lint:
	@echo "🔍 Running lint checks..."
	@$(GOCMD) vet ./...
	@$(GOCMD) fmt ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; fi

# Run with custom config
run: build
	@echo "🏃 Running $(BINARY_NAME)..."
	@if [ -f "proxy-config.yaml" ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) -config proxy-config.yaml; \
	else \
		echo "❌ Configuration file 'proxy-config.yaml' not found"; \
		echo "💡 Run 'make example' to create one"; \
		exit 1; \
	fi

# Create example configuration
example: build
	@echo "📝 Creating example configuration..."
	./$(BUILD_DIR)/$(BINARY_NAME) -example
	@echo "✅ Example configuration created: proxy-config.yaml"
	@echo "💡 Edit the file before running 'make run'"

# Cross-compile for multiple platforms
cross-compile: deps
	@echo "🌍 Cross-compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		output=$(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then output=$$output.exe; fi; \
		echo "Building for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) $(LDFLAGS) -o $$output .; \
	done
	@echo "✅ Cross-compilation complete"

# Quick setup for new users
setup: init deps example
	@echo "🎉 Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit proxy-config.yaml with your domains and backends"
	@echo "2. Run 'make run' to start the proxy"
	@echo "3. Or run 'make install' to install system-wide"

# Check system requirements
check:
	@echo "🔍 Checking system requirements..."
	@echo -n "Go version: "; $(GOCMD) version 2>/dev/null || echo "❌ Go not installed"
	@echo -n "Git version: "; git --version 2>/dev/null || echo "⚠️  Git not installed (optional)"
	@echo -n "Port 80 available: "; sudo netstat -tlnp | grep :80 > /dev/null && echo "❌ Port 80 in use" || echo "✅ Available"
	@echo -n "Port 443 available: "; sudo netstat -tlnp | grep :443 > /dev/null && echo "❌ Port 443 in use" || echo "✅ Available"
	@echo -n "Root privileges: "; [ $$(id -u) -eq 0 ] && echo "✅ Running as root" || echo "⚠️  Not running as root (needed for ports 80/443)"

# Show version information
version:
	@echo "Version: $(VERSION)"
	@$(GOBUILD) $(LDFLAGS) -o /tmp/version-check . && /tmp/version-check -version 2>/dev/null || echo "Build required"

# Show help
help:
	@echo "🚀 hnProxy Makefile Commands"
	@echo ""
	@echo "📦 Setup & Dependencies:"
	@echo "  make setup          - Complete setup for new users"
	@echo "  make init           - Initialize Go module"
	@echo "  make deps           - Install dependencies"
	@echo ""
	@echo "🔨 Build Commands:"
	@echo "  make build          - Build the binary"
	@echo "  make cross-compile  - Build for multiple platforms"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "🏃 Run Commands:"
	@echo "  make run            - Build and run with proxy-config.yaml"
	@echo ""
	@echo "🔍 Utilities:"
	@echo "  make test           - Run unit tests with coverage"
	@echo "  make test-all       - Run unit + integration tests"
	@echo "  make test-suite     - Run comprehensive test suite"
	@echo "  make test-ci        - Run CI test pipeline"
	@echo "  make test-bench     - Run benchmarks"
	@echo "  make test-security  - Run security tests"
	@echo "  make lint           - Run lint checks"
	@echo "  make coverage       - Generate HTML coverage report"
	@echo "  make check          - Check system requirements"
	@echo "  make version        - Show version info"
	@echo "  make help           - Show this help"
