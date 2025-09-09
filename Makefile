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

.PHONY: all build clean test test-unit test-integration test-bench deps help install run dev example cross-compile

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
	$(GOMOD) tidy
	$(GOGET) gopkg.in/yaml.v3
	$(GOGET) golang.org/x/crypto/acme/autocert
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

# Install the binary to system PATH
install: build
	@echo "🚀 Installing to system..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✅ Installed to /usr/local/bin/$(BINARY_NAME)"

# Uninstall from system
uninstall:
	@echo "🗑️  Uninstalling..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✅ Uninstalled"

# Run the application in development mode
dev: build
	@echo "🏃 Running in development mode..."
	sudo ./$(BUILD_DIR)/$(BINARY_NAME) -config proxy-config.yaml

# Run with custom config
run: build
	@echo "🏃 Running $(BINARY_NAME)..."
	@if [ -f "proxy-config.yaml" ]; then \
		sudo ./$(BUILD_DIR)/$(BINARY_NAME) -config proxy-config.yaml; \
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

# Create release archives
release: cross-compile
	@echo "📦 Creating release archives..."
	@mkdir -p $(BUILD_DIR)/releases
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		binary=$(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then binary=$$binary.exe; fi; \
		archive=$(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then \
			zip -j $$archive.zip $$binary README.md; \
		else \
			tar -czf $$archive.tar.gz -C $(BUILD_DIR) $$(basename $$binary) -C .. README.md; \
		fi; \
		echo "Created: $$archive"; \
	done
	@echo "✅ Release archives created in $(BUILD_DIR)/releases/"

# Quick setup for new users
setup: init deps example
	@echo "🎉 Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit proxy-config.yaml with your domains and backends"
	@echo "2. Run 'make run' to start the proxy"
	@echo "3. Or run 'make install' to install system-wide"

# Development server with auto-reload (requires 'entr')
watch:
	@if ! command -v entr > /dev/null; then \
		echo "❌ 'entr' is required for watch mode"; \
		echo "💡 Install with: apt install entr (Ubuntu) or brew install entr (macOS)"; \
		exit 1; \
	fi
	@echo "👀 Watching for changes (Ctrl+C to stop)..."
	find . -name "*.go" | entr -r make dev

# Generate systemd service file
systemd: install
	@echo "⚙️  Creating systemd service..."
	@echo '[Unit]' > /tmp/hnproxy.service
	@echo 'Description=hnProxy - Reverse Proxy with ACME' >> /tmp/hnproxy.service
	@echo 'After=network.target' >> /tmp/hnproxy.service
	@echo '' >> /tmp/hnproxy.service
	@echo '[Service]' >> /tmp/hnproxy.service
	@echo 'Type=simple' >> /tmp/hnproxy.service
	@echo 'User=root' >> /tmp/hnproxy.service
	@echo 'WorkingDirectory=/opt/hnproxy' >> /tmp/hnproxy.service
	@echo 'ExecStart=/usr/local/bin/hnproxy -config /opt/hnproxy/proxy-config.yaml' >> /tmp/hnproxy.service
	@echo 'Restart=always' >> /tmp/hnproxy.service
	@echo 'RestartSec=5' >> /tmp/hnproxy.service
	@echo 'StandardOutput=journal' >> /tmp/hnproxy.service
	@echo 'StandardError=journal' >> /tmp/hnproxy.service
	@echo '' >> /tmp/hnproxy.service
	@echo '[Install]' >> /tmp/hnproxy.service
	@echo 'WantedBy=multi-user.target' >> /tmp/hnproxy.service
	sudo mv /tmp/hnproxy.service /etc/systemd/system/
	sudo mkdir -p /opt/hnproxy
	sudo cp proxy-config.yaml /opt/hnproxy/ 2>/dev/null || true
	sudo systemctl daemon-reload
	@echo "✅ Systemd service created"
	@echo "💡 Commands:"
	@echo "   sudo systemctl enable hnproxy     # Enable auto-start"
	@echo "   sudo systemctl start hnproxy      # Start service"
	@echo "   sudo systemctl status hnproxy     # Check status"

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
	@echo "  make release        - Create release archives"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "🏃 Run Commands:"
	@echo "  make run            - Build and run with proxy-config.yaml"
	@echo "  make dev            - Build and run in development mode"
	@echo "  make watch          - Auto-rebuild on file changes (requires entr)"
	@echo "  make example        - Create example configuration"
	@echo ""
	@echo "🚀 Installation:"
	@echo "  make install        - Install to /usr/local/bin"
	@echo "  make uninstall      - Remove from system"
	@echo "  make systemd        - Create systemd service"
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