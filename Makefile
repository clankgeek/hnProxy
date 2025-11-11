# Variables
BINARY_NAME=hnproxy
BUILD_DIR=build
VERSION=$(shell grep  "const VERSION string = " main.go | egrep "[0-9\.]+" -o)
LDFLAGS=-ldflags "-s -w"
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Package variables
PKG_NAME=hnproxy
PKG_VERSION=$(shell echo $(VERSION) | sed 's/^v//')
PKG_MAINTAINER=Clank <clank@ik.me>
PKG_DESCRIPTION=HTTP/HTTPS reverse proxy with automatic SSL certificate management
PKG_HOMEPAGE=https://github.com/clankgeek/hnProxy
DEB_DIR=$(BUILD_DIR)/deb
DEB_PKG_DIR=$(DEB_DIR)/$(PKG_NAME)_$(PKG_VERSION)

# Go parameters
GOCMD=GOAMD64=v3 go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

.PHONY: all build clean test test-unit test-integration test-bench deps help run example cross-compile deb deb-clean

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

# Build Debian package for amd64
deb: deb-clean
	@echo "📦 Building Debian package..."
	@mkdir -p $(DEB_PKG_DIR)/DEBIAN
	@mkdir -p $(DEB_PKG_DIR)/usr/bin
	@mkdir -p $(DEB_PKG_DIR)/etc/hnproxy
	@mkdir -p $(DEB_PKG_DIR)/etc/systemd/system
	@mkdir -p $(DEB_PKG_DIR)/var/lib/hnproxy/certs
	@mkdir -p $(DEB_PKG_DIR)/var/log/hnproxy
	
	@echo "🔨 Building binary for linux/amd64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DEB_PKG_DIR)/usr/bin/$(BINARY_NAME) .
	
	@echo "📝 Creating control file..."
	@echo "Package: $(PKG_NAME)" > $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Version: $(PKG_VERSION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Architecture: amd64" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Maintainer: $(PKG_MAINTAINER)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Description: $(PKG_DESCRIPTION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo " A lightweight HTTP/HTTPS reverse proxy with automatic SSL" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo " certificate management using Let's Encrypt." >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Homepage: $(PKG_HOMEPAGE)" >> $(DEB_PKG_DIR)/DEBIAN/control
	
	@echo "📝 Creating postinst script..."
	@echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Create hnproxy user if it doesn't exist" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "if ! id -u hnproxy > /dev/null 2>&1; then" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    useradd --system --no-create-home --shell /bin/false hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Set permissions" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chown -R hnproxy:hnproxy /var/lib/hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chown -R hnproxy:hnproxy /var/log/hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chmod 750 /var/lib/hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chmod 750 /var/log/hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Create example config if it doesn't exist" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "if [ ! -f /etc/hnproxy/config.yaml ]; then" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    /usr/bin/hnproxy -example -config /etc/hnproxy/config.yaml > /dev/null 2>&1 || true" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    chown hnproxy:hnproxy /etc/hnproxy/config.yaml" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Reload systemd" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "systemctl daemon-reload" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "echo '✅ hnProxy installed successfully!'" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "echo '📝 Edit /etc/hnproxy/config.yaml and run: systemctl start hnproxy'" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_PKG_DIR)/DEBIAN/postinst
	
	@echo "📝 Creating prerm script..."
	@echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "# Stop service if running" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "if systemctl is-active --quiet hnproxy; then" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "    systemctl stop hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "if systemctl is-enabled --quiet hnproxy 2>/dev/null; then" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "    systemctl disable hnproxy" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@chmod 755 $(DEB_PKG_DIR)/DEBIAN/prerm
	
	@echo "📝 Creating systemd service file..."
	@echo "[Unit]" > $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "Description=hnProxy - HTTP/HTTPS Reverse Proxy" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "After=network.target" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "[Service]" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "Type=simple" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "User=hnproxy" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "Group=hnproxy" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "ExecStart=/usr/bin/hnproxy -config /etc/hnproxy/config.yaml" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "Restart=on-failure" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "RestartSec=5s" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "# Security hardening" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "NoNewPrivileges=true" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "PrivateTmp=true" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "ProtectSystem=strict" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "ProtectHome=false" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "ReadWritePaths=/var/lib/hnproxy /var/log/hnproxy" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "# Give permissions to bind to ports 80 and 443" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "AmbientCapabilities=CAP_NET_BIND_SERVICE" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "[Install]" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	@echo "WantedBy=multi-user.target" >> $(DEB_PKG_DIR)/etc/systemd/system/hnproxy.service
	
	@echo "🔨 Building package..."
	@dpkg-deb --build $(DEB_PKG_DIR)
	@mv $(DEB_PKG_DIR).deb $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb
	@rm -rf $(DEB_DIR)
	@echo "✅ Debian package created: $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb"
	@echo ""
	@echo "📦 Install with: sudo dpkg -i $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb"

# Build Debian package for arm64
deb-arm64: deb-clean
	@echo "📦 Building Debian package for arm64..."
	@mkdir -p $(DEB_PKG_DIR)/DEBIAN
	@mkdir -p $(DEB_PKG_DIR)/usr/bin
	@mkdir -p $(DEB_PKG_DIR)/etc/hnproxy
	@mkdir -p $(DEB_PKG_DIR)/etc/systemd/system
	@mkdir -p $(DEB_PKG_DIR)/var/lib/hnproxy/certs
	@mkdir -p $(DEB_PKG_DIR)/var/log/hnproxy
	
	@echo "🔨 Building binary for linux/arm64..."
	@GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DEB_PKG_DIR)/usr/bin/$(BINARY_NAME) .
	
	@echo "📝 Creating control file..."
	@echo "Package: $(PKG_NAME)" > $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Version: $(PKG_VERSION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Architecture: arm64" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Maintainer: $(PKG_MAINTAINER)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Description: $(PKG_DESCRIPTION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo " A lightweight HTTP/HTTPS reverse proxy with automatic SSL" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo " certificate management using Let's Encrypt." >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Homepage: $(PKG_HOMEPAGE)" >> $(DEB_PKG_DIR)/DEBIAN/control
	
	# Copier les mêmes scripts postinst et prerm
	@cp $(BUILD_DIR)/deb/$(PKG_NAME)_$(PKG_VERSION)/DEBIAN/postinst $(DEB_PKG_DIR)/DEBIAN/ 2>/dev/null || \
		(echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/postinst && \
		 echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/postinst && \
		 chmod 755 $(DEB_PKG_DIR)/DEBIAN/postinst)
	
	@cp $(BUILD_DIR)/deb/$(PKG_NAME)_$(PKG_VERSION)/DEBIAN/prerm $(DEB_PKG_DIR)/DEBIAN/ 2>/dev/null || \
		(echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/prerm && \
		 echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/prerm && \
		 chmod 755 $(DEB_PKG_DIR)/DEBIAN/prerm)
	
	@cp $(BUILD_DIR)/deb/$(PKG_NAME)_$(PKG_VERSION)/etc/systemd/system/hnproxy.service \
		$(DEB_PKG_DIR)/etc/systemd/system/ 2>/dev/null || true
	
	@echo "🔨 Building package..."
	@dpkg-deb --build $(DEB_PKG_DIR)
	@mv $(DEB_PKG_DIR).deb $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_arm64.deb
	@rm -rf $(DEB_DIR)
	@echo "✅ Debian package created: $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_arm64.deb"

# Build all Debian packages
deb-all: deb deb-arm64

# Clean Debian build artifacts
deb-clean:
	@rm -rf $(DEB_DIR)
	@rm -f $(BUILD_DIR)/*.deb

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
	@echo -n "dpkg-deb: "; dpkg-deb --version 2>/dev/null | head -n1 || echo "⚠️  dpkg-deb not installed (needed for 'make deb')"
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
	@echo "📦 Package Commands:"
	@echo "  make deb            - Build Debian package (amd64)"
	@echo "  make deb-arm64      - Build Debian package (arm64)"
	@echo "  make deb-all        - Build all Debian packages"
	@echo "  make deb-clean      - Clean Debian build artifacts"
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