#!/bin/bash

# Script de test complet pour le reverse proxy
# Usage: ./test.sh [unit|integration|bench|all|ci]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="30s"
COVERAGE_THRESHOLD=80
BUILD_DIR="build"
COVERAGE_FILE="coverage.out"
COVERAGE_HTML="coverage.html"

# Functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Go
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
    log_info "Go version: $GO_VERSION"
    
    # Check if go.mod exists
    if [[ ! -f "go.mod" ]]; then
        log_warning "go.mod not found, initializing..."
        go mod init hnproxy-https
    fi
    
    # Install dependencies
    log_info "Installing dependencies..."
    make deps
    
    log_success "Dependencies OK"
}

setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p $BUILD_DIR
    mkdir -p tests/fixtures
    mkdir -p tests/tmp
    
    # Create test config if not exists
    if [[ ! -f "tests/fixtures/test-config.yaml" ]]; then
        cat > tests/fixtures/test-config.yaml << 'EOF'
listen: "127.0.0.1:0"
routes:
  test1.local:
    backends:
      - "http://127.0.0.1:3001"
      - "http://127.0.0.1:3002"
  test2.local:
    backends:
      - "http://127.0.0.1:4001"
EOF
    fi
    
    log_success "Test environment ready"
}

run_unit_tests() {
    log_info "Running unit tests..."
    
    # Run tests with coverage
    go test -v -race -timeout=$TEST_TIMEOUT -coverprofile=$COVERAGE_FILE ./...
    
    if [[ $? -eq 0 ]]; then
        log_success "Unit tests passed"
        
        # Generate coverage report
        log_info "Generating coverage report..."
        go tool cover -func=$COVERAGE_FILE
        
        # Check coverage threshold
        COVERAGE=$(go tool cover -func=$COVERAGE_FILE | grep total | awk '{print $3}' | sed 's/%//')
        COVERAGE_INT=${COVERAGE%.*}
        
        if [[ $COVERAGE_INT -ge $COVERAGE_THRESHOLD ]]; then
            log_success "Coverage: $COVERAGE% (>= $COVERAGE_THRESHOLD%)"
        else
            log_warning "Coverage: $COVERAGE% (< $COVERAGE_THRESHOLD%)"
        fi
        
        # Generate HTML report
        go tool cover -html=$COVERAGE_FILE -o $COVERAGE_HTML
        log_info "HTML coverage report: $COVERAGE_HTML"
    else
        log_error "Unit tests failed"
        return 1
    fi
}

run_integration_tests() {
    log_info "Running integration tests..."
    
    # Check if integration tests exist
    if ! grep -r "// +build integration" . &> /dev/null; then
        log_warning "No integration tests found"
        return 0
    fi
    
    # Run integration tests
    go test -v -race -tags=integration -timeout=$TEST_TIMEOUT ./...
    
    if [[ $? -eq 0 ]]; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        return 1
    fi
}

run_benchmark_tests() {
    log_info "Running benchmark tests..."
    
    # Run benchmarks
    go test -v -bench=. -benchmem -timeout=$TEST_TIMEOUT ./... > benchmark_results.txt
    
    if [[ $? -eq 0 ]]; then
        log_success "Benchmark tests completed"
        log_info "Results saved to benchmark_results.txt"
        
        # Show some results
        echo ""
        echo "=== Benchmark Results ==="
        grep "^Benchmark" benchmark_results.txt | head -10
        echo ""
    else
        log_error "Benchmark tests failed"
        return 1
    fi
}

run_race_tests() {
    log_info "Running race condition tests..."
    
    # Run tests with race detector
    go test -race -timeout=$TEST_TIMEOUT ./...
    
    if [[ $? -eq 0 ]]; then
        log_success "Race condition tests passed"
    else
        log_error "Race condition detected!"
        return 1
    fi
}

run_memory_tests() {
    log_info "Running memory tests..."
    
    # Build the binary
    make build
    
    # Test for memory leaks (basic check)
    if command -v valgrind &> /dev/null; then
        log_info "Running with valgrind..."
        # Note: This would need a C-compatible binary, Go has its own memory management
        log_warning "Valgrind not suitable for Go binaries, using go test -memprofile"
    fi
    
    # Run memory profiling
    go test -memprofile=mem.prof -timeout=$TEST_TIMEOUT ./... &> /dev/null
    
    if [[ -f "mem.prof" ]]; then
        log_success "Memory profile generated: mem.prof"
    fi
}

run_lint_checks() {
    log_info "Running lint checks..."
    
    # go vet
    go vet ./...
    if [[ $? -eq 0 ]]; then
        log_success "go vet passed"
    else
        log_error "go vet failed"
        return 1
    fi
    
    # go fmt check
    UNFORMATTED=$(go fmt ./...)
    if [[ -z "$UNFORMATTED" ]]; then
        log_success "Code formatting OK"
    else
        log_error "Code needs formatting:"
        echo "$UNFORMATTED"
        return 1
    fi
    
    # golangci-lint if available
    if command -v golangci-lint &> /dev/null; then
        log_info "Running golangci-lint..."
        golangci-lint run
        if [[ $? -eq 0 ]]; then
            log_success "golangci-lint passed"
        else
            log_warning "golangci-lint issues found"
        fi
    else
        log_warning "golangci-lint not installed, skipping"
    fi
}

run_security_checks() {
    log_info "Running security checks..."
    
    # gosec if available
    if command -v gosec &> /dev/null; then
        log_info "Running gosec..."
        gosec ./...
        if [[ $? -eq 0 ]]; then
            log_success "Security scan passed"
        else
            log_warning "Security issues found"
        fi
    else
        log_warning "gosec not installed, skipping security scan"
        log_info "Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    # Check for common vulnerabilities
    log_info "Checking for hardcoded secrets..."
    if grep -r "password\|secret\|key\|token" --include="*.go" . | grep -v "test" | grep -v "example"; then
        log_warning "Potential hardcoded secrets found (review above)"
    else
        log_success "No obvious hardcoded secrets found"
    fi
}

test_build() {
    log_info "Testing build process..."
    
    # Clean build
    make clean
    
    # Test normal build
    make build
    if [[ $? -eq 0 ]] && [[ -f "$BUILD_DIR/hnproxy" ]]; then
        log_success "Build successful"
    else
        log_error "Build failed"
        return 1
    fi
    
    # Test cross-compilation
    log_info "Testing cross-compilation..."
    make cross-compile
    if [[ $? -eq 0 ]]; then
        log_success "Cross-compilation successful"
        ls -la $BUILD_DIR/
    else
        log_error "Cross-compilation failed"
        return 1
    fi
}

test_docker_build() {
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not available, skipping Docker tests"
        return 0
    fi
    
    log_info "Testing Docker build..."
    
    # Build Docker image
    docker build -t hnproxy-test .
    if [[ $? -eq 0 ]]; then
        log_success "Docker build successful"
        
        # Test Docker image
        log_info "Testing Docker image..."
        timeout 10s docker run --rm hnproxy-test -version || true
        
        # Clean up
        docker rmi hnproxy-test &> /dev/null || true
    else
        log_error "Docker build failed"
        return 1
    fi
}

generate_test_report() {
    log_info "Generating test report..."
    
    REPORT_FILE="test-report.html"
    
    cat > $REPORT_FILE << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Reverse Proxy Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
        .section { margin: 20px 0; padding: 10px; border-left: 3px solid #ccc; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Reverse Proxy Test Report</h1>
    <p>Generated on: $(date)</p>
    <p>Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo "unknown")</p>
    
    <div class="section">
        <h2>Test Results</h2>
        <p>See terminal output for detailed results</p>
    </div>
    
    <div class="section">
        <h2>Coverage Report</h2>
        <p>HTML Coverage: <a href="$COVERAGE_HTML">$COVERAGE_HTML</a></p>
    </div>
    
    <div class="section">
        <h2>Benchmark Results</h2>
        <pre>$(cat benchmark_results.txt 2>/dev/null | head -20 || echo "No benchmark results available")</pre>
    </div>
    
</body>
</html>
EOF

    log_success "Test report generated: $REPORT_FILE"
}

cleanup() {
    log_info "Cleaning up test artifacts..."
    
    # Remove temporary files but keep important ones
    rm -f tests/tmp/* 2>/dev/null || true
    rm -f mem.prof cpu.prof 2>/dev/null || true
    
    log_success "Cleanup complete"
}

main() {
    local test_type=${1:-"unit"}
    local exit_code=0
    
    echo "🚀 hnProxy Test Suite"
    echo "=========================="
    echo ""
    
    # Setup
    check_dependencies
    setup_test_environment
    
    case $test_type in
        "unit")
            run_unit_tests || exit_code=1
            ;;
        "integration")
            run_integration_tests || exit_code=1
            ;;
        "bench"|"benchmark")
            run_benchmark_tests || exit_code=1
            ;;
        "race")
            run_race_tests || exit_code=1
            ;;
        "memory"|"mem")
            run_memory_tests || exit_code=1
            ;;
        "lint")
            run_lint_checks || exit_code=1
            ;;
        "security"|"sec")
            run_security_checks || exit_code=1
            ;;
        "build")
            test_build || exit_code=1
            ;;
        "docker")
            test_docker_build || exit_code=1
            ;;
        "all")
            run_unit_tests || exit_code=1
            run_integration_tests || exit_code=1
            run_race_tests || exit_code=1
            run_lint_checks || exit_code=1
            run_security_checks || exit_code=1
            test_build || exit_code=1
            run_benchmark_tests || exit_code=1
            ;;
        "ci")
            # CI pipeline - strict mode
            set -x
            run_lint_checks || exit_code=1
            run_unit_tests || exit_code=1
            run_integration_tests || exit_code=1
            run_race_tests || exit_code=1
            run_security_checks || exit_code=1
            test_build || exit_code=1
            test_docker_build || exit_code=1
            set +x
            ;;
        *)
            log_error "Unknown test type: $test_type"
            echo "Usage: $0 [unit|integration|bench|race|memory|lint|security|build|docker|all|ci]"
            exit 1
            ;;
    esac
    
    # Generate report for comprehensive tests
    if [[ "$test_type" == "all" || "$test_type" == "ci" ]]; then
        generate_test_report
    fi
    
    # Summary
    echo ""
    echo "=========================="
    if [[ $exit_code -eq 0 ]]; then
        log_success "All tests completed successfully! 🎉"
    else
        log_error "Some tests failed! Check output above."
    fi
    
    cleanup
    exit $exit_code
}

# Handle script termination
trap cleanup EXIT

# Run main function
main "$@"