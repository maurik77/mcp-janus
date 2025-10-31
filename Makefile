.PHONY: all build test clean run install lint fmt help gen-keys rotate-keys

# Variables
BINARY_NAME=mcpproxy
BUILD_DIR=./bin
MAIN_PATH=./cmd/proxy
COVERAGE_FILE=coverage.out

# Default target
all: test build

# Build the proxy server
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Run tests
test:
	@echo "Running tests..."
	@go test ./... -v

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@go test ./... -coverprofile=$(COVERAGE_FILE)
	@go tool cover -html=$(COVERAGE_FILE)
	@echo "✓ Coverage report generated: $(COVERAGE_FILE)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE)
	@echo "✓ Clean complete"

# Run the proxy server (development mode)
run: build
	@echo "Starting MCP proxy server..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

# Install dependencies
install:
	@echo "Installing dependencies..."
	@go mod download
	@go mod verify
	@echo "✓ Dependencies installed"

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run ./...
	@echo "✓ Lint complete"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .
	@echo "✓ Format complete"

# Generate encryption keys
gen-keys:
	@echo "Generating encryption keys..."
	@go run scripts/gen-keys.go

# Rotate encryption keys
rotate-keys:
	@echo "Rotating encryption keys..."
	@go run scripts/rotate-keys.go

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PATH)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PATH)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)
	@echo "✓ Multi-platform build complete"

# Run security checks
security:
	@echo "Running security checks..."
	@gosec ./...
	@echo "✓ Security check complete"

# Display help
help:
	@echo "MCP Proxy Server - Makefile Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       - Build the proxy server binary"
	@echo "  test        - Run all tests"
	@echo "  coverage    - Run tests with coverage report"
	@echo "  clean       - Remove build artifacts"
	@echo "  run         - Build and run the server"
	@echo "  install     - Download and verify dependencies"
	@echo "  lint        - Run golangci-lint"
	@echo "  fmt         - Format code with gofmt and goimports"
	@echo "  gen-keys    - Generate new encryption keys"
	@echo "  rotate-keys - Rotate encryption keys"
	@echo "  build-all   - Build for multiple platforms"
	@echo "  security    - Run security checks with gosec"
	@echo "  help        - Display this help message"
