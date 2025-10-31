# Contributing to MCP Proxy

Thank you for your interest in contributing to the MCP Proxy Server! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

Be respectful, professional, and constructive in all interactions.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional but recommended)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/mcpproxy.git
cd mcpproxy
```

### Install Dependencies

```bash
make install
# or
go mod download
```

## Development Setup

### 1. Create Environment File

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 2. Generate Encryption Keys

```bash
make gen-keys
# or
go run scripts/gen-keys.go
```

### 3. Run Tests

```bash
make test
# or
go test ./...
```

### 4. Build and Run

```bash
make run
# or
make build && ./bin/mcpproxy
```

## Project Structure

```
mcpproxy/
├── cmd/proxy/           # Application entry point
├── internal/            # Internal packages (not importable)
│   ├── config/         # Configuration management
│   ├── crypto/         # Cryptography and key management
│   ├── oauth/          # OAuth 2.1 provider
│   ├── tokens/         # Token storage and opaque tokens
│   └── mcp/            # MCP client and forwarding
├── pkg/http/           # HTTP server (potentially reusable)
├── docs/               # Documentation
├── scripts/            # Utility scripts
└── tests/              # Integration tests (future)
```

## Coding Standards

### Go Style

Follow idiomatic Go conventions:

1. **Use `gofmt` and `goimports`**
   ```bash
   make fmt
   ```

2. **Follow Effective Go**
   - https://go.dev/doc/effective_go

3. **Use meaningful names**
   ```go
   // ✅ Good
   func (s *OpaqueTokenService) Validate(ctx context.Context, token string) (*Payload, error)
   
   // ❌ Bad
   func (s *OTS) V(c context.Context, t string) (*P, error)
   ```

4. **Keep functions small and focused**
   - Aim for < 50 lines per function
   - Single responsibility principle

5. **Error handling**
   ```go
   // ✅ Good - wrap errors with context
   if err != nil {
       return fmt.Errorf("failed to encrypt token: %w", err)
   }
   
   // ❌ Bad - lose context
   if err != nil {
       return err
   }
   ```

6. **Use interfaces wisely**
   - Define interfaces where they're used, not where they're implemented
   - Keep interfaces small (1-3 methods)

### Documentation

1. **Package-level documentation**
   ```go
   // Package crypto provides AEAD encryption services for opaque tokens.
   package crypto
   ```

2. **Exported function documentation**
   ```go
   // Encrypt encrypts plaintext using AES-GCM AEAD.
   // Returns ciphertext, nonce, and authentication tag.
   func (s *AESGCMService) Encrypt(ctx context.Context, plaintext []byte, kid string) ([]byte, []byte, []byte, error)
   ```

3. **Complex logic documentation**
   ```go
   // We use a 1-minute buffer for expiry checks to account for clock skew
   // between client and server.
   if time.Now().Add(1 * time.Minute).After(c.ExpiresAt) {
       return true
   }
   ```

### Linting

Run the linter before committing:

```bash
make lint
# or
golangci-lint run ./...
```

## Testing Guidelines

### Test Coverage

Aim for >80% coverage for:
- All cryptographic operations
- Token validation logic
- OAuth flows
- Error handling paths

### Table-Driven Tests

Use table-driven tests for multiple scenarios:

```go
func TestValidate(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *Payload
        wantErr bool
    }{
        {
            name:    "valid token",
            input:   "valid.token.here",
            want:    &Payload{RTID: "123"},
            wantErr: false,
        },
        {
            name:    "expired token",
            input:   "expired.token.here",
            want:    nil,
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := service.Validate(ctx, tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
            // ... more assertions
        })
    }
}
```

### Test Organization

- Unit tests: `*_test.go` in same package
- Integration tests: `tests/` directory (future)
- Mock external dependencies with interfaces

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./internal/crypto/... -v

# With coverage
make coverage

# Short mode (skip slow tests)
go test ./... -short
```

## Security Guidelines

### Never Commit Secrets

- No API keys, tokens, passwords in code
- No encryption keys in version control
- Use `.env` files (git-ignored) for secrets

### Security-Critical Code

For crypto, tokens, and OAuth code:

1. **Extra scrutiny in code review**
2. **Comprehensive test coverage**
3. **Document security assumptions**
4. **Follow principle of least privilege**

### Logging

```go
// ✅ Good - log IDs, not secrets
slog.Info("token issued", "rtid", rtid, "expires_in", ttl)

// ❌ Bad - logs actual token
slog.Info("token issued", "token", tokenValue)
```

### Error Messages

```go
// ✅ Good - generic error
return errors.New("authentication failed")

// ❌ Bad - leaks information
return errors.New("password incorrect for user admin")
```

## Pull Request Process

### Before Submitting

1. **Run tests**
   ```bash
   make test
   ```

2. **Run linter**
   ```bash
   make lint
   ```

3. **Format code**
   ```bash
   make fmt
   ```

4. **Update documentation**
   - Update README.md if adding features
   - Update SECURITY.md if security-related
   - Add/update code comments

5. **Check coverage**
   ```bash
   make coverage
   ```

### PR Guidelines

1. **One concern per PR**
   - Bug fix: single bug
   - Feature: single feature
   - Refactor: focused refactor

2. **Clear description**
   ```markdown
   ## Summary
   Implements opaque token validation with audience binding.
   
   ## Changes
   - Added audience validation in token service
   - Updated tests to cover audience mismatch
   - Added error handling for invalid audience
   
   ## Testing
   - Added 3 new test cases
   - Coverage increased from 78% to 85%
   
   ## Security Impact
   Implements RFC 8707 audience binding to prevent token misuse.
   ```

3. **Reference issues**
   ```markdown
   Fixes #123
   Relates to #456
   ```

4. **Small, focused commits**
   ```bash
   git commit -m "Add audience validation to token service"
   git commit -m "Add tests for audience validation"
   ```

### Review Process

1. Automated checks must pass (tests, lint)
2. At least one maintainer approval required
3. Address all review comments
4. Squash commits before merge (if needed)

## Reporting Issues

### Bug Reports

Include:

1. **Expected behavior**
2. **Actual behavior**
3. **Steps to reproduce**
4. **Environment** (Go version, OS, config)
5. **Logs** (sanitize secrets!)

Example:

```markdown
### Bug: Token validation fails with valid token

**Expected**: Token should validate successfully

**Actual**: Returns "invalid token format" error

**Steps to Reproduce**:
1. Generate token with `service.Create(...)`
2. Immediately call `service.Validate(...)`
3. Error occurs

**Environment**:
- Go 1.21.3
- macOS 14.0
- KEY_STORE_TYPE=memory

**Logs**:
```
ERROR token validation failed error="invalid token format"
```

### Feature Requests

Include:

1. **Use case** - why is this needed?
2. **Proposed solution** - how should it work?
3. **Alternatives considered**
4. **Security implications** (if any)

### Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email maintainers directly
2. Use GitHub Security Advisories (private)
3. Provide proof-of-concept (if safe)

## Development Tips

### Useful Commands

```bash
# Run specific test
go test ./internal/crypto -run TestEncrypt -v

# Watch for changes and re-run tests (requires entr)
find . -name "*.go" | entr -c make test

# Generate mock (requires mockgen)
mockgen -source=internal/oauth/provider.go -destination=internal/oauth/mock_provider.go

# Profile CPU usage
go test -cpuprofile=cpu.prof ./internal/crypto
go tool pprof cpu.prof
```

### Debugging

```go
import "log/slog"

// Temporary debug logging
slog.Debug("debugging token validation",
    "token_length", len(token),
    "kid", kid,
)
```

### IDE Setup

**VS Code**: Install Go extension
```json
{
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "workspace",
  "go.formatTool": "goimports"
}
```

**GoLand**: Built-in Go support, enable golangci-lint

## Questions?

- Check existing issues and documentation
- Ask in discussions (if enabled)
- Reach out to maintainers

## Thank You!

Your contributions make this project better for everyone. Thank you for taking the time to contribute!
